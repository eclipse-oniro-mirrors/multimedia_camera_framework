/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <securec.h>
#include "events_monitor.h"
#include "dp_log.h"
#include "dp_utils.h"
#include <if_system_ability_manager.h>
#include <ipc_skeleton.h>
#include <iservice_registry.h>
#include <system_ability_definition.h>
#ifdef CAMERA_USE_THERMAL
#include "thermal_mgr_client.h"
#endif
#include "dps_event_report.h"

namespace OHOS {
namespace CameraStandard {

namespace {
    constexpr int32_t LEVEL_0 = 0;
    constexpr int32_t LEVEL_1 = 1;
    constexpr int32_t LEVEL_2 = 2;
    constexpr int32_t LEVEL_3 = 3;
    constexpr int32_t LEVEL_4 = 4;
    constexpr int32_t LEVEL_5 = 5;
}

namespace DeferredProcessing {
class EventsMonitor::ThermalMgrDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit ThermalMgrDeathRecipient(EventsMonitor *eventMonitor) : eventMonitor_(eventMonitor)
    {}
    ~ThermalMgrDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject>& remote) override
    {
        (void)(remote);
        if (eventMonitor_) {
            eventMonitor_->SetRegisterThermalStatus(false);
            eventMonitor_->ScheduleRegisterThermalListener();
        }
    }

private:
    EventsMonitor *eventMonitor_;
};

EventsMonitor &EventsMonitor::GetInstance()
{
    static EventsMonitor instance;
    return instance;
}

EventsMonitor::EventsMonitor() : initialized_(false), numActiveSessions_(0), mIsRegistered(false)
{
    DP_DEBUG_LOG("EventsMonitor enter.");
}

EventsMonitor::~EventsMonitor()
{
    DP_DEBUG_LOG("~EventsMonitor enter.");
    numActiveSessions_ = 0;
    initialized_ = false;
    UnRegisterThermalLevel();
}

void EventsMonitor::Initialize()
{
    DP_DEBUG_LOG("Initialize enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_) {
        return;
    }
    RegisterThermalLevel();
    ScheduleRegisterThermalListener();
    initialized_ = true;
}

void EventsMonitor::RegisterEventsListener(int userId, const std::vector<EventType> &events,
                                           const std::shared_ptr<IEventsListener> &listener)
{
    DP_INFO_LOG("RegisterEventsListener enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<EventType, std::vector<std::weak_ptr<IEventsListener>>> eventListeners_;
    if (userIdToeventListeners_.count(userId) > 0) {
        eventListeners_ = userIdToeventListeners_[userId];
    }
    for (const auto &event : events) {
        eventListeners_[event].push_back(listener);
    }
    userIdToeventListeners_[userId] = eventListeners_;
}

void EventsMonitor::RegisterTaskManager(int userId, TaskManager *taskManager)
{
    DP_INFO_LOG("RegisterTaskManager enter.");
    auto taskIter = userIdToTaskManager.find(userId);
    if (taskIter != userIdToTaskManager.end()) {
        (taskIter->second).push_back(taskManager);
    } else {
        std::vector<TaskManager*> taskVector;
        taskVector.push_back(taskManager);
        userIdToTaskManager[userId] = taskVector;
    }
}

void EventsMonitor::SetRegisterThermalStatus(bool isHasRegistered)
{
    mIsRegistered = isHasRegistered;
}

void EventsMonitor::UnRegisterListener(int userId, TaskManager *taskManager)
{
    DP_INFO_LOG("UnRegisterListener enter.");
    auto taskIter = userIdToTaskManager.find(userId);
    if (taskIter != userIdToTaskManager.end()) {
        std::vector<TaskManager*>::iterator itVect = (taskIter->second).begin();
        for (; itVect != (taskIter->second).end(); ++itVect) {
            if (*itVect == taskManager) {
                break;
            }
        }
        (taskIter->second).erase(itVect);
    }
    if (userIdToTaskManager[userId].size() == 0) {
        userIdToTaskManager.erase(userId);
    }
}

void EventsMonitor::NotifyThermalLevel(int level)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("notify : %d.", level);
    if (!initialized_) {
        DP_INFO_LOG("uninitialized events monitor!");
        return;
    }
    for (auto it = userIdToeventListeners_.begin(); it != userIdToeventListeners_.end(); ++it) {
        NotifyObserversUnlocked(it->first, EventType::SYSTEM_PRESSURE_LEVEL_EVENT, level);
    }
}

void EventsMonitor::NotifyCameraSessionStatus(int userId,
    const std::string &cameraId, bool running, bool isSystemCamera)
{
    DP_INFO_LOG("entered, userId: %d, cameraId: %s, running: %d, isSystemCamera: %d: ",
        userId, cameraId.c_str(), running, isSystemCamera);
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return;
    }
    CameraSessionStatus cameraSessionStatus;
    running ? numActiveSessions_++ : numActiveSessions_--;
    bool currSessionRunning = numActiveSessions_.load() > 0;
    if (currSessionRunning) {
        cameraSessionStatus = isSystemCamera ?
            CameraSessionStatus::SYSTEM_CAMERA_OPEN :
            CameraSessionStatus::NORMAL_CAMERA_OPEN;
    } else {
        cameraSessionStatus = isSystemCamera ?
            CameraSessionStatus::SYSTEM_CAMERA_CLOSED :
            CameraSessionStatus::NORMAL_CAMERA_CLOSED;
    }
    NotifyObserversUnlocked(userId, EventType::CAMERA_SESSION_STATUS_EVENT, cameraSessionStatus);
    ConnectThermalSvr();
}

void EventsMonitor::NotifyMediaLibraryStatus(bool available)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("mediaLibrary available: %d.", available);
    if (!initialized_) {
        DP_INFO_LOG("uninitialized events monitor!");
        return;
    }
    for (auto it = userIdToeventListeners_.begin(); it != userIdToeventListeners_.end(); ++it) {
        NotifyObserversUnlocked(it->first, EventType::MEDIA_LIBRARY_STATUS_EVENT, available);
    }
}

void EventsMonitor::NotifyImageEnhanceStatus(int32_t status)
{
    DP_INFO_LOG("entered: %d.", status);
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        DP_INFO_LOG("uninitialized events monitor!");
        return;
    }

    for (auto it = userIdToeventListeners_.begin(); it != userIdToeventListeners_.end(); ++it) {
        NotifyObserversUnlocked(it->first, EventType::HDI_STATUS_EVENT, status);
    }
}

void EventsMonitor::NotifySystemPressureLevel(SystemPressureLevel level)
{
    DP_INFO_LOG("entered: %d.", level);
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        DP_INFO_LOG("uninitialized events monitor!");
        return;
    }

    for (auto it = userIdToeventListeners_.begin(); it != userIdToeventListeners_.end(); ++it) {
        NotifyObserversUnlocked(it->first, EventType::SYSTEM_PRESSURE_LEVEL_EVENT, level);
    }
}

void EventsMonitor::NotifyObserversUnlocked(int userId, EventType event, int value)
{
    DP_INFO_LOG("entered.");
    auto taskIter = userIdToTaskManager.find(userId);
    if (taskIter != userIdToTaskManager.end()) {
        std::vector<TaskManager*> taskvect = userIdToTaskManager[userId];
        for (auto it = taskvect.begin(); it != taskvect.end();) {
            if (*it) {
                (*it)->SubmitTask([userId, event, value]() {
                    EventsMonitor::GetInstance().NotifyEventToObervers(userId, event, value);
                });
            }
            ++it;
        }
    }
}

void EventsMonitor::NotifyEventToObervers(int userId, EventType event, int value)
{
    DP_INFO_LOG("entered.");
    auto eventListeners = userIdToeventListeners_.find(userId);
    if (eventListeners != userIdToeventListeners_.end()) {
        std::map<EventType, std::vector<std::weak_ptr<IEventsListener>>> eventListenersVect;
        eventListenersVect = userIdToeventListeners_[userId];
        auto &observers = eventListenersVect[event];
        for (auto it = observers.begin(); it != observers.end();) {
            auto observer = it->lock();
            if (observer) {
                observer->OnEventChange(event, value);
                ++it;
            } else {
                it = observers.erase(it);
            }
        }
    }
}

void EventsMonitor::ScheduleRegisterThermalListener()
{
    DP_INFO_LOG("entered.");
    uint32_t callbackHandle;
    constexpr uint32_t delayMilli = 10 * 1000;
    GetGlobalWatchdog().StartMonitor(callbackHandle, delayMilli, [this](uint32_t handle) {
        DP_INFO_LOG("PhotoPostProcessor-ProcessImage-Watchdog executed, handle: %d", static_cast<int>(handle));
        this->RegisterThermalLevel();
    });
}

void EventsMonitor::NotifyObservers(EventType event, int value, int userId)
{
    DP_INFO_LOG("entered.");
    std::lock_guard<std::mutex> lock(mutex_);
    NotifyObserversUnlocked(userId, event, value);
}

void EventsMonitor::RegisterThermalLevel()
{
    std::unique_lock<std::mutex> lock(thermalEventMutex);
    if (thermalLevelSubscriber_) {
        return;
    }
    ConnectThermalSvr();
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    thermalLevelSubscriber_ = std::make_shared<ThermalLevelSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(thermalLevelSubscriber_)) {
        DP_INFO_LOG("THERMAL_LEVEL_CHANGED SubscribeCommonEvent() failed");
    } else {
        DP_INFO_LOG("THERMAL_LEVEL_CHANGED SubscribeCommonEvent() OK");
    }
}

void EventsMonitor::UnRegisterThermalLevel()
{
    std::unique_lock<std::mutex> lock(thermalEventMutex);
    if (!thermalLevelSubscriber_) {
        return;
    }
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(thermalLevelSubscriber_)) {
        DP_INFO_LOG("THERMAL_LEVEL_CHANGED UnSubscribeCommonEvent() failed");
    } else {
        DP_INFO_LOG("THERMAL_LEVEL_CHANGED UnSubscribeCommonEvent() OK");
    }
}

void EventsMonitor::ConnectThermalSvr()
{
#ifdef CAMERA_USE_THERMAL
    DP_INFO_LOG("thermalSrv_ enter");
    auto& thermalMgrClient = OHOS::PowerMgr::ThermalMgrClient::GetInstance();
    OHOS::PowerMgr::ThermalLevel level = thermalMgrClient.GetThermalLevel();
    DP_DEBUG_LOG("ThermalMgrClient is level %{public}d", level);
    DPSEventReport::GetInstance().SetTemperatureLevel(static_cast<int>(level));
#endif

    DP_INFO_LOG("Connecting ThermalMgrService success.");
}

ThermalLevelSubscriber::ThermalLevelSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : CommonEventSubscriber(subscriberInfo)
{
    DP_INFO_LOG("ThermalLevelSubscriber enter");
}

ThermalLevelSubscriber::~ThermalLevelSubscriber()
{
    DP_INFO_LOG("~ThermalLevelSubscriber enter");
}

void ThermalLevelSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    DP_INFO_LOG("ThermalLevelSubscriber::OnReceiveEvent: %{public}s.", action.c_str());
    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED) {
        static const std::string THERMAL_EVENT_ID = "0";
        int level = data.GetWant().GetIntParam(THERMAL_EVENT_ID, 0);
        DPSEventReport::GetInstance().SetTemperatureLevel(level);
        DP_INFO_LOG("OnThermalLevelChanged level:%d", static_cast<int>(level));
        EventsMonitor::GetInstance().NotifySystemPressureLevel(MapEventLevel(level));
        DP_INFO_LOG("ThermalLevelSubscriber SetThermalLevel: %{public}d.", level);
    }
}

SystemPressureLevel ThermalLevelSubscriber::MapEventLevel(int level)
{
    if (level < LEVEL_0 || level > LEVEL_5) {
        return SystemPressureLevel::SEVERE;
    }
    SystemPressureLevel eventLevel;
    switch (level) {
        case LEVEL_0:
        case LEVEL_1:
        case LEVEL_2:
            eventLevel = SystemPressureLevel::NOMINAL;
            break;
        case LEVEL_3:
        case LEVEL_4:
            eventLevel = SystemPressureLevel::FAIR;
            break;
        default:
            eventLevel = SystemPressureLevel::SEVERE;
            break;
    }
    return eventLevel;
}
}
} // namespace CameraStandard
} // namespace OHOS
