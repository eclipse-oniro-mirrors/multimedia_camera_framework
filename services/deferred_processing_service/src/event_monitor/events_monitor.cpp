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

#include "events_monitor.h"

#include "dp_log.h"
#include "dp_utils.h"
#include "dps_event_report.h"
#include "dps.h"
#include "event_status_change_command.h"
#include "events_info.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
EventsMonitor::EventsMonitor()
{
    DP_DEBUG_LOG("entered.");
}

EventsMonitor::~EventsMonitor()
{
    DP_DEBUG_LOG("entered.");
    UnSubscribeSystemAbility();
}

void EventsMonitor::Initialize()
{
    DP_DEBUG_LOG("entered.");
    std::lock_guard<std::mutex> lock(mutex_);
    DP_CHECK_RETURN(initialized_.load());
    DP_CHECK_RETURN(SubscribeSystemAbility() != DP_OK);
    initialized_ = true;
}

void EventsMonitor::RegisterEventsListener(const int32_t userId, const std::vector<EventType>& events,
    const std::weak_ptr<IEventsListener>& listener)
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

void EventsMonitor::NotifyThermalLevel(int32_t level)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("notify : %{public}d.", level);
    DP_CHECK_ERROR_RETURN_LOG(!initialized_.load(), "uninitialized events monitor!");

    for (auto it = userIdToeventListeners_.begin(); it != userIdToeventListeners_.end(); ++it) {
        NotifyObserversUnlocked(it->first, EventType::THERMAL_LEVEL_STATUS_EVENT, level);
    }
}

void EventsMonitor::NotifyCameraSessionStatus(const int32_t userId,
    const std::string& cameraId, bool running, bool isSystemCamera)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered, userId: %{public}d, cameraId: %s, running: %{public}d, isSystemCamera: %{public}d: ",
        userId, cameraId.c_str(), running, isSystemCamera);
    DP_CHECK_ERROR_RETURN_LOG(!initialized_.load(), "uninitialized events monitor!");

    CameraSessionStatus cameraSessionStatus;
    running ? numActiveSessions_++ : numActiveSessions_--;
    DP_INFO_LOG("numActiveSessions_: %{public}d", static_cast<int>(numActiveSessions_.load()));
    bool currSessionRunning = running;
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
    auto level = EventsInfo::GetInstance().GetPhotoThermalLevel();
    DPSEventReport::GetInstance().SetTemperatureLevel(static_cast<int>(level));
}

void EventsMonitor::NotifyMediaLibraryStatus(bool available)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("mediaLibrary available: %{public}d.", available);
    DP_CHECK_ERROR_RETURN_LOG(!initialized_.load(), "uninitialized events monitor!");

    for (auto it = userIdToeventListeners_.begin(); it != userIdToeventListeners_.end(); ++it) {
        NotifyObserversUnlocked(it->first, EventType::MEDIA_LIBRARY_STATUS_EVENT, available);
    }
}

void EventsMonitor::NotifyImageEnhanceStatus(int32_t status)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered: %{public}d.", status);
    DP_CHECK_ERROR_RETURN_LOG(!initialized_.load(), "uninitialized events monitor!");

    for (auto it = userIdToeventListeners_.begin(); it != userIdToeventListeners_.end(); ++it) {
        NotifyObserversUnlocked(it->first, EventType::HDI_STATUS_EVENT, status);
    }
}

void EventsMonitor::NotifyScreenStatus(int32_t status)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered: %{public}d.", status);
    DP_CHECK_ERROR_RETURN_LOG(!initialized_.load(), "uninitialized events monitor!");

    for (auto it = userIdToeventListeners_.begin(); it != userIdToeventListeners_.end(); ++it) {
        NotifyObserversUnlocked(it->first, EventType::SCREEN_STATUS_EVENT, status);
    }
}

void EventsMonitor::NotifyChargingStatus(int32_t status)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered: %{public}d.", status);
    DP_CHECK_ERROR_RETURN_LOG(!initialized_.load(), "uninitialized events monitor!");

    for (auto it = userIdToeventListeners_.begin(); it != userIdToeventListeners_.end(); ++it) {
        NotifyObserversUnlocked(it->first, EventType::CHARGING_STATUS_EVENT, status);
    }
}

void EventsMonitor::NotifyBatteryStatus(int32_t status)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered: %{public}d.", status);
    DP_CHECK_ERROR_RETURN_LOG(!initialized_.load(), "uninitialized events monitor!");

    for (auto it = userIdToeventListeners_.begin(); it != userIdToeventListeners_.end(); ++it) {
        NotifyObserversUnlocked(it->first, EventType::BATTERY_STATUS_EVENT, status);
    }
}

void EventsMonitor::NotifyBatteryLevel(int32_t level)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered: %{public}d.", level);
    DP_CHECK_ERROR_RETURN_LOG(!initialized_.load(), "uninitialized events monitor!");

    for (auto it = userIdToeventListeners_.begin(); it != userIdToeventListeners_.end(); ++it) {
        NotifyObserversUnlocked(it->first, EventType::BATTERY_LEVEL_STATUS_EVENT, level);
    }
}

void EventsMonitor::NotifySystemPressureLevel(SystemPressureLevel level)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered: %{public}d.", level);
    DP_CHECK_ERROR_RETURN_LOG(!initialized_.load(), "uninitialized events monitor!");

    for (auto it = userIdToeventListeners_.begin(); it != userIdToeventListeners_.end(); ++it) {
        NotifyObserversUnlocked(it->first, EventType::SYSTEM_PRESSURE_LEVEL_EVENT, level);
    }
}
void EventsMonitor::NotifyPhotoProcessSize(int32_t size)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered, image job size: %{public}d.", size);
    DP_CHECK_ERROR_RETURN_LOG(!initialized_.load(), "uninitialized events monitor!");

    for (auto it = userIdToeventListeners_.begin(); it != userIdToeventListeners_.end(); ++it) {
        NotifyObserversUnlocked(it->first, EventType::PHOTO_PROCESS_STATUS_EVENT, size);
    }
}

void EventsMonitor::NotifyObserversUnlocked(const int32_t userId, EventType event, int32_t value)
{
    int32_t ret = DPS_SendCommand<EventStatusChangeCommand>(userId, event, value);
    DP_CHECK_ERROR_PRINT_LOG(ret != DP_OK, "send command fail, ret: %{public}d", ret);
}

void EventsMonitor::NotifyEventToObervers(const int32_t userId, EventType event, int32_t value)
{
    DP_DEBUG_LOG("entered.");
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

void EventsMonitor::NotifyObservers(EventType event, int value, int32_t userId)
{
    DP_DEBUG_LOG("entered.");
    std::lock_guard<std::mutex> lock(mutex_);
    NotifyObserversUnlocked(userId, event, value);
}

void CommonEventListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    DP_CHECK_RETURN(eventSubscriber_ != nullptr);
    DP_DEBUG_LOG("saId: %{public}d", systemAbilityId);
    eventSubscriber_ = EventSubscriber::Create();
    DP_CHECK_ERROR_RETURN_LOG(eventSubscriber_ == nullptr, "RegisterEventStatus failed, eventSubscriber is nullptr");
    eventSubscriber_->Subcribe();
}

void CommonEventListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    DP_CHECK_RETURN(eventSubscriber_ == nullptr);
    DP_DEBUG_LOG("saId: %{public}d", systemAbilityId);
    DP_CHECK_ERROR_RETURN_LOG(eventSubscriber_ == nullptr, "UnRegisterEventStatus failed, eventSubscriber is nullptr");
    eventSubscriber_->UnSubscribe();
}

int32_t EventsMonitor::SubscribeSystemAbility()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    DP_CHECK_ERROR_RETURN_RET_LOG(samgr == nullptr, DP_NULL_POINTER, "failed to get system ability manager");

    ceListener_ = sptr<CommonEventListener>::MakeSptr();
    DP_CHECK_ERROR_RETURN_RET_LOG(ceListener_ == nullptr, DP_NULL_POINTER, "ceListener is nullptr.");

    int32_t ret = samgr->SubscribeSystemAbility(COMMON_EVENT_SERVICE_ID, ceListener_);
    DP_INFO_LOG("SubscribeSystemAbility ret = %{public}d", ret);
    return ret == DP_OK ? DP_OK : DP_ERR;
}

int32_t EventsMonitor::UnSubscribeSystemAbility()
{
    DP_CHECK_RETURN_RET(ceListener_ == nullptr, DP_OK);

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    DP_CHECK_ERROR_RETURN_RET_LOG(samgr == nullptr, DP_NULL_POINTER, "failed to get System ability manager");
    
    int32_t ret = samgr->UnSubscribeSystemAbility(COMMON_EVENT_SERVICE_ID, ceListener_);
    DP_INFO_LOG("UnSubscribeSystemAbility ret = %{public}d", ret);
    ceListener_ = nullptr;
    return ret == DP_OK ? DP_OK : DP_ERR;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
