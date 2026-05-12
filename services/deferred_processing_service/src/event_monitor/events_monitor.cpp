/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
    DP_INFO_LOG("entered.");
    UnSubscribeSystemAbility();
}

void EventsMonitor::Initialize()
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_RETURN(initialized_.load());
    DP_CHECK_RETURN(SubscribeSystemAbility() != DP_OK);
    initialized_.store(true);
}

void EventsMonitor::RegisterEventsListener(int32_t userId, const std::vector<EventType>& events,
    const std::weak_ptr<IEventsListener>& listener)
{
    DP_INFO_LOG("RegisterEventsListener enter.");
    std::lock_guard<std::mutex> lock(eventMutex_);
    auto& listenersMap = userIdToeventListeners_;
    auto& currentListeners = listenersMap[userId];
    for (const auto &event : events) {
        currentListeners[event].push_back(listener);
    }
}

void EventsMonitor::NotifyThermalLevel(int32_t level)
{
    NotifyObserversUnlocked(EventType::THERMAL_LEVEL_STATUS_EVENT, level);
}

void EventsMonitor::NotifyCameraSessionStatus(CameraSessionStatus status)
{
    NotifyObserversUnlocked(EventType::CAMERA_SESSION_STATUS_EVENT, status);
    auto level = EventsInfo::GetInstance().GetThermalLevel();
    DPSEventReport::GetInstance().SetTemperatureLevel(static_cast<int>(level));
}

void EventsMonitor::NotifyImageEnhanceStatus(int32_t status)
{
    DP_INFO_LOG("DPS_EVENT: ImageEnhanceStatus: %{public}d", status);
    NotifyObserversUnlocked(EventType::PHOTO_HDI_STATUS_EVENT, status);
}

void EventsMonitor::NotifyVideoEnhanceStatus(int32_t status)
{
    DP_INFO_LOG("DPS_EVENT: VideoEnhanceStatus: %{public}d", status);
    NotifyObserversUnlocked(EventType::VIDEO_HDI_STATUS_EVENT, status);
}

void EventsMonitor::NotifyScreenStatus(int32_t status)
{
    NotifyObserversUnlocked(EventType::SCREEN_STATUS_EVENT, status);
}

void EventsMonitor::NotifyChargingStatus(int32_t status)
{
    NotifyObserversUnlocked(EventType::CHARGING_STATUS_EVENT, status);
}

void EventsMonitor::NotifyBatteryStatus(int32_t status)
{
    NotifyObserversUnlocked(EventType::BATTERY_STATUS_EVENT, status);
}

void EventsMonitor::NotifyBatteryLevel(int32_t level)
{
    NotifyObserversUnlocked(EventType::BATTERY_LEVEL_STATUS_EVENT, level);
}

void EventsMonitor::NotifyPhotoProcessSize(int32_t offlineSize, int32_t backSize)
{
    DP_INFO_LOG("DPS_EVENT: offline: %{public}d, background: %{public}d", offlineSize, backSize);
    NotifyObserversUnlocked(EventType::PHOTO_PROCESS_STATUS_EVENT, offlineSize + backSize);
}

void EventsMonitor::NotifyTrailingStatus(int32_t status)
{
    DP_INFO_LOG("DPS_EVENT: TrailingStatus: %{public}d", status);
    NotifyObserversUnlocked(EventType::TRAILING_STATUS_EVENT, status);
}

void EventsMonitor::NotifyInterrupt()
{
    DP_INFO_LOG("DPS_EVENT: Interrupt");
    NotifyObserversUnlocked(EventType::INTERRUPT_EVENT, IS_INTERRUPT);
}

void EventsMonitor::NotifyUserSwitched(int32_t userId)
{
    EventsInfo::GetInstance().SetCurrentUser(userId);
}

void EventsMonitor::NotifyObserversUnlocked(EventType event, int32_t value)
{
    int32_t ret = DPS_SendCommand<EventStatusChangeCommand>(event, value);
    DP_CHECK_ERROR_PRINT_LOG(ret != DP_OK, "send command fail, ret: %{public}d", ret);
}

void EventsMonitor::NotifyEventToObervers(EventType event, int32_t value)
{
    DP_DEBUG_LOG("EventType: %{public}d, value: %{public}d", event, value);
    int32_t userId = EventsInfo::GetInstance().GetCurrentUser();
    DP_DEBUG_LOG("NotifyEventToObervers userId: %{public}d", userId);
    auto eventListeners = userIdToeventListeners_.find(userId);
    if (eventListeners == userIdToeventListeners_.end()) {
        DP_DEBUG_LOG("Not find user[%{private}d] listener", userId);
    } else {
        DP_DEBUG_LOG("Find user[%{private}d] listener", userId);
    }
    DP_CHECK_ERROR_RETURN_LOG(eventListeners == userIdToeventListeners_.end(),
        "Not find user[%{private}d] listener", userId);
    auto iter = eventListeners->second.find(event);
    if (iter == eventListeners->second.end()) {
        DP_ERR_LOG("unexpect event: %{public}d", event);
        return;
    }
    auto& observers = iter->second;
    DP_DEBUG_LOG("Find event[%{public}d] listener, num: %{public}zu", event, observers.size());
    for (auto it = observers.begin(); it != observers.end();) {
        auto observer = it->lock();
        if (observer) {
            DP_DEBUG_LOG("Observer is valid, notify event[%{public}d] to observer", event);
            observer->OnEventChange(event, value);
            ++it;
        } else {
            DP_DEBUG_LOG("Observer is expired, remove it from listener list");
            it = observers.erase(it);
        }
    }
}

void CommonEventListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    std::lock_guard<std::mutex> lock(eventSubscriberMutex_);
    DP_CHECK_RETURN(commonEventSubscriber_ != nullptr && cameraEventSubscriber_ != nullptr);
    DP_DEBUG_LOG("saId: %{public}d", systemAbilityId);
    EventSubscriber::InitializeStrategies();
    commonEventSubscriber_ = EventSubscriber::CreateCommonSubscriber();
    DP_CHECK_ERROR_RETURN_LOG(commonEventSubscriber_ == nullptr,
        "RegisterCommonEvent failed, commonEventSubscriber is nullptr");
    commonEventSubscriber_->Subcribe();
    cameraEventSubscriber_ = EventSubscriber::CreateCameraSubscriber();
    DP_CHECK_ERROR_RETURN_LOG(cameraEventSubscriber_ == nullptr,
        "RegisterCameraEvent failed, cameraEventSubscriber is nullptr");
    cameraEventSubscriber_->Subcribe();
}

void CommonEventListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    std::lock_guard<std::mutex> lock(eventSubscriberMutex_);
    DP_DEBUG_LOG("saId: %{public}d", systemAbilityId);
    DP_CHECK_EXECUTE(commonEventSubscriber_ != nullptr, commonEventSubscriber_->UnSubscribe());
    commonEventSubscriber_ = nullptr;
    DP_CHECK_EXECUTE(cameraEventSubscriber_ != nullptr, cameraEventSubscriber_->UnSubscribe());
    cameraEventSubscriber_ = nullptr;
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
