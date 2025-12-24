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

void EventsMonitor::RegisterEventsListener(const std::vector<EventType>& events,
    const std::weak_ptr<IEventsListener>& listener)
{
    DP_INFO_LOG("RegisterEventsListener enter.");
    std::lock_guard<std::mutex> lock(eventMutex_);
    for (const auto& event : events) {
        eventListenerList_[event].push_back(listener);
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

void EventsMonitor::NotifyObserversUnlocked(EventType event, int32_t value)
{
    int32_t ret = DPS_SendUrgentCommand<EventStatusChangeCommand>(event, value);
    DP_CHECK_ERROR_PRINT_LOG(ret != DP_OK, "send command fail, ret: %{public}d", ret);
}

void EventsMonitor::NotifyEventToObervers(EventType event, int32_t value)
{
    DP_DEBUG_LOG("EventType: %{public}d, value: %{public}d", event, value);
    auto iter = eventListenerList_.find(event);
    if (iter == eventListenerList_.end()) {
        DP_ERR_LOG("unexpect event: %{public}d", event);
        return;
    }

    auto& observers = iter->second;
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

void CommonEventListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    std::lock_guard<std::mutex> lock(eventSubscriberMutex_);
    DP_CHECK_RETURN(eventSubscriber_ != nullptr);
    DP_DEBUG_LOG("saId: %{public}d", systemAbilityId);
    eventSubscriber_ = EventSubscriber::Create();
    DP_CHECK_ERROR_RETURN_LOG(eventSubscriber_ == nullptr, "RegisterEventStatus failed, eventSubscriber is nullptr");
    eventSubscriber_->Subcribe();
}

void CommonEventListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    std::lock_guard<std::mutex> lock(eventSubscriberMutex_);
    DP_CHECK_RETURN(eventSubscriber_ == nullptr);
    DP_DEBUG_LOG("saId: %{public}d", systemAbilityId);
    DP_CHECK_ERROR_RETURN_LOG(eventSubscriber_ == nullptr, "UnregisterEventStatus failed, eventSubscriber is nullptr");
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
