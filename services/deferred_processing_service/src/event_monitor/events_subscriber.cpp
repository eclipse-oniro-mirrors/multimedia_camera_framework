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

#include "events_subscriber.h"

#include "battery_level_strategy.h"
#include "battery_strategy.h"
#include "camera_strategy.h"
#include "common_event_subscribe_info.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "charging_strategy.h"
#include "dp_utils.h"
#include "screen_strategy.h"
#include "thermal_strategy.h"
#include "user_strategy.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr char COMMON_EVENT_CAMERA_STATUS[] = "usual.event.CAMERA_STATUS";
    constexpr char OHOS_PERMISSION_MANAGE_CAMERA_CONFIG[] = "ohos.permission.MANAGE_CAMERA_CONFIG";
}

std::mutex EventSubscriber::mutex_;
std::unordered_map<std::string, std::shared_ptr<EventStrategy>> EventSubscriber::eventStrategy_;

const std::vector<std::string> EventSubscriber::commonEvents_ = {
    OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED,
    OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON,
    OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF,
    OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_CHARGING,
    OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_DISCHARGING,
    OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_OKAY,
    OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_LOW,
    OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED,
    OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED,
};

EventSubscriber::EventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo& subscriberInfo)
    : CommonEventSubscriber(subscriberInfo)
{
    DP_DEBUG_LOG("entered.");
}

EventSubscriber::~EventSubscriber()
{
    DP_DEBUG_LOG("entered.");
}

std::shared_ptr<EventSubscriber> EventSubscriber::CreateCommonSubscriber()
{
    DP_DEBUG_LOG("entered.");
    OHOS::EventFwk::MatchingSkills matchingSkills;
    for (const auto& event : commonEvents_) {
        matchingSkills.AddEvent(event);
    }
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    return CreateShared<EventSubscriber>(subscriberInfo);
}

std::shared_ptr<EventSubscriber> EventSubscriber::CreatePermissionSubscriber(
    const std::string& event, const std::string& permission)
{
    DP_DEBUG_LOG("entered.");
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(event);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetPermission(permission);
    return CreateShared<EventSubscriber>(subscriberInfo);
}

std::shared_ptr<EventSubscriber> EventSubscriber::CreateCameraSubscriber()
{
    DP_DEBUG_LOG("entered.");
    return CreatePermissionSubscriber(COMMON_EVENT_CAMERA_STATUS, OHOS_PERMISSION_MANAGE_CAMERA_CONFIG);
}

void EventSubscriber::InitializeStrategies()
{
    DP_DEBUG_LOG("entered.");
    std::lock_guard<std::mutex> lock(mutex_);
    if (!eventStrategy_.empty()) {
        return;
    }
    eventStrategy_[OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED]
        = std::make_shared<ThermalStrategy>();
    auto screen = std::make_shared<ScreenStrategy>();
    eventStrategy_[OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON]
        = screen;
    eventStrategy_[OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF]
        = screen;
    auto charging = std::make_shared<ChargingStrategy>();
    eventStrategy_[OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_CHARGING]
        = charging;
    eventStrategy_[OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_DISCHARGING]
        = charging;
    auto batteryState = std::make_shared<BatteryStrategy>();
    eventStrategy_[OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_OKAY]
        = batteryState;
    eventStrategy_[OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_LOW]
        = batteryState;
    eventStrategy_[OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED]
        = std::make_shared<BatteryLevelStrategy>();
    eventStrategy_[OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED]
        = std::make_shared<UserStrategy>();
    eventStrategy_[COMMON_EVENT_CAMERA_STATUS] = std::make_shared<CameraStrategy>();
}

void EventSubscriber::Subcribe()
{
    DP_CHECK_ERROR_RETURN_LOG(!EventFwk::CommonEventManager::SubscribeCommonEvent(shared_from_this()),
        "SubscribeCommonEvent failed");
    DP_INFO_LOG("SubscribeCommonEvent OK");
}

void EventSubscriber::UnSubscribe()
{
    DP_CHECK_ERROR_RETURN_LOG(!EventFwk::CommonEventManager::UnSubscribeCommonEvent(shared_from_this()),
        "UnSubscribeCommonEvent failed");
    DP_INFO_LOG("UnSubscribeCommonEvent OK");
}

void EventSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData& data)
{
    auto action = data.GetWant().GetAction();
    DP_DEBUG_LOG("DPS_EVENT: %{public}s.", action.c_str());
    std::lock_guard lock(mutex_);
    auto iter = eventStrategy_.find(action);
    DP_CHECK_ERROR_RETURN_LOG(iter == eventStrategy_.end(), "Not find strategy.");
    if (auto strategy = iter->second) {
        strategy->handleEvent(data);
    }
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS