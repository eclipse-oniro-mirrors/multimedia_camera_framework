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

#include "events_subscriber.h"

#include "battery_level_strategy.h"
#include "battery_strategy.h"
#include "common_event_subscribe_info.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "charging_strategy.h"
#include "dp_utils.h"
#include "screen_strategy.h"
#include "thermal_strategy.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
const std::vector<std::string> EventSubscriber::events_ = {
    OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED,
    OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON,
    OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF,
    OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_CHARGING,
    OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_DISCHARGING,
    OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_OKAY,
    OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_LOW,
    OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED,
};

EventSubscriber::EventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo& subscriberInfo)
    : CommonEventSubscriber(subscriberInfo)
{
    DP_DEBUG_LOG("entered.");
    Initialize();
}

EventSubscriber::~EventSubscriber()
{
    DP_DEBUG_LOG("entered.");
    eventStrategy_.clear();
}

std::shared_ptr<EventSubscriber> EventSubscriber::Create()
{
    DP_DEBUG_LOG("entered.");
    OHOS::EventFwk::MatchingSkills matchingSkills;
    for (auto event : events_) {
        matchingSkills.AddEvent(event);
    }
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    return CreateShared<EventSubscriber>(subscriberInfo);
}

void EventSubscriber::Initialize()
{
    DP_DEBUG_LOG("entered.");
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
    AAFwk::Want want = data.GetWant();
    auto action = want.GetAction();
    DP_INFO_LOG("EventSubscriber::OnReceiveEvent: %{public}s.", action.c_str());
    auto entry = eventStrategy_.find(action);
    if (entry != eventStrategy_.end()) {
        auto strategy = entry->second;
        if (strategy != nullptr) {
            strategy->handleEvent(data);
        }
    }
    DP_DEBUG_LOG("EventSubscriber::OnReceiveEvent: end");
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS