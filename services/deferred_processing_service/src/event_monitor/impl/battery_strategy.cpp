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

#include "battery_strategy.h"

#include "basic_definitions.h"
#include "common_event_support.h"
#include "events_monitor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
BatteryStrategy::BatteryStrategy()
{
    DP_DEBUG_LOG("entered.");
}

BatteryStrategy::~BatteryStrategy()
{
    DP_DEBUG_LOG("entered.");
}

void BatteryStrategy::handleEvent(const EventFwk::CommonEventData& data)
{
    auto action = data.GetWant().GetAction();
    int32_t batteryState = BatteryStatus::BATTERY_LOW;
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_LOW) {
        batteryState = BatteryStatus::BATTERY_LOW;
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_OKAY) {
        batteryState = BatteryStatus::BATTERY_OKAY;
    }
    DP_INFO_LOG("OnBatteryStatusChanged state:%{public}d", batteryState);
    EventsMonitor::GetInstance().NotifyBatteryStatus(batteryState);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS