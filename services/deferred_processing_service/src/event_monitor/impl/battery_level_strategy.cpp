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

#include "battery_level_strategy.h"

#ifdef CAMERA_USE_BATTERY
#include "battery_info.h"
#endif
#include "events_monitor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr int32_t DEFAULT_CAPACITY = -1;
    constexpr int32_t BATTERY_THRESHOLD = 50;
    const std::string KEY_CAPACITY = "soc";
}

BatteryLevelStrategy::BatteryLevelStrategy() : preLevel_(BATTERY_LEVEL_LOW)
{
    DP_DEBUG_LOG("entered.");
}

BatteryLevelStrategy::~BatteryLevelStrategy()
{
    DP_DEBUG_LOG("entered.");
}

void BatteryLevelStrategy::handleEvent(const EventFwk::CommonEventData& data)
{
    int32_t capacity = data.GetWant().GetIntParam(KEY_CAPACITY, DEFAULT_CAPACITY);
    DP_CHECK_RETURN(capacity == DEFAULT_CAPACITY);
    int32_t batteryLevel = BatteryLevel::BATTERY_LEVEL_LOW;
    if (capacity >= BATTERY_THRESHOLD) {
        batteryLevel = BatteryLevel::BATTERY_LEVEL_OKAY;
    }
    DP_CHECK_RETURN(batteryLevel == preLevel_);

    preLevel_ = batteryLevel;
    DP_INFO_LOG("DPS_EVENT: BatteryLevelChanged level:%{public}d", preLevel_);
    EventsMonitor::GetInstance().NotifyBatteryLevel(preLevel_);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS