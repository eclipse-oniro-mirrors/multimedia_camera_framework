/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "thermal_strategy.h"

#include "dps_event_report.h"
#include "events_monitor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    const std::string THERMAL_EVENT_ID = "0";
    constexpr int32_t DEFAULT_LEVEL = 0;
}

ThermalStrategy::ThermalStrategy()
{
    DP_DEBUG_LOG("entered.");
}

ThermalStrategy::~ThermalStrategy()
{
    DP_DEBUG_LOG("entered.");
}

void ThermalStrategy::handleEvent(const EventFwk::CommonEventData& data)
{
    AAFwk::Want want = data.GetWant();
    int level = want.GetIntParam(THERMAL_EVENT_ID, DEFAULT_LEVEL);
    DPSEventReport::GetInstance().SetTemperatureLevel(level);
    DP_INFO_LOG("DPS_EVENT: ThermalLevelChanged level:%{public}d", level);
    EventsMonitor::GetInstance().NotifyThermalLevel(level);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS