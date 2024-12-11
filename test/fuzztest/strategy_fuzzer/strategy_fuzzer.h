 /*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef STRATEGY_FUZZER_H
#define STRATEGY_FUZZER_H

#include "battery_level_strategy.h"
#include "battery_strategy.h"
#include "charging_strategy.h"
#include "screen_strategy.h"
#include "thermal_strategy.h"
#include "dps_event_report.h"

namespace OHOS {
namespace CameraStandard {
using namespace DeferredProcessing;
class BatteryLevelStrategyFuzzer {
public:
static BatteryLevelStrategy *fuzz;
static void BatteryLevelStrategyFuzzTest();
};

class BatteryStrategyFuzzer {
public:
static BatteryStrategy *fuzz;
static void BatteryStrategyFuzzTest();
};

class ChargingStrategyFuzzer {
public:
static ChargingStrategy *fuzz;
static void ChargingStrategyFuzzTest();
};

class ScreenStrategyFuzzer {
public:
static ScreenStrategy *fuzz;
static void ScreenStrategyFuzzTest();
};

class ThermalStrategyFuzzer {
public:
static ThermalStrategy *fuzz;
static void ThermalStrategyFuzzTest();
};
}
}
#endif