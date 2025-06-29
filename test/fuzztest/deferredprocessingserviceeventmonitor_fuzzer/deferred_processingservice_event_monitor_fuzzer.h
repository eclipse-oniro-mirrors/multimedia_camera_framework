 /*
  * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 
#ifndef EVENT_MONITOR_FUZZER_H
#define EVENT_MONITOR_FUZZER_H
 
 
#include <fuzzer/FuzzedDataProvider.h>
#include "battery_level_strategy.h"
#include "battery_strategy.h"
#include "camera_strategy.h"
#include "charging_strategy.h"
#include "screen_strategy.h"
#include "thermal_strategy.h"
#include "command/event_status_change_command.h"
#include "events_info.h"
#include "events_monitor.h"
#include "events_subscriber.h"
#include "ievents_listener.h"
 
 
namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
 
class EventMonitorFuzzer {
public:
    
    static std::shared_ptr<BatteryLevelStrategy> batterylevelstrategyfuzz_;
    static std::shared_ptr<BatteryStrategy> batterystrategyfuzz_;
    static std::shared_ptr<CameraStrategy> camerastrategyfuzz_;
    static std::shared_ptr<ChargingStrategy> chargingstrategyfuzz_;
    static std::shared_ptr<ScreenStrategy> screenstrategyfuzz_;
    static std::shared_ptr<ThermalStrategy> thermalstrategyfuzz_;
    static std::shared_ptr<EventStatusChangeCommand> eventstatuschangecommandfuzz_;
    static std::shared_ptr<EventsInfo> eventsinfofuzz_;
    static std::shared_ptr<EventsMonitor> eventsmonitorfuzz_;
    
    static void EventMonitorCameraStrategyFuzzTest(FuzzedDataProvider& fdp);
};
}
} //CameraStandard
} //OHOS
#endif //EVENT_MONITOR_FUZZER_H