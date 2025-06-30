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
 
 
#include "accesstoken_kit.h"
#include "access_token.h"
#include "camera_log.h"
#include "deferred_processingservice_event_monitor_fuzzer.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "hap_token_info.h"
#include "image_info.h"
#include "ipc_skeleton.h"
#include "token_setproc.h"
#include "camera_util.h"
 
#include <utility>
 
namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
 
static constexpr int32_t MIN_SIZE_NUM = 4;
 
std::shared_ptr<CameraStrategy> EventMonitorFuzzer::camerastrategyfuzz_ = nullptr;
std::shared_ptr<BatteryLevelStrategy> EventMonitorFuzzer::batterylevelstrategyfuzz_ = nullptr;
std::shared_ptr<BatteryStrategy> EventMonitorFuzzer::batterystrategyfuzz_ = nullptr;
std::shared_ptr<ChargingStrategy> EventMonitorFuzzer::chargingstrategyfuzz_ = nullptr;
std::shared_ptr<ScreenStrategy> EventMonitorFuzzer::screenstrategyfuzz_ = nullptr;
std::shared_ptr<ThermalStrategy> EventMonitorFuzzer::thermalstrategyfuzz_ = nullptr;
std::shared_ptr<EventStatusChangeCommand> EventMonitorFuzzer::eventstatuschangecommandfuzz_ = nullptr;
std::shared_ptr<EventsInfo> EventMonitorFuzzer::eventsinfofuzz_ = nullptr;
std::shared_ptr<EventsMonitor> EventMonitorFuzzer::eventsmonitorfuzz_ = nullptr;
 
void EventMonitorFuzzer::EventMonitorCameraStrategyFuzzTest(FuzzedDataProvider& fdp)
{
    camerastrategyfuzz_ = std::make_shared<CameraStrategy>();
    OHOS::AAFwk::Want want;
    static const std::string EVENT_CAMERA = "CAMERA_BEAUTY_NOTIFICATION";
    want.SetAction(EVENT_CAMERA);
    EventFwk::CommonEventData CommonEventData { want };
    camerastrategyfuzz_->handleEvent(CommonEventData);
 
    batterylevelstrategyfuzz_ = std::make_shared<BatteryLevelStrategy>();
    batterylevelstrategyfuzz_->handleEvent(CommonEventData);
 
    batterystrategyfuzz_ = std::make_shared<BatteryStrategy>();
    batterystrategyfuzz_->handleEvent(CommonEventData);
 
    chargingstrategyfuzz_ = std::make_shared<ChargingStrategy>();
    chargingstrategyfuzz_->handleEvent(CommonEventData);
 
    screenstrategyfuzz_ = std::make_shared<ScreenStrategy>();
    screenstrategyfuzz_->handleEvent(CommonEventData);
 
    thermalstrategyfuzz_ = std::make_shared<ThermalStrategy>();
    thermalstrategyfuzz_->handleEvent(CommonEventData);
 
    int32_t value = 1;
    int32_t enumval = fdp.ConsumeIntegralInRange<int32_t>(1, 13);
    EventType eventType = static_cast<EventType>(enumval);
    int val = 0;
    eventstatuschangecommandfuzz_ = std::make_shared<EventStatusChangeCommand>(eventType, val);
    eventstatuschangecommandfuzz_->Executing();
 
    eventsinfofuzz_ = std::make_shared<EventsInfo>();
    eventsinfofuzz_->GetScreenState();
    eventsinfofuzz_->GetBatteryState();
    eventsinfofuzz_->GetChargingState();
    eventsinfofuzz_->GetBatteryLevel();
    eventsinfofuzz_->GetThermalLevel();
    eventsinfofuzz_->GetCameraState();
    enumval = fdp.ConsumeIntegralInRange<int32_t>(0, 3);
    CameraSessionStatus camerasessionstatus = static_cast<CameraSessionStatus>(enumval);
    eventsinfofuzz_->SetCameraState(camerasessionstatus);
    eventsinfofuzz_->IsCameraOpen();
 
    eventsmonitorfuzz_ = std::make_shared<EventsMonitor>();
    eventsmonitorfuzz_->Initialize();
    std::vector<EventType>events;
    std::weak_ptr<IEventsListener>listener;
    eventsmonitorfuzz_->RegisterEventsListener(events, listener);
    int32_t level = fdp.ConsumeIntegral<int32_t>();
    eventsmonitorfuzz_->NotifyThermalLevel(level);
    enumval = fdp.ConsumeIntegralInRange<int32_t>(0, 3);
    camerasessionstatus = static_cast<CameraSessionStatus>(enumval);
    eventsmonitorfuzz_->NotifyCameraSessionStatus(camerasessionstatus);
    bool available = fdp.ConsumeBool();
    eventsmonitorfuzz_->NotifyMediaLibraryStatus(available);
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    eventsmonitorfuzz_->NotifyImageEnhanceStatus(status);
    status = fdp.ConsumeIntegral<int32_t>();
    eventsmonitorfuzz_->NotifyVideoEnhanceStatus(status);
    status = fdp.ConsumeIntegral<int32_t>();
    eventsmonitorfuzz_->NotifyScreenStatus(status);
    status = fdp.ConsumeIntegral<int32_t>();
    eventsmonitorfuzz_->NotifyChargingStatus(status);
    status = fdp.ConsumeIntegral<int32_t>();
    eventsmonitorfuzz_->NotifyBatteryStatus(status);
    status = fdp.ConsumeIntegral<int32_t>();
    eventsmonitorfuzz_->NotifyBatteryLevel(status);

    status = fdp.ConsumeIntegral<int32_t>();
    eventsmonitorfuzz_->NotifyTrailingStatus(status);
    enumval = fdp.ConsumeIntegralInRange<int32_t>(1, 13);
    eventType = static_cast<EventType>(enumval);
    value = fdp.ConsumeIntegral<int32_t>();
    eventsmonitorfuzz_->NotifyObserversUnlocked(eventType, value);
    value = fdp.ConsumeIntegral<int32_t>();
    eventsmonitorfuzz_->NotifyEventToObervers(eventType, value);
    eventsmonitorfuzz_->SubscribeSystemAbility();
    eventsmonitorfuzz_->UnSubscribeSystemAbility();
}
 
void Test(uint8_t* data, size_t size)
{
    auto eventMonitor = std::make_unique<EventMonitorFuzzer>();
    if (eventMonitor == nullptr) {
        MEDIA_INFO_LOG("eventMonitor is null");
        return;
    }
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    eventMonitor->EventMonitorCameraStrategyFuzzTest(fdp);
}
}
} // namespace CameraStandard
} // namespace OHOS
 
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraStandard::DeferredProcessing::Test(data, size);
    return 0;
}