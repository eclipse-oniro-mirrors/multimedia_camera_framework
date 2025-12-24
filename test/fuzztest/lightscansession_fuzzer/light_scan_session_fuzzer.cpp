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
#include "light_scan_session_fuzzer.h"
#include "camera_log.h"
#include "message_parcel.h"
#include "securec.h"
#include <memory>
#include "timer.h"
#include "input/camera_manager.h"
#include "input/camera_manager_for_sys.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 16;
sptr<LightPaintingSession> LightScanSessionFuzzer::fuzzLight_{nullptr};
sptr<ScanSession> LightScanSessionFuzzer::fuzzScan_{nullptr};

sptr<CameraManager> cameraManager = CameraManager::GetInstance();
void LightScanSessionFuzzer::LightPaintingSessionFuzzTest(FuzzedDataProvider& fdp)
{
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    sptr<CameraManager> cameraManager = CameraManager::GetInstance();
    sptr<CaptureSessionForSys> captureSessionForSys =
        CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::SLOW_MOTION);
    auto lightPaintingSession = static_cast<LightPaintingSession*>(captureSessionForSys.GetRefPtr());
    fuzzLight_ = lightPaintingSession;
    CHECK_RETURN_ELOG(!fuzzLight_, "Create fuzzLight_ Error");

    std::vector<LightPaintingType> supportedType;
    fuzzLight_->GetSupportedLightPaintings(supportedType);
    LightPaintingType setType = LightPaintingType::LIGHT;
    fuzzLight_->GetLightPainting(setType);
    fuzzLight_->SetLightPainting(setType);
    fuzzLight_->TriggerLighting();
}
void LightScanSessionFuzzer::ScanSessionFuzzTest(FuzzedDataProvider& fdp)
{
    sptr<CameraManager> cameraManager = CameraManager::GetInstance();
    sptr<CaptureSession> captureSession = cameraManager->CreateCaptureSession(SceneMode::SCAN);
    sptr<ScanSession> scanSession = static_cast<ScanSession*>(captureSession.GetRefPtr());
    fuzzScan_ = scanSession;
    CHECK_RETURN_ELOG(!fuzzScan_, "Create fuzzScan_ Error");
    fuzzScan_->BeginConfig();
    sptr<CaptureOutput> preview = nullptr;
    fuzzScan_->AddOutput(preview);
    fuzzScan_->IsBrightnessStatusSupported();
    fuzzScan_->UnRegisterBrightnessStatusCallback();
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto lightscansession = std::make_unique<LightScanSessionFuzzer>();
    if (lightscansession == nullptr) {
        MEDIA_INFO_LOG("lightscansession is null");
        return;
    }
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    MEDIA_INFO_LOG("yuanwp_fuzz 001");
    lightscansession->LightPaintingSessionFuzzTest(fdp);
    lightscansession->ScanSessionFuzzTest(fdp);
}

} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}