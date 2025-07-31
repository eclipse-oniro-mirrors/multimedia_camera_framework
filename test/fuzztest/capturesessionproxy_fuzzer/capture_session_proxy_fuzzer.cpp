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

#include "ability/camera_ability_const.h"
#include "capture_session_proxy_fuzzer.h"
#include "capture_session_proxy.h"
#include "camera_log.h"
#include "iconsumer_surface.h"
#include "securec.h"
#include "system_ability_definition.h"
#include "icapture_session.h"
#include "capture_session.h"
#include "securec.h"
#include "iservice_registry.h"
#include "token_setproc.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
namespace OHOS {
namespace CameraStandard {
const size_t THRESHOLD = 10;
const int32_t MAX_BUFFER_SIZE = 16;
static constexpr int32_t NUM_1 = 1;
std::shared_ptr<CaptureSessionProxy> CaptureSessionProxyFuzz::fuzz_{nullptr};

void CaptureSessionProxyFuzz::CaptureSessionProxyFuzzTest1(FuzzedDataProvider &fdp)
{
    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!mgr, "samgr nullptr");
    auto object = mgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!object, "object nullptr");
    fuzz_ = std::make_shared<CaptureSessionProxy>(object);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    uint8_t vectorSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    std::vector<float> virtualApertureMetadata;
    for (int i = 0; i < vectorSize; ++i) {
        virtualApertureMetadata.push_back(fdp.ConsumeFloatingPoint<float>());
    }
    fuzz_->GetVirtualApertureMetadate(virtualApertureMetadata);
    float value;
    fuzz_->GetVirtualApertureValue(value);
    float values = fdp.ConsumeFloatingPoint<float>();
    bool needPersist = fdp.ConsumeIntegral<int32_t>() ? 1 : 0;
    fuzz_->SetVirtualApertureValue(values, needPersist);
}

void CaptureSessionProxyFuzz::CaptureSessionProxyFuzzTest2(FuzzedDataProvider &fdp)
{
    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!mgr, "samgr nullptr");
    auto object = mgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!object, "object nullptr");
    fuzz_ = std::make_shared<CaptureSessionProxy>(object);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    fuzz_->Stop();
    constexpr int32_t executionModeCount = static_cast<int32_t>(ColorSpace::P3_PQ_LIMIT) + NUM_1;
    ColorSpace colorSpace = static_cast<ColorSpace>(fdp.ConsumeIntegral<uint8_t>() % executionModeCount);
    int32_t curColorSpace = static_cast<int32_t>(colorSpace);
    fuzz_->GetActiveColorSpace(curColorSpace);
    int32_t colorSpaceSetting = static_cast<int32_t>(colorSpace);
    bool ret = fdp.ConsumeIntegral<int32_t>() ? 1 : 0;
    fuzz_->SetColorSpace(colorSpaceSetting, ret);
}

void CaptureSessionProxyFuzz::CaptureSessionProxyFuzzTest3(FuzzedDataProvider &fdp)
{
    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!mgr, "samgr nullptr");
    auto object = mgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!object, "object nullptr");
    fuzz_ = std::make_shared<CaptureSessionProxy>(object);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");

    int32_t smoothZoomType = fdp.ConsumeIntegral<int32_t>();
    int32_t operationMode = fdp.ConsumeIntegral<int32_t>();
    float targetZoomRatio = fdp.ConsumeFloatingPoint<float>();
    float duration = fdp.ConsumeFloatingPoint<float>();
    fuzz_->SetSmoothZoom(smoothZoomType, operationMode, targetZoomRatio, duration);
    bool isHasFitedRotation = fdp.ConsumeIntegral<int32_t>() ? 1 : 0;
    fuzz_->SetHasFitedRotation(isHasFitedRotation);
}

void CaptureSessionProxyFuzz::CaptureSessionProxyFuzzTest4(FuzzedDataProvider &fdp)
{
    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!mgr, "samgr nullptr");
    auto object = mgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!object, "object nullptr");
    fuzz_ = std::make_shared<CaptureSessionProxy>(object);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    bool ret = fdp.ConsumeIntegral<int32_t>() ? 1 : 0;
    fuzz_->EnableMovingPhoto(ret);
    bool isMirror = fdp.ConsumeIntegral<int32_t>() ? 1 : 0;
    bool isConfig = fdp.ConsumeIntegral<int32_t>() ? 1 : 0;
    fuzz_->EnableMovingPhotoMirror(isMirror, isConfig);
}

void CaptureSessionProxyFuzz::CaptureSessionProxyFuzzTest5(FuzzedDataProvider &fdp)
{
    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!mgr, "samgr nullptr");
    auto object = mgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!object, "object nullptr");
    fuzz_ = std::make_shared<CaptureSessionProxy>(object);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    std::vector<std::string> testStrings = {"test1", "test2"};
    int8_t randomNum = fdp.ConsumeIntegral<uint8_t>();
    std::string deviceClass(testStrings[randomNum % testStrings.size()]);
    fuzz_->SetPreviewRotation(deviceClass);
}

void CaptureSessionProxyFuzz::CaptureSessionProxyFuzzTest6()
{
    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!mgr, "samgr nullptr");
    auto object = mgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!object, "object nullptr");
    fuzz_ = std::make_shared<CaptureSessionProxy>(object);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    sptr<ICaptureSessionCallback> captureSessionCallback = new (std::nothrow)CaptureSessionCallback();
    fuzz_->SetCallback(captureSessionCallback);
    sptr<IPressureStatusCallback> pressureStatusCallback = new (std::nothrow)PressureStatusCallback();
    fuzz_->SetPressureCallback(pressureStatusCallback);
    fuzz_->UnSetCallback();
    fuzz_->UnSetPressureCallback();
    sptr<IControlCenterEffectStatusCallback> callbackFunc = new (std::nothrow)ControlCenterEffectStatusCallback();
    fuzz_->SetControlCenterEffectStatusCallback(callbackFunc);
    fuzz_->UnSetControlCenterEffectStatusCallback();
}

void CaptureSessionProxyFuzz::CaptureSessionProxyFuzzTest7(FuzzedDataProvider &fdp)
{
    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(!mgr, "samgr nullptr");
    auto object = mgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(!object, "object nullptr");
    fuzz_ = std::make_shared<CaptureSessionProxy>(object);
    CHECK_RETURN_ELOG(!fuzz_, "fuzz_ nullptr");
    std::vector<int32_t> beautyApertureMetadata;
    uint8_t vectorSize = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_BUFFER_SIZE);
    for (int i = 0; i < vectorSize; ++i) {
        beautyApertureMetadata.push_back(fdp.ConsumeIntegral<int32_t>());
    }
    fuzz_->GetBeautyMetadata(beautyApertureMetadata);
    int32_t type = fdp.ConsumeIntegral<int32_t>();
    std::vector<int32_t> range;
    for (int i = 0; i < vectorSize; ++i) {
        range.push_back(fdp.ConsumeIntegral<int32_t>());
    }
    fuzz_->GetBeautyRange(range, type);
    int32_t beautyValue = fdp.ConsumeIntegral<int32_t>();
    fuzz_->GetBeautyValue(type, beautyValue);
}

void FuzzTest(const uint8_t *rawData, size_t size)
{
    FuzzedDataProvider fdp(rawData, size);
    auto captureSessionProxy = std::make_unique<CaptureSessionProxyFuzz>();
    if (captureSessionProxy == nullptr) {
        MEDIA_INFO_LOG("captureSessionProxy is null");
        return;
    }
    captureSessionProxy->CaptureSessionProxyFuzzTest1(fdp);
    captureSessionProxy->CaptureSessionProxyFuzzTest2(fdp);
    captureSessionProxy->CaptureSessionProxyFuzzTest3(fdp);
    captureSessionProxy->CaptureSessionProxyFuzzTest4(fdp);
    captureSessionProxy->CaptureSessionProxyFuzzTest5(fdp);
    captureSessionProxy->CaptureSessionProxyFuzzTest6();
    captureSessionProxy->CaptureSessionProxyFuzzTest7(fdp);
}
}  // namespace CameraStandard
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    if (size < OHOS::CameraStandard::THRESHOLD) {
        return 0;
    }

    OHOS::CameraStandard::FuzzTest(data, size);
    return 0;
}