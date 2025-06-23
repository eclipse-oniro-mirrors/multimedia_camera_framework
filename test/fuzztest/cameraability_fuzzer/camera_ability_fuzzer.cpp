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

#include <cstddef>
#include <cstdint>
#include <memory>

#include "accesstoken_kit.h"
#include "camera_ability_fuzzer.h"
#include "camera_log.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "securec.h"
#include "test_token.h"
#include "token_setproc.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 24;
const int32_t NUM_TWO = 2;
std::shared_ptr<CameraAbility> CameraAbilityFuzzer::fuzz_{nullptr};

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/

void CameraAbilityFuzzer::CameraAbilityFuzzTest(FuzzedDataProvider& fdp)
{
    CHECK_ERROR_RETURN_LOG(!TestToken::GetAllCameraPermission(), "GetPermission error");
    fuzz_ = std::make_shared<CameraAbility>();
    CHECK_ERROR_RETURN_LOG(!fuzz_, "Create fuzz_ Error");
    fuzz_->HasFlash();
    {
        int32_t getData = fdp.ConsumeIntegral<int32_t>();
        FlashMode flashMode = static_cast<FlashMode>(
            getData % (FlashMode::FLASH_MODE_ALWAYS_OPEN + NUM_TWO));
        fuzz_->IsFlashModeSupported(flashMode);
    }
    fuzz_->GetSupportedFlashModes();
    {
        int32_t getData = fdp.ConsumeIntegral<int32_t>();
        ExposureMode exposureMode = static_cast<ExposureMode>(
            getData % (ExposureMode::EXPOSURE_MODE_CONTINUOUS_AUTO + NUM_TWO));
        fuzz_->IsExposureModeSupported(exposureMode);
    }
    fuzz_->GetSupportedExposureModes();
    fuzz_->GetExposureBiasRange();
    fuzz_->GetSupportedFocusModes();
    {
        int32_t getData = fdp.ConsumeIntegral<int32_t>();
        FocusMode focusMode = static_cast<FocusMode>(
            getData % (FocusMode::FOCUS_MODE_LOCKED + NUM_TWO));
        fuzz_->IsFocusModeSupported(focusMode);
    }
    fuzz_->GetZoomRatioRange();
    fuzz_->GetSupportedBeautyTypes();
    {
        int32_t getData = fdp.ConsumeIntegral<int32_t>();
        BeautyType beautyType = static_cast<BeautyType>(
            getData % (BeautyType::SKIN_TONE + NUM_TWO));
        fuzz_->GetSupportedBeautyRange(beautyType);
    }
    fuzz_->GetSupportedColorEffects();
    fuzz_->GetSupportedColorSpaces();
    fuzz_->IsMacroSupported();
    fuzz_->GetSupportedPortraitEffects();
    fuzz_->GetSupportedVirtualApertures();
    fuzz_->GetSupportedPhysicalApertures();
    fuzz_->GetSupportedStabilizationMode();
    {
        int32_t getData = fdp.ConsumeIntegral<int32_t>();
        VideoStabilizationMode stabilizationMode = static_cast<VideoStabilizationMode>(
            getData % (VideoStabilizationMode::AUTO + NUM_TWO));
        fuzz_->IsVideoStabilizationModeSupported(stabilizationMode);
    }
    fuzz_->GetSupportedExposureRange();
    {
        int32_t getData = fdp.ConsumeIntegral<int32_t>();
        SceneFeature feature = static_cast<SceneFeature>(
            getData % (SceneFeature::FEATURE_ENUM_MAX + NUM_TWO));
        fuzz_->IsFeatureSupported(feature);
    }
    fuzz_->IsLcdFlashSupported();
}

void Test(uint8_t* data, size_t size)
{
    auto cameraAbility = std::make_unique<CameraAbilityFuzzer>();
    if (cameraAbility == nullptr) {
        MEDIA_INFO_LOG("cameraAbility is null");
        return;
    }
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    cameraAbility->CameraAbilityFuzzTest(fdp);
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}