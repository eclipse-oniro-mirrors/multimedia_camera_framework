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

#include "camera_ability_fuzzer.h"
#include "camera_log.h"
#include "message_parcel.h"
#include "securec.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;

const int32_t NUM_TWO = 2;
CameraAbility *CameraAbilityFuzzer::fuzz_ = nullptr;

/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/
template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_dataSize - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

template<class T>
uint32_t GetArrLength(T& arr)
{
    if (arr == nullptr) {
        MEDIA_INFO_LOG("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

void GetPermission()
{
    uint64_t tokenId;
    const char* perms[2];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.CAMERA";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "native_camera_tdd",
        .aplStr = "system_basic",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

void CameraAbilityFuzzer::CameraAbilityFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }

    GetPermission();
    if (fuzz_ == nullptr) {
        fuzz_ = new CameraAbility();
    }
    fuzz_->HasFlash();
    FlashMode flashMode = static_cast<FlashMode>(
        GetData<int32_t>() % (FlashMode::FLASH_MODE_ALWAYS_OPEN + NUM_TWO));
    fuzz_->IsFlashModeSupported(flashMode);
    fuzz_->GetSupportedFlashModes();
    ExposureMode exposureMode = static_cast<ExposureMode>(
        GetData<int32_t>() % (ExposureMode::EXPOSURE_MODE_CONTINUOUS_AUTO + NUM_TWO));
    fuzz_->IsExposureModeSupported(exposureMode);
    fuzz_->GetSupportedExposureModes();
    fuzz_->GetExposureBiasRange();
    fuzz_->GetSupportedFocusModes();
    FocusMode focusMode = static_cast<FocusMode>(
        GetData<int32_t>() % (FocusMode::FOCUS_MODE_LOCKED + NUM_TWO));
    fuzz_->IsFocusModeSupported(focusMode);
    fuzz_->GetZoomRatioRange();
    fuzz_->GetSupportedBeautyTypes();
    BeautyType beautyType = static_cast<BeautyType>(
        GetData<int32_t>() % (BeautyType::SKIN_TONE + NUM_TWO));
    fuzz_->GetSupportedBeautyRange(beautyType);
    fuzz_->GetSupportedColorEffects();
    fuzz_->GetSupportedColorSpaces();
    fuzz_->IsMacroSupported();
    fuzz_->GetSupportedPortraitEffects();
    fuzz_->GetSupportedVirtualApertures();
    fuzz_->GetSupportedPhysicalApertures();
    fuzz_->GetSupportedStabilizationMode();
    VideoStabilizationMode stabilizationMode = static_cast<VideoStabilizationMode>(
        GetData<int32_t>() % (VideoStabilizationMode::AUTO + NUM_TWO));
    fuzz_->IsVideoStabilizationModeSupported(stabilizationMode);
    fuzz_->GetSupportedExposureRange();
    SceneFeature feature = static_cast<SceneFeature>(
        GetData<int32_t>() % (SceneFeature::FEATURE_ENUM_MAX + NUM_TWO));
    fuzz_->IsFeatureSupported(feature);
    fuzz_->IsLcdFlashSupported();
}

void Test()
{
    auto cameraAbility = std::make_unique<CameraAbilityFuzzer>();
    if (cameraAbility == nullptr) {
        MEDIA_INFO_LOG("cameraAbility is null");
        return;
    }
    cameraAbility->CameraAbilityFuzzTest();
}

typedef void (*TestFuncs[1])();

TestFuncs g_testFuncs = {
    Test,
};

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    // initialize data
    RAW_DATA = rawData;
    g_dataSize = size;
    g_pos = 0;

    uint32_t code = GetData<uint32_t>();
    uint32_t len = GetArrLength(g_testFuncs);
    if (len > 0) {
        g_testFuncs[code % len]();
    } else {
        MEDIA_INFO_LOG("%{public}s: The len length is equal to 0", __func__);
    }

    return true;
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < OHOS::CameraStandard::THRESHOLD) {
        return 0;
    }

    OHOS::CameraStandard::FuzzTest(data, size);
    return 0;
}