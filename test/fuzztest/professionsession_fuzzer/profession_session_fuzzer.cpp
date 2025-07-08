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

#include <cstddef>
#include <cstdint>
#include <memory>

#include "accesstoken_kit.h"
#include "camera_log.h"
#include "ipc_skeleton.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "profession_session_fuzzer.h"
#include "securec.h"
#include "test_token.h"
#include "token_setproc.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MAX_CODE_LEN = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;

const int32_t NUM_FOUR = 4;
const int32_t NUM_THREE = 3;
sptr<ProfessionSession> ProfessionSessionFuzzer::fuzz_{nullptr};
sptr<CameraManager> manager_;

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

sptr<CaptureOutput> CreatePreviewOutput(Profile& profile)
{
    sptr<IConsumerSurface> previewSurface = IConsumerSurface::Create();
    Size previewSize = profile.GetSize();
    previewSurface->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
    previewSurface->SetDefaultWidthAndHeight(previewSize.width, previewSize.height);

    sptr<IBufferProducer> bp = previewSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(bp);

    sptr<CaptureOutput> previewOutput = nullptr;
    previewOutput = manager_->CreatePreviewOutput(profile, pSurface);
    return previewOutput;
}

sptr<CaptureOutput> CreateVideoOutput(VideoProfile& videoProfile)
{
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    sptr<IBufferProducer> videoProducer = surface->GetProducer();
    sptr<Surface> videoSurface = Surface::CreateSurfaceAsProducer(videoProducer);
    sptr<CaptureOutput> videoOutput = nullptr;
    videoOutput = manager_->CreateVideoOutput(videoProfile, videoSurface);
    return videoOutput;
}

void ProfessionSessionFuzzer::ProfessionSessionFuzzTest1()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    MeteringMode meteringModes = static_cast<MeteringMode>(GetData<int32_t>() % NUM_FOUR);
    std::vector<MeteringMode> supportedMeteringModes = {};
    supportedMeteringModes.push_back(meteringModes);
    fuzz_->GetSupportedMeteringModes(supportedMeteringModes);
    bool isSupported = GetData<bool>();
    fuzz_->IsMeteringModeSupported(meteringModes, isSupported);
    fuzz_->SetMeteringMode(meteringModes);
    fuzz_->GetMeteringMode(meteringModes);
}

void ProfessionSessionFuzzer::ProfessionSessionFuzzTest2()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    bool isSupported = GetData<bool>();
    fuzz_->HasFlash(isSupported);
    ColorEffect colorEffects = static_cast<ColorEffect>(GetData<int32_t>() % NUM_FOUR);
    vector<ColorEffect> supportedColorEffects;
    fuzz_->GetSupportedColorEffects(supportedColorEffects);
    fuzz_->GetColorEffect(colorEffects);
    fuzz_->SetColorEffect(colorEffects);
    vector<int32_t> isoRange;
    fuzz_->GetIsoRange(isoRange);
    int32_t range = GetData<int32_t>();
    fuzz_->SetISO(range);
    fuzz_->GetISO(range);
    fuzz_->IsManualIsoSupported();
    FocusMode focusMode = static_cast<FocusMode>(GetData<int32_t>() % NUM_FOUR);
    vector<FocusMode> supportedFocusModes;
    supportedFocusModes.push_back(focusMode);
    fuzz_->GetSupportedFocusModes(supportedFocusModes);
    fuzz_->IsFocusModeSupported(focusMode, isSupported);
    fuzz_->SetFocusMode(focusMode);
    fuzz_->GetFocusMode(focusMode);
    ExposureHintMode exposureHintModes = static_cast<ExposureHintMode>(GetData<int32_t>() % NUM_THREE);
    vector<ExposureHintMode> supportedExposureHintModes;
    fuzz_->GetSupportedExposureHintModes(supportedExposureHintModes);
    fuzz_->SetExposureHintMode(exposureHintModes);
    fuzz_->GetExposureHintMode(exposureHintModes);
    FocusAssistFlashMode focusAssistFlashModes = static_cast<FocusAssistFlashMode>(GetData<int32_t>() % NUM_FOUR);
    vector<FocusAssistFlashMode> supportedFocusAssistFlashModes;
    fuzz_->GetSupportedFocusAssistFlashModes(supportedFocusAssistFlashModes);
    fuzz_->IsFocusAssistFlashModeSupported(focusAssistFlashModes, isSupported);
    fuzz_->SetFocusAssistFlashMode(focusAssistFlashModes);
    fuzz_->GetFocusAssistFlashMode(focusAssistFlashModes);
}

void Test()
{
    auto professionSession = std::make_unique<ProfessionSessionFuzzer>();
    if (professionSession == nullptr) {
        MEDIA_INFO_LOG("professionSession is null");
        return;
    }
    CHECK_RETURN_ELOG(!TestToken::GetAllCameraPermission(), "GetPermission error");
    manager_ = CameraManager::GetInstance();
    sptr<CaptureSessionForSys> captureSessionForSys =
        CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::PROFESSIONAL_VIDEO);
    ProfessionSessionFuzzer::fuzz_ = static_cast<ProfessionSession*>(captureSessionForSys.GetRefPtr());
    CHECK_RETURN_ELOG(!ProfessionSessionFuzzer::fuzz_, "Create fuzz_ Error");
    SceneMode sceneMode = SceneMode::PROFESSIONAL_VIDEO;
    std::vector<sptr<CameraDevice>> cameras;
    cameras = manager_->GetSupportedCameras();
    CHECK_RETURN_ELOG(cameras.empty(), "GetCameraDeviceListFromServer Error");
    sptr<CaptureInput> input = manager_->CreateCameraInput(cameras[0]);
    CHECK_RETURN_ELOG(!input, "CreateCameraInput Error");
    sptr<CameraOutputCapability> modeAbility =
        manager_->GetSupportedOutputCapability(cameras[0], sceneMode);
    captureSessionForSys->BeginConfig();
    captureSessionForSys->AddInput(input);
    input->Open();
    Profile previewProfile;
    VideoProfile videoProfile;
    auto previewProfiles = modeAbility->GetPreviewProfiles();
    auto videoProfiles = modeAbility->GetVideoProfiles();
    for (const auto &vProfile : videoProfiles) {
        for (const auto &pProfile : previewProfiles) {
            if (vProfile.size_.width == pProfile.size_.width) {
                previewProfile = pProfile;
                videoProfile = vProfile;
                break;
            }
        }
    }
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput(previewProfile);
    captureSessionForSys->AddOutput(previewOutput);
    sptr<CaptureOutput> videoOutput = CreateVideoOutput(videoProfile);
    captureSessionForSys->AddOutput(videoOutput);
    captureSessionForSys->CommitConfig();
    professionSession->ProfessionSessionFuzzTest1();
    professionSession->ProfessionSessionFuzzTest2();
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