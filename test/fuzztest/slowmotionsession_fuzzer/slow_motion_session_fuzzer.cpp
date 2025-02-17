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

#include "slow_motion_session_fuzzer.h"
#include "camera_log.h"
#include "camera_output_capability.h"
#include "input/camera_manager.h"
#include "message_parcel.h"
#include "time_lapse_photo_session.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "securec.h"
#include "ipc_skeleton.h"
#include "os_account_manager.h"


namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
const int32_t DEFAULT_ITEMS = 10;
const int32_t DEFAULT_DATA_LENGTH = 100;
static size_t g_dataSize = 0;
static size_t g_pos;
sptr<CameraManager> manager;
std::vector<Profile> previewProfile_ = {};
std::vector<VideoProfile> videoProfile_;

void GetPermission()
{
    uint64_t tokenId;
    const char *perms[2];
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

sptr<CaptureOutput> CreatePreviewOutput()
{
    previewProfile_ = {};
    std::vector<sptr<CameraDevice>> cameras = manager->GetCameraDeviceListFromServer();
    auto outputCapability = manager->GetSupportedOutputCapability(cameras[0],
        static_cast<int32_t>(SceneMode::SLOW_MOTION));
    previewProfile_ = outputCapability->GetPreviewProfiles();
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    if (surface == nullptr) {
        return nullptr;
    }
    return manager->CreatePreviewOutput(previewProfile_[0], surface);
}

sptr<CaptureOutput> CreateVideoOutput()
{
    videoProfile_ = {};
    std::vector<sptr<CameraDevice>> cameras = manager->GetCameraDeviceListFromServer();
    auto outputCapability = manager->GetSupportedOutputCapability(cameras[0],
        static_cast<int32_t>(SceneMode::SLOW_MOTION));
    videoProfile_ = outputCapability->GetVideoProfiles();
    sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
    if (surface == nullptr) {
        return nullptr;
    }
    return manager->CreateVideoOutput(videoProfile_[0], surface);
}

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

void SlowMotionSessionFuzzer::SlowMotionSessionFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    GetPermission();
    manager = CameraManager::GetInstance();
    sptr<CaptureSession> captureSession = manager->CreateCaptureSession(SceneMode::SLOW_MOTION);
    std::vector<sptr<CameraDevice>> cameras_;

    cameras_ = manager->GetCameraDeviceListFromServer();
    sptr<CaptureInput> input = manager->CreateCameraInput(cameras_[0]);
    input->Open();

    sptr<CaptureOutput> videoOutput = CreateVideoOutput();
    sptr<CaptureOutput> previewOutput = CreatePreviewOutput();

    captureSession->BeginConfig();
    captureSession->AddInput(input);

    sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(SceneMode::SLOW_MOTION), previewProfile_);
    info->modeVideoProfiles_.emplace(static_cast<int32_t>(SceneMode::SLOW_MOTION), videoProfile_);

    captureSession->AddOutput(previewOutput);
    captureSession->AddOutput(videoOutput);
    captureSession->CommitConfig();
    input->Release();

    sptr<SlowMotionSession> fuzz_ = static_cast<SlowMotionSession*>(captureSession.GetRefPtr());
    if (fuzz_ == nullptr) {
        return;
    }
    fuzz_->IsSlowMotionDetectionSupported();
    Rect rect = {0, 0, 0, 0};
    fuzz_->NormalizeRect(rect);
    fuzz_->SetSlowMotionDetectionArea(rect);
    std::shared_ptr<OHOS::Camera::CameraMetadata> result =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    SlowMotionSession::SlowMotionSessionMetadataResultProcessor processor(fuzz_);
    uint64_t timestamp = 1;
    auto metadata = make_shared<OHOS::Camera::CameraMetadata>(10, 100);
    processor.ProcessCallbacks(timestamp, metadata);
    std::shared_ptr<SlowMotionStateCallback> callback = std::make_shared<TestSlowMotionStateCallback>();
    fuzz_->SetCallback(callback);
    fuzz_->OnSlowMotionStateChange(metadata);
    fuzz_->GetApplicationCallback();
    bool isEnable = GetData<bool>();
    fuzz_->LockForControl();
    fuzz_->EnableMotionDetection(isEnable);
}

void Test()
{
    auto slowMotionSession = std::make_unique<SlowMotionSessionFuzzer>();
    if (slowMotionSession == nullptr) {
        MEDIA_INFO_LOG("slowMotionSession is null");
        return;
    }
    slowMotionSession->SlowMotionSessionFuzzTest();
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