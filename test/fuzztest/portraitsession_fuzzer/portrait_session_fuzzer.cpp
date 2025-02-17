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

#include "portrait_session_fuzzer.h"
#include "access_token.h"
#include "camera_log.h"
#include "camera_output_capability.h"
#include "input/camera_manager.h"
#include "message_parcel.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "securec.h"
#include "ipc_skeleton.h"
#include <cstdint>
#include <vector>
#include "camera_util.h"
#include "hap_token_info.h"
#include "metadata_utils.h"
#include "surface.h"
#include "os_account_manager.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MAX_CODE_LEN  = 512;
static constexpr int32_t MIN_SIZE_NUM = 4;
static const uint8_t* RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;
sptr<CameraManager> cameraManager_ = nullptr;
std::vector<Profile> previewProfile_ = {};
std::vector<Profile> photoProfile_ = {};
bool g_preIsSupportedPortraitmode = false;
bool g_phoIsSupportedPortraitmode = false;

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

sptr<CaptureOutput> CreatePreviewOutput()
{
    previewProfile_ = {};
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    if (!cameraManager_ || cameras.empty()) {
        return nullptr;
    }
    g_preIsSupportedPortraitmode = false;
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::PORTRAIT) != modes.end()) {
            g_preIsSupportedPortraitmode = true;
        }

        if (!g_preIsSupportedPortraitmode) {
            continue;
        }

        auto outputCapability = cameraManager_->GetSupportedOutputCapability(camDevice, static_cast<int32_t>(PORTRAIT));
        if (!outputCapability) {
            return nullptr;
        }

        previewProfile_ = outputCapability->GetPreviewProfiles();
        if (previewProfile_.empty()) {
            return nullptr;
        }

        sptr<Surface> surface = Surface::CreateSurfaceAsConsumer();
        if (surface == nullptr) {
            return nullptr;
        }
        return cameraManager_->CreatePreviewOutput(previewProfile_[0], surface);
    }
    return nullptr;
}

sptr<CaptureOutput> CreatePhotoOutput()
{
    photoProfile_ = {};
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    if (!cameraManager_ || cameras.empty()) {
        return nullptr;
    }
    g_phoIsSupportedPortraitmode = false;
    for (sptr<CameraDevice> camDevice : cameras) {
        std::vector<SceneMode> modes = cameraManager_->GetSupportedModes(camDevice);
        if (find(modes.begin(), modes.end(), SceneMode::PORTRAIT) != modes.end()) {
            g_phoIsSupportedPortraitmode = true;
        }

        if (!g_phoIsSupportedPortraitmode) {
            continue;
        }

        auto outputCapability = cameraManager_->GetSupportedOutputCapability(camDevice, static_cast<int32_t>(PORTRAIT));
        if (!outputCapability) {
            return nullptr;
        }

        photoProfile_ = outputCapability->GetPhotoProfiles();
        if (photoProfile_.empty()) {
            return nullptr;
        }

        sptr<IConsumerSurface> surface = IConsumerSurface::Create();
        if (surface == nullptr) {
            return nullptr;
        }
        sptr<IBufferProducer> surfaceProducer = surface->GetProducer();
        return cameraManager_->CreatePhotoOutput(photoProfile_[0], surfaceProducer);
    }
    return nullptr;
}

void NativeAuthorization()
{
    const char *perms[2];
    uint64_t tokenId = 0;
    int32_t uid = 0;
    int32_t userId = 0;
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
    uid = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    MEDIA_DEBUG_LOG("CameraPortraitSessionUnitTest::NativeAuthorization TearDown");
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

void PortraitSessionFuzzer::PortraitSessionFuzzTest()
{
    if ((RAW_DATA == nullptr) || (g_dataSize > MAX_CODE_LEN) || (g_dataSize < MIN_SIZE_NUM)) {
        return;
    }
    NativeAuthorization();
    cameraManager_ = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    sptr<CameraInput> camInput = (sptr<CameraInput> &)input;
    std::string cameraSettings = camInput->GetCameraSettings();
    camInput->SetCameraSettings(cameraSettings);
    camInput->GetCameraDevice()->Open();
    sptr<CaptureOutput> preview = CreatePreviewOutput();
    sptr<CaptureOutput> photo = CreatePhotoOutput();
    sptr<CaptureSession> captureSession = cameraManager_->CreateCaptureSession(SceneMode::PORTRAIT);
    sptr<PortraitSession> portraitSession = nullptr;
    portraitSession = static_cast<PortraitSession *> (captureSession.GetRefPtr());
    portraitSession->BeginConfig();
    portraitSession->AddInput(input);
    sptr<CameraDevice> info = captureSession->innerInputDevice_->GetCameraDeviceInfo();
    info->modePreviewProfiles_.emplace(static_cast<int32_t>(PORTRAIT), previewProfile_);
    info->modePhotoProfiles_.emplace(static_cast<int32_t>(PORTRAIT), photoProfile_);
    portraitSession->AddOutput(preview);
    portraitSession->AddOutput(photo);
    portraitSession->CommitConfig();
    portraitSession->LockForControl();
    auto portraitEffect = portraitSession->GetSupportedPortraitEffects();
    portraitSession->GetPortraitEffect();
    if (!portraitEffect.empty()) {
        portraitSession->SetPortraitEffect(portraitEffect[0]);
    }
    portraitSession->CanAddOutput(photo);
    portraitSession->UnlockForControl();
}

void Test()
{
    auto portraitSession = std::make_unique<PortraitSessionFuzzer>();
    if (portraitSession == nullptr) {
        MEDIA_INFO_LOG("portraitSession is null");
        return;
    }
    // std::cout << "aning PortraitSessionFuzzTest" << std::endl;
    portraitSession->PortraitSessionFuzzTest();
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