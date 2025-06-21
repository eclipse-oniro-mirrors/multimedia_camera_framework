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
#include <fuzzer/FuzzedDataProvider.h>
#include "test_token.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 4;
static constexpr int32_t PORTRAIT_SIZE = 6;
sptr<CameraManager> cameraManager_ = nullptr;
std::vector<Profile> previewProfile_ = {};
std::vector<Profile> photoProfile_ = {};
bool g_preIsSupportedPortraitmode = false;
bool g_phoIsSupportedPortraitmode = false;

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

void PortraitSessionFuzzer::PortraitSessionFuzzTest(FuzzedDataProvider& fdp)
{
    cameraManager_ = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetCameraDeviceListFromServer();
    CHECK_ERROR_RETURN_LOG(cameras.empty(), "PortraitSessionFuzzer: GetCameraDeviceListFromServer Error");
    sptr<CaptureInput> input = cameraManager_->CreateCameraInput(cameras[0]);
    CHECK_ERROR_RETURN_LOG(!input, "CreateCameraInput Error");
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
    uint8_t portraitEnum = fdp.ConsumeIntegral<uint8_t>() % PORTRAIT_SIZE;
    if (!portraitEffect.empty()) {
        portraitSession->SetPortraitEffect(portraitEffect[portraitEnum]);
    }
    portraitSession->CanAddOutput(photo);
    portraitSession->UnlockForControl();
}

void Test(uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    CHECK_ERROR_RETURN_LOG(!TestToken::GetAllCameraPermission(), "GetPermission error");
    auto portraitSession = std::make_unique<PortraitSessionFuzzer>();
    if (portraitSession == nullptr) {
        MEDIA_INFO_LOG("portraitSession is null");
        return;
    }
    portraitSession->PortraitSessionFuzzTest(fdp);
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    OHOS::CameraStandard::Test(data, size);
    return 0;
}