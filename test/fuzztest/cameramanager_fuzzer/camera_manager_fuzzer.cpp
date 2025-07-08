/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "camera_manager_fuzzer.h"
#include "camera_manager.h"
#include "camera_manager_for_sys.h"
#include "camera_log.h"
#include "input/camera_device.h"
#include "message_parcel.h"
#include <cstddef>
#include <cstdint>
#include <mutex>
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "securec.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace CameraStandard {
static constexpr int32_t MIN_SIZE_NUM = 24;
const size_t THRESHOLD = 10;
sptr<CameraManager> manager = nullptr;
const int32_t NUM_10 = 10;
const int32_t NUM_100 = 100;
std::shared_ptr<IDeferredPhotoProcSessionCallbackFuzz> photoSessionCallback_ =
    std::make_shared<IDeferredPhotoProcSessionCallbackFuzz>();
std::shared_ptr<IDeferredVideoProcSessionCallbackFuzz> videoSessionCallback_ =
    std::make_shared<IDeferredVideoProcSessionCallbackFuzz>();
std::shared_ptr<CameraManagerCallbackFuzz> managerCallback_ = std::make_shared<CameraManagerCallbackFuzz>();
std::shared_ptr<CameraMuteListenerFuzz> muteListenerCallback_ = std::make_shared<CameraMuteListenerFuzz>();
std::shared_ptr<FoldListenerFuzz> foldListenerCallback_ = std::make_shared<FoldListenerFuzz>();
std::shared_ptr<TorchListenerFuzz> torchListenerCallback_ = std::make_shared<TorchListenerFuzz>();

void CameraManagerFuzzer::CameraManagerFuzzTest1(FuzzedDataProvider& fdp)
{
    manager = CameraManager::GetInstance();
    CHECK_RETURN_ELOG(!manager, "GetInstance Error");
    auto session = manager->CreateCaptureSession();
    manager->CreateCaptureSession(&session);
    int userId = fdp.ConsumeIntegral<int>();
    auto deferedPhotoSession = manager->CreateDeferredPhotoProcessingSession(userId, photoSessionCallback_);
    manager->CreateDeferredPhotoProcessingSession(userId, photoSessionCallback_, &deferedPhotoSession);
    auto deferedVideoSession = manager->CreateDeferredVideoProcessingSession(userId, videoSessionCallback_);
    manager->CreateDeferredVideoProcessingSession(userId, videoSessionCallback_, &deferedVideoSession);
    sptr<IBufferProducer> bufferProducer;
    auto photoOutput = manager->CreatePhotoOutput(bufferProducer);
    manager->CreatePhotoOutputWithoutProfile(bufferProducer, &photoOutput);
    sptr<Surface> surface;
    sptr<PreviewOutput> previewOutput;
    manager->CreatePreviewOutputWithoutProfile(surface, &previewOutput);
    sptr<IStreamRepeat> streamPtr;
    Profile profile;
    manager->CreatePreviewOutputStream(streamPtr, profile, bufferProducer);
    sptr<IStreamCapture> capture;
    manager->ValidCreateOutputStream(profile, bufferProducer);
    manager->CreatePreviewOutput(bufferProducer,  fdp.ConsumeIntegral<int32_t>());
    int32_t width = fdp.ConsumeIntegral<int32_t>();
    int32_t height = fdp.ConsumeIntegral<int32_t>();
    manager->CreateCustomPreviewOutput(surface, width, height);
    sptr<MetadataOutput> metadataOutput;
    std::vector<MetadataObjectType> metadataObjectTypes;
    manager->CreateMetadataOutput(metadataOutput, metadataObjectTypes);
    DepthProfile depthProfile;
    sptr<CameraManagerForSys> managerForSys = CameraManagerForSys::GetInstance();
    sptr<DepthDataOutput> depthDataOutput = nullptr;
    managerForSys->CreateDepthDataOutput(depthProfile, bufferProducer, &depthDataOutput);
    manager->CreateVideoOutput(surface);
    manager->CreateVideoOutputStream(streamPtr, profile, bufferProducer);
    sptr<VideoOutput> videoOutput;
    manager->CreateVideoOutputWithoutProfile(surface, &videoOutput);
    manager->DestroyStubObj();
    manager->CameraServerDied(0);
    manager->SetCallback(managerCallback_);
    manager->RegisterCameraMuteListener(muteListenerCallback_);
    manager->RegisterTorchListener(torchListenerCallback_);
    manager->RegisterFoldListener(foldListenerCallback_);
}

void CameraManagerFuzzer::CameraManagerFuzzTest2(FuzzedDataProvider& fdp)
{
    manager = CameraManager::GetInstance();
    CHECK_RETURN_ELOG(!manager, "GetInstance Error");
    std::string cameraId;
    manager->GetCameraDeviceFromId(cameraId);
    manager->GetCameras();
    int32_t testPid = fdp.ConsumeIntegral<int32_t>();
    int32_t status =  fdp.ConsumeIntegral<int32_t>();
    manager->GetCameraOutputStatus(testPid, status);
    manager->foldScreenType_ = "test_type";
    manager->GetSupportedCameras();
    sptr<CameraInfo> info;
    manager->CreateCameraInput(info);
    manager->ReportEvent(cameraId);
    CameraPosition position = CameraPosition::CAMERA_POSITION_BACK;
    CameraType cameraType = CameraType::CAMERA_TYPE_DEFAULT;
    auto input = manager->CreateCameraInput(position, cameraType);
    manager->CreateCameraInput(position, cameraType, &input);
    CameraManager::ProfilesWrapper profilesWrapper = {};
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(NUM_10, NUM_100);
    camera_metadata_item_t item;
    manager->ParseBasicCapability(profilesWrapper, metadata, item);
    int32_t modeName = SceneMode::VIDEO;
    manager->ParseExtendCapability(profilesWrapper, modeName, item);
    modeName = SceneMode::NORMAL;
    manager->ParseExtendCapability(profilesWrapper, modeName, item);
    sptr<ICameraServiceCallback> cameraServiceCallback;
    manager->SetCameraServiceCallback(cameraServiceCallback);
    CameraFormat cameraFormat = CameraFormat::CAMERA_FORMAT_JPEG;
    manager->GetCameraMetadataFormat(cameraFormat);
}

void CameraManagerFuzzer::CameraManagerFuzzTest3(FuzzedDataProvider& fdp)
{
    manager = CameraManager::GetInstance();
    CHECK_RETURN_ELOG(!manager, "GetInstance Error");
    ITorchServiceCallbackFuzz torchServiceCallback;
    TorchStatus torchStatus = TorchStatus::TORCH_STATUS_ON;
    torchServiceCallback.OnTorchStatusChange(torchStatus);
    IFoldServiceCallbackFuzz foldServiceCallback;
    FoldStatus foldStatus = FoldStatus::EXPAND;
    foldServiceCallback.OnFoldStatusChanged(foldStatus);
    sptr<ITorchServiceCallback> torchCallback = new ITorchServiceCallbackFuzz();
    manager->SetTorchServiceCallback(torchCallback);
    sptr<IFoldServiceCallback> serviceCallback = new IFoldServiceCallbackFuzz();
    manager->SetFoldServiceCallback(serviceCallback);
    ICameraMuteServiceCallbackFuzz cameraMuteServiceCallback;
    cameraMuteServiceCallback.OnCameraMute(fdp.ConsumeBool());
    manager->IsCameraMuteSupported();
    manager->IsCameraMuted();
    manager->PrelaunchCamera(0);
    manager->ResetRssPriority();
    manager->IsTorchSupported();
    TorchMode mode = TorchMode::TORCH_MODE_ON;
    manager->SetTorchMode(mode);
    mode = TorchMode::TORCH_MODE_OFF;
    manager->SetTorchMode(mode);
    mode = TorchMode::TORCH_MODE_AUTO;
    manager->SetTorchMode(mode);
    manager->UpdateTorchMode(mode);
    manager->GetTorchMode();
    manager->SetCameraManagerNull();
}

void Test(uint8_t* data, size_t size)
{
    auto cameraManager = std::make_unique<CameraManagerFuzzer>();
    if (cameraManager == nullptr) {
        MEDIA_INFO_LOG("cameraManager is null");
        return;
    }
    FuzzedDataProvider fdp(data, size);
    if (fdp.remaining_bytes() < MIN_SIZE_NUM) {
        return;
    }
    cameraManager->CameraManagerFuzzTest1(fdp);
    cameraManager->CameraManagerFuzzTest2(fdp);
    cameraManager->CameraManagerFuzzTest3(fdp);
}
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < OHOS::CameraStandard::THRESHOLD) {
        return 0;
    }

    OHOS::CameraStandard::Test(data, size);
    return 0;
}