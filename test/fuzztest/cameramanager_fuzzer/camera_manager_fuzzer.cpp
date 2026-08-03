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
std::shared_ptr<CameraSpectrumInfoListenerFuzz> spectrumListener_ =
    std::make_shared<CameraSpectrumInfoListenerFuzz>();

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
    torchServiceCallback.OnTorchStatusChange(torchStatus, 1);
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
    manager->PrelaunchCamera();
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
    int32_t maxLength = 30;
    std::string bundleName = fdp.ConsumeRandomLengthString().substr(0, maxLength);
    std::string pageName = fdp.ConsumeRandomLengthString().substr(0, maxLength);
    int32_t preScanMode = fdp.ConsumeIntegralInRange<int32_t>(0, 2);
    manager->PrelaunchScanCamera(bundleName, pageName,
        static_cast<PrelaunchScanModeOhos>(preScanMode));
}

static CameraFormat FuzzPickFormat(FuzzedDataProvider& fdp)
{
    if (fdp.ConsumeBool()) {
        return CAMERA_FORMAT_INVALID;
    }
    static const CameraFormat formats[] = {
        CAMERA_FORMAT_YCBCR_420_888,
        CAMERA_FORMAT_RGBA_8888,
        CAMERA_FORMAT_DNG,
        CAMERA_FORMAT_DNG_XDRAW,
        CAMERA_FORMAT_YUV_420_SP,
        CAMERA_FORMAT_NV12,
        CAMERA_FORMAT_YUV_422_YUYV,
        CAMERA_FORMAT_JPEG,
        CAMERA_FORMAT_YCBCR_P010,
        CAMERA_FORMAT_YCRCB_P010,
        CAMERA_FORMAT_HEIC,
    };
    int32_t idx = fdp.ConsumeIntegralInRange<int32_t>(0, sizeof(formats) / sizeof(formats[0]) - 1);
    return formats[idx];
}

static Size FuzzPickSize(FuzzedDataProvider& fdp)
{
    Size size;
    size.width = fdp.ConsumeIntegralInRange<uint32_t>(0, 4096);
    size.height = fdp.ConsumeIntegralInRange<uint32_t>(0, 4096);
    return size;
}

static std::vector<int32_t> FuzzPickFrameRates(FuzzedDataProvider& fdp)
{
    std::vector<int32_t> rates;
    uint32_t cnt = fdp.ConsumeIntegralInRange<uint32_t>(0, 4);
    for (uint32_t i = 0; i < cnt; i++) {
        rates.push_back(fdp.ConsumeIntegral<int32_t>());
    }
    return rates;
}

static DepthDataAccuracy FuzzPickDepthAccuracy(FuzzedDataProvider& fdp)
{
    int32_t idx = fdp.ConsumeIntegralInRange<int32_t>(0, 2);
    switch (idx) {
        case 0:
            return DEPTH_DATA_ACCURACY_INVALID;
        case 1:
            return DEPTH_DATA_ACCURACY_RELATIVE;
        default:
            return DEPTH_DATA_ACCURACY_ABSOLUTE;
    }
}

void CameraManagerFuzzer::CameraManagerFuzzTest4(FuzzedDataProvider& fdp)
{
    manager = CameraManager::GetInstance();
    CHECK_RETURN_ELOG(!manager, "GetInstance Error");

    {
        Profile profile(FuzzPickFormat(fdp), FuzzPickSize(fdp));
        sptr<PhotoOutput> photoOutput;
        manager->CreatePhotoOutput(profile, &photoOutput);
    }
    {
        Profile profile(FuzzPickFormat(fdp), FuzzPickSize(fdp));
        sptr<IBufferProducer> producer;
        sptr<PhotoOutput> photoOutput;
        manager->CreatePhotoOutput(profile, producer, &photoOutput);
    }
    {
        Profile profile(FuzzPickFormat(fdp), FuzzPickSize(fdp));
        sptr<Surface> surface;
        sptr<PreviewOutput> previewOutput;
        manager->CreatePreviewOutput(profile, surface, &previewOutput);
    }
    {
        VideoProfile vProfile(FuzzPickFormat(fdp), FuzzPickSize(fdp), FuzzPickFrameRates(fdp));
        sptr<Surface> surface;
        sptr<VideoOutput> videoOutput;
        manager->CreateVideoOutput(vProfile, surface, &videoOutput);
    }
    {
        VideoProfile vProfile(FuzzPickFormat(fdp), FuzzPickSize(fdp), FuzzPickFrameRates(fdp));
        sptr<MovieFileOutput> movieFileOutput;
        manager->CreateMovieFileOutput(vProfile, &movieFileOutput);
    }
    {
        VideoProfile vProfile(FuzzPickFormat(fdp), FuzzPickSize(fdp), FuzzPickFrameRates(fdp));
        sptr<UnifyMovieFileOutput> unifyMovieFileOutput;
        manager->CreateMovieFileOutput(vProfile, &unifyMovieFileOutput);
    }
    {
        DepthProfile depthProfile(FuzzPickFormat(fdp), FuzzPickDepthAccuracy(fdp), FuzzPickSize(fdp));
        sptr<IBufferProducer> producer;
        sptr<IStreamDepthData> streamDepthData;
        manager->GetStreamDepthDataFromService(depthProfile, producer, streamDepthData);
    }
    {
        Profile profile(FuzzPickFormat(fdp), FuzzPickSize(fdp));
        sptr<PreviewOutput> previewOutput;
        manager->CreateDeferredPreviewOutput(profile, &previewOutput);
    }

    std::vector<sptr<CameraDevice>> cameras = manager->GetSupportedCameras();
    sptr<CameraDevice> camera = cameras.empty() ? nullptr : cameras[0];
    bool useNullCamera = fdp.ConsumeBool();
    sptr<CameraDevice> cameraArg = useNullCamera ? nullptr : camera;
    int32_t mode = fdp.ConsumeIntegralInRange<int32_t>(0, 24);
    bool completeRemove = fdp.ConsumeBool();
    manager->GetSupportedOutputCapability(cameraArg, mode, completeRemove);
    manager->GetSupportedFullOutputCapability(cameraArg, mode);
    manager->GetSupportedModes(cameraArg);
    std::vector<sptr<CameraDevice>> camArray;
    if (cameraArg != nullptr) {
        camArray.push_back(cameraArg);
    }
    manager->CheckConcurrentExecution(camArray);
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    sptr<MechSession> mechSession;
    manager->CreateMechSession(userId, &mechSession);
    manager->IsMechSupported();
    sptr<CameraSwitchSession> switchSession;
    manager->CreateCameraSwitchSession(&switchSession);
    auto switchSessionDirect = manager->CreateCameraSwitchSession();
    (void)switchSessionDirect;
    bool useNullInput = fdp.ConsumeBool();
    sptr<CameraDevice> inputCamera = useNullInput ? nullptr : camera;
    sptr<CameraInput> cameraInput;
    manager->CreateCameraInput(inputCamera, &cameraInput);

    std::string prelaunchCameraId = fdp.ConsumeRandomLengthString(30);
    int32_t restoreIdx = fdp.ConsumeIntegralInRange<int32_t>(0, 2);
    RestoreParamTypeOhos restoreType = static_cast<RestoreParamTypeOhos>(restoreIdx);
    int32_t activeTime = fdp.ConsumeIntegral<int32_t>();
    EffectParam effectParam;
    effectParam.skinSmoothLevel = fdp.ConsumeIntegral<int32_t>();
    effectParam.faceSlender = fdp.ConsumeIntegral<int32_t>();
    effectParam.skinTone = fdp.ConsumeIntegral<int32_t>();
    effectParam.skinToneBright = fdp.ConsumeIntegral<int32_t>();
    effectParam.eyeBigEyes = fdp.ConsumeIntegral<int32_t>();
    effectParam.hairHairline = fdp.ConsumeIntegral<int32_t>();
    effectParam.faceMakeUp = fdp.ConsumeIntegral<int32_t>();
    effectParam.headShrink = fdp.ConsumeIntegral<int32_t>();
    effectParam.noseSlender = fdp.ConsumeIntegral<int32_t>();
    manager->SetPrelaunchConfig(prelaunchCameraId, restoreType, activeTime, effectParam);
    int32_t policyIdx = fdp.ConsumeIntegralInRange<int32_t>(0, 1);
    PolicyType policyType = static_cast<PolicyType>(policyIdx);
    bool muteMode = fdp.ConsumeBool();
    manager->MuteCameraPersist(policyType, muteMode);
    std::string switchId = fdp.ConsumeRandomLengthString(30);
    manager->PreSwitchCamera(switchId);
    int32_t torchIdx = fdp.ConsumeIntegralInRange<int32_t>(0, 2);
    TorchMode torchMode = static_cast<TorchMode>(torchIdx);
    float level = fdp.ConsumeFloatingPointInRange<float>(0.0f, 1.0f);
    manager->SetTorchModeOnWithLevel(torchMode, level);
    manager->IsTorchModeSupported(torchMode);
    manager->IsTorchLevelControlSupported();
    SpectrumCallerInfo info;
    info.cameraId = fdp.ConsumeRandomLengthString(30);
    info.userId = fdp.ConsumeIntegral<int32_t>();
    manager->RegisterSpectrumListener(info, spectrumListener_);
    manager->UnregisterSpectrumListener(info, spectrumListener_);
    std::string reason = fdp.ConsumeRandomLengthString(30);
    int32_t memSize = fdp.ConsumeIntegral<int32_t>();
    manager->RequireMemorySize(memSize);
    int64_t storage = 0;
    manager->GetCameraStorageSize(storage);
    sptr<ControlCenterSession> ccSession;
    manager->CreateControlCenterSession(ccSession);
    manager->IsControlCenterActive();
    bool frameCondition = fdp.ConsumeBool();
    manager->SetControlCenterFrameCondition(frameCondition);
    manager->GetControlCenterPrecondition();
}

void Test(uint8_t* data, size_t size)
{
    auto cameraManager = std::make_unique<CameraStandard::CameraManagerFuzzer>();
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