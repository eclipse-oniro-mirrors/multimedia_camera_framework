/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#include "hcamera_service_fuzzer.h"
#include "sys_binder.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <string>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_dynamic_loader.h"
#include "camera_log.h"
#include "camera_xcollie.h"
#include "hap_token_info.h"
#include "hcamera_service.h"
#include "input/camera_manager.h"
#include "camera_listener_manager.h"
#include "camera_service_proxy.h"
#include "control_center_status_callback_stub.h"
#include "ipc_object_stub.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "camera_device_service_stub.h"
#include "camera_multi_stream_output_stub.h"
#include "icamera_service.h"
#include "icamera_device_service.h"
#include "icamera_mute_service_callback.h"
#include "icapture_session.h"
#include "ifold_service_callback.h"
#include "itorch_service_callback.h"
#include "icamera_service_callback.h"
#include "istream_capture.h"
#include "istream_repeat.h"
#include "istream_metadata.h"
#include "istream_depth_data.h"
#include "imech_session.h"
#include "ibuffer_producer.h"
#include "icamera_broker.h"
#include "camera_types.h"
#include "camera_metadata_info.h"
#include "camera_metadata.h"
#include "ideferred_photo_processing_session.h"
#include "ideferred_video_processing_session.h"
#include "ideferred_video_processing_session_callback.h"
#include "ideferred_photo_processing_session_callback.h"
#include "test_token.h"
#include "fuzz_util.h"

using namespace OHOS;
using namespace OHOS::Camera;
using namespace OHOS::CameraStandard;
using namespace OHOS::CameraStandard::DeferredProcessing;
sptr<HCameraHostManager> g_hCameraHostManager = nullptr;
sptr<HCameraService> g_hCameraService = nullptr;

sptr<IBufferProducer> GetMockBufferProducer()
{
    sptr<IConsumerSurface> surface = IConsumerSurface::Create();
    if (!surface) {
        return nullptr;
    }
    return surface->GetProducer();
}

static std::vector<int32_t> ConsumeIntList(FuzzedDataProvider& provider)
{
    size_t len = provider.ConsumeIntegralInRange<size_t>(0, 8);
    std::vector<int32_t> vec;
    for (size_t i = 0; i < len; ++i) {
        vec.push_back(provider.ConsumeIntegral<int32_t>());
    }
    return vec;
}

void CreateCameraDevice(FuzzedDataProvider& provider)
{
    std::string cameraId = provider.ConsumeRandomLengthString();
    sptr<ICameraDeviceService> device;
    g_hCameraService->CreateCameraDevice(cameraId, device);
}

void SetCameraCallback(FuzzedDataProvider& provider)
{
    auto cb = sptr<MockCameraServiceCallback>::MakeSptr();
    g_hCameraService->SetCameraCallback(cb, true);
}

void SetMuteCallback(FuzzedDataProvider& provider)
{
    auto cb = sptr<MockCameraMuteServiceCallback>::MakeSptr();
    g_hCameraService->SetMuteCallback(cb);
}

void SetTorchCallback(FuzzedDataProvider& provider)
{
    auto cb = sptr<MockTorchServiceCallback>::MakeSptr();
    g_hCameraService->SetTorchCallback(cb);
}

void GetCameras(FuzzedDataProvider& provider)
{
    std::vector<std::string> cameraIds;
    std::vector<std::shared_ptr<CameraMetadata>> cameraAbilityList;
    g_hCameraService->GetCameras(cameraIds, cameraAbilityList);
}

void CreateCaptureSession(FuzzedDataProvider& provider)
{
    sptr<ICaptureSession> session;
    int32_t operationMode = provider.ConsumeIntegral<int32_t>();
    g_hCameraService->CreateCaptureSession(session, operationMode);
}

void CreatePhotoOutput(FuzzedDataProvider& provider)
{
    sptr<IBufferProducer> producer = GetMockBufferProducer();
    int32_t format = provider.ConsumeIntegral<int32_t>();
    int32_t width = provider.ConsumeIntegral<int32_t>();
    int32_t height = provider.ConsumeIntegral<int32_t>();
    sptr<IStreamCapture> photoOutput;
    g_hCameraService->CreatePhotoOutput(producer, format, width, height, photoOutput);
}

void CreateDeferredPreviewOutput(FuzzedDataProvider& provider)
{
    int32_t format = provider.ConsumeIntegral<int32_t>();
    int32_t width = provider.ConsumeIntegral<int32_t>();
    int32_t height = provider.ConsumeIntegral<int32_t>();
    sptr<IStreamRepeat> previewOutput;
    g_hCameraService->CreateDeferredPreviewOutput(format, width, height, previewOutput);
}

void CreateVideoOutput(FuzzedDataProvider& provider)
{
    sptr<IBufferProducer> producer = GetMockBufferProducer();
    int32_t format = provider.ConsumeIntegral<int32_t>();
    int32_t width = provider.ConsumeIntegral<int32_t>();
    int32_t height = provider.ConsumeIntegral<int32_t>();
    sptr<IStreamRepeat> videoOutput;
    g_hCameraService->CreateVideoOutput(producer, format, width, height, videoOutput);
}

void SetListenerObject(FuzzedDataProvider& provider)
{
    auto remote = sptr<MockIRemoteObject>::MakeSptr();
    g_hCameraService->SetListenerObject(remote);
}

void CreateMetadataOutput(FuzzedDataProvider& provider)
{
    sptr<IBufferProducer> producer = GetMockBufferProducer();
    int32_t format = provider.ConsumeIntegral<int32_t>();
    std::vector<int32_t> metadataTypes = ConsumeIntList(provider);
    sptr<IStreamMetadata> metadataOutput;
    g_hCameraService->CreateMetadataOutput(producer, format, metadataTypes, metadataOutput);
}

void MuteCamera(FuzzedDataProvider& provider)
{
    bool muteMode = provider.ConsumeBool();
    g_hCameraService->MuteCamera(muteMode);
}

void IsCameraMuted(FuzzedDataProvider& provider)
{
    bool muteMode;
    g_hCameraService->IsCameraMuted(muteMode);
}

void IsTorchSupported(FuzzedDataProvider& provider)
{
    bool isTorchSupported;
    g_hCameraService->IsTorchSupported(isTorchSupported);
}

void IsCameraMuteSupported(FuzzedDataProvider& provider)
{
    bool isCameraMuteSupported;
    g_hCameraService->IsCameraMuteSupported(isCameraMuteSupported);
}

void PrelaunchCamera(FuzzedDataProvider& provider)
{
    int32_t flag = provider.ConsumeIntegral<int32_t>();
    g_hCameraService->PrelaunchCamera(flag);
}

void ResetRssPriority(FuzzedDataProvider& provider)
{
    g_hCameraService->ResetRssPriority();
}

void SetPrelaunchConfig(FuzzedDataProvider& provider)
{
    std::string cameraId = provider.ConsumeRandomLengthString();

    int32_t restoreParamType = provider.ConsumeIntegral<int32_t>();
    int32_t activeTime = provider.ConsumeIntegral<int32_t>();
    struct EffectParam effectParam;
    effectParam.skinSmoothLevel = provider.ConsumeIntegral<int32_t>();
    effectParam.faceSlender = provider.ConsumeIntegral<int32_t>();
    effectParam.skinTone = provider.ConsumeIntegral<int32_t>();
    effectParam.skinToneBright = provider.ConsumeIntegral<int32_t>();
    effectParam.eyeBigEyes = provider.ConsumeIntegral<int32_t>();
    effectParam.hairHairline = provider.ConsumeIntegral<int32_t>();
    effectParam.faceMakeUp = provider.ConsumeIntegral<int32_t>();
    effectParam.headShrink = provider.ConsumeIntegral<int32_t>();
    effectParam.noseSlender = provider.ConsumeIntegral<int32_t>();
    g_hCameraService->SetPrelaunchConfig(
        cameraId, static_cast<RestoreParamTypeOhos>(restoreParamType), activeTime, effectParam);
}

void SetTorchLevel(FuzzedDataProvider& provider)
{
    float level = provider.ConsumeFloatingPoint<float>();
    g_hCameraService->SetTorchLevel(level);
}

void PreSwitchCamera(FuzzedDataProvider& provider)
{
    std::string cameraId = provider.ConsumeRandomLengthString();
    g_hCameraService->PreSwitchCamera(cameraId);
}

void CreateDeferredPhotoProcessingSession(FuzzedDataProvider& provider)
{
    int32_t userId = provider.ConsumeIntegral<int32_t>();
    auto cb = sptr<MockDeferredPhotoProcessingSessionCallback>::MakeSptr();
    sptr<IDeferredPhotoProcessingSession> session;
    g_hCameraService->CreateDeferredPhotoProcessingSession(userId, cb, session);
}

void GetCameraIds(FuzzedDataProvider& provider)
{
    std::vector<std::string> cameraIds;
    g_hCameraService->GetCameraIds(cameraIds);
}

void GetCameraAbility(FuzzedDataProvider& provider)
{
    std::string cameraId = provider.ConsumeRandomLengthString();
    std::shared_ptr<CameraMetadata> cameraAbility;
    g_hCameraService->GetCameraAbility(cameraId, cameraAbility);
}

void DestroyStubObj(FuzzedDataProvider& provider)
{
    g_hCameraService->DestroyStubObj();
}

void MuteCameraPersist(FuzzedDataProvider& provider)
{
    int32_t policyType = provider.ConsumeIntegral<int32_t>();
    bool isMute = provider.ConsumeBool();
    g_hCameraService->MuteCameraPersist(static_cast<OHOS::CameraStandard::PolicyType>(policyType), isMute);
}

void ProxyForFreeze(FuzzedDataProvider& provider)
{
    std::set<int32_t> pidList;
    size_t numPids = provider.ConsumeIntegralInRange<size_t>(0, 10);
    for (size_t i = 0; i < numPids; ++i) {
        pidList.insert(provider.ConsumeIntegral<int32_t>());
    }
    bool isProxy = provider.ConsumeBool();
    g_hCameraService->ProxyForFreeze(pidList, isProxy);
}

void ResetAllFreezeStatus(FuzzedDataProvider& provider)
{
    g_hCameraService->ResetAllFreezeStatus();
}

void GetDmDeviceInfo(FuzzedDataProvider& provider)
{
    std::vector<dmDeviceInfo> deviceInfos;
    g_hCameraService->GetDmDeviceInfo(deviceInfos);
}

void SetFoldStatusCallback(FuzzedDataProvider& provider)
{
    auto cb = sptr<MockFoldServiceCallback>::MakeSptr();
    bool isInnerCallback = provider.ConsumeBool();
    g_hCameraService->SetFoldStatusCallback(cb, isInnerCallback);
}

void GetCameraOutputStatus(FuzzedDataProvider& provider)
{
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    int32_t status;
    g_hCameraService->GetCameraOutputStatus(pid, status);
}

void CreateDepthDataOutput(FuzzedDataProvider& provider)
{
    sptr<IBufferProducer> producer = GetMockBufferProducer();
    int32_t format = provider.ConsumeIntegral<int32_t>();
    int32_t width = provider.ConsumeIntegral<int32_t>();
    int32_t height = provider.ConsumeIntegral<int32_t>();
    sptr<IStreamDepthData> depthDataOutput;
    g_hCameraService->CreateDepthDataOutput(producer, format, width, height, depthDataOutput);
}

void CreateDeferredVideoProcessingSession(FuzzedDataProvider& provider)
{
    int32_t userId = provider.ConsumeIntegral<int32_t>();
    auto cb = sptr<MockDeferredVideoProcessingSessionCallback>::MakeSptr();
    sptr<IDeferredVideoProcessingSession> session;
    g_hCameraService->CreateDeferredVideoProcessingSession(userId, cb, session);
}

void RequireMemorySize(FuzzedDataProvider& provider)
{
    int32_t memSize = provider.ConsumeIntegral<int32_t>();
    g_hCameraService->RequireMemorySize(memSize);
}

void GetIdforCameraConcurrentType(FuzzedDataProvider& provider)
{
    int32_t cameraPosition = provider.ConsumeIntegral<int32_t>();
    std::string cameraId;
    g_hCameraService->GetIdforCameraConcurrentType(cameraPosition, cameraId);
}

void GetConcurrentCameraAbility(FuzzedDataProvider& provider)
{
    std::string cameraId = provider.ConsumeRandomLengthString();
    std::shared_ptr<CameraMetadata> cameraAbility;
    g_hCameraService->GetConcurrentCameraAbility(cameraId, cameraAbility);
}

void GetTorchStatus(FuzzedDataProvider& provider)
{
    int32_t status;
    g_hCameraService->GetTorchStatus(status);
}

void UnSetCameraCallback(FuzzedDataProvider& provider)
{
    g_hCameraService->UnSetCameraCallback();
}

void UnSetMuteCallback(FuzzedDataProvider& provider)
{
    g_hCameraService->UnSetMuteCallback();
}

void UnSetTorchCallback(FuzzedDataProvider& provider)
{
    g_hCameraService->UnSetTorchCallback();
}

void UnSetFoldStatusCallback(FuzzedDataProvider& provider)
{
    g_hCameraService->UnSetFoldStatusCallback();
}

void CheckWhiteList(FuzzedDataProvider& provider)
{
    bool isInWhiteList = provider.ConsumeBool();
    g_hCameraService->CheckWhiteList(isInWhiteList);
}

void CreateMechSession(FuzzedDataProvider& provider)
{
    int32_t userId = provider.ConsumeIntegral<int32_t>();
    sptr<IMechSession> session;
    g_hCameraService->CreateMechSession(userId, session);
}

void IsMechSupported(FuzzedDataProvider& provider)
{
    bool isMechSupported;
    g_hCameraService->IsMechSupported(isMechSupported);
}

void GetCameraStorageSize(FuzzedDataProvider& provider)
{
    long size;
    g_hCameraService->GetCameraStorageSize(size);
}

void CreatePhotoOutputOverride(FuzzedDataProvider& provider)
{
    int32_t format = provider.ConsumeIntegral<int32_t>();
    int32_t width = provider.ConsumeIntegral<int32_t>();
    int32_t height = provider.ConsumeIntegral<int32_t>();
    sptr<IStreamCapture> photoOutput;
    g_hCameraService->CreatePhotoOutput(format, width, height, photoOutput);
}

void GetVideoSessionForControlCenter(FuzzedDataProvider& provider)
{
    sptr<ICaptureSession> session;
    g_hCameraService->GetVideoSessionForControlCenter(session);
}

void SetControlCenterCallback(FuzzedDataProvider& provider)
{
    auto cb = sptr<MockControlCenterStatusCallbackStub>::MakeSptr();

    g_hCameraService->SetControlCenterCallback(cb);
}

void UnSetControlCenterStatusCallback(FuzzedDataProvider& provider)
{
    g_hCameraService->UnSetControlCenterStatusCallback();
}

void EnableControlCenter(FuzzedDataProvider& provider)
{
    bool status = provider.ConsumeBool();
    bool needPersistEnable = provider.ConsumeBool();
    g_hCameraService->EnableControlCenter(status, needPersistEnable);
}

void SetControlCenterPrecondition(FuzzedDataProvider& provider)
{
    bool condition = provider.ConsumeBool();
    g_hCameraService->SetControlCenterPrecondition(condition);
}

void SetDeviceControlCenterAbility(FuzzedDataProvider& provider)
{
    bool ability = provider.ConsumeBool();
    g_hCameraService->SetDeviceControlCenterAbility(ability);
}

void GetControlCenterStatus(FuzzedDataProvider& provider)
{
    bool status;
    g_hCameraService->GetControlCenterStatus(status);
}

void CheckControlCenterPermission(FuzzedDataProvider& provider)
{
    g_hCameraService->CheckControlCenterPermission();
}

void AllowOpenByOHSide(FuzzedDataProvider& provider)
{
    std::string cameraId = provider.ConsumeRandomLengthString();
    int32_t state = provider.ConsumeIntegral<int32_t>();
    bool canOpenCamera = provider.ConsumeBool();
    g_hCameraService->AllowOpenByOHSide(cameraId, state, canOpenCamera);
}

void NotifyCameraState(FuzzedDataProvider& provider)
{
    std::string cameraId = provider.ConsumeRandomLengthString();
    int32_t state = provider.ConsumeIntegral<int32_t>();
    g_hCameraService->NotifyCameraState(cameraId, state);
}

void SetPeerCallback(FuzzedDataProvider& provider)
{
    auto cb = sptr<MockCameraBroker>::MakeSptr();
    g_hCameraService->SetPeerCallback(cb);
}

void UnsetPeerCallback(FuzzedDataProvider& provider)
{
    g_hCameraService->UnsetPeerCallback();
}

void PrelaunchScanCamera(FuzzedDataProvider& provider)
{
    int32_t maxLength = 30;
    std::string bundleName = provider.ConsumeRandomLengthString().substr(0, maxLength);
    std::string pageName = provider.ConsumeRandomLengthString().substr(0, maxLength);
    int32_t preScanMode = provider.ConsumeIntegralInRange<int32_t>(0, 2);
    GetInstance().PrelaunchScanCamera(bundleName, pageName,
        static_cast<PrelaunchScanModeOhos>(preScanMode));
}

void Init()
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "Get permission fail");
    g_hCameraHostManager = new (std::nothrow) HCameraHostManager(nullptr);
    if (g_hCameraHostManager) {
        sptr<HCameraService> g_hCameraService = new (std::nothrow) HCameraService(g_hCameraHostManager);
        if (g_hCameraService) {
            g_hCameraService->serviceStatus_ = CameraServiceStatus::SERVICE_NOT_READY;
        }
    }
}

void Test(FuzzedDataProvider& fdp)
{
    CHECK_RETURN_ELOG(!g_hCameraHostManager, "g_hCameraHostManager is nullptr");
    CHECK_RETURN_ELOG(!g_hCameraService, "g_hCameraService is nullptr");
    auto func = fdp.PickValueInArray({
        CreateCaptureSession,
        CreatePhotoOutput,
        CreateDeferredPreviewOutput,
        CreateVideoOutput,
        SetListenerObject,
        CreateMetadataOutput,
        MuteCamera,
        IsCameraMuted,
        IsTorchSupported,
        IsCameraMuteSupported,
        PrelaunchCamera,
        ResetRssPriority,
        SetPrelaunchConfig,
        SetTorchLevel,
        PreSwitchCamera,
        CreateDeferredPhotoProcessingSession,
        GetCameraIds,
        GetCameraAbility,
        DestroyStubObj,
        MuteCameraPersist,
        ProxyForFreeze,
        ResetAllFreezeStatus,
        GetDmDeviceInfo,
        SetFoldStatusCallback,
        GetCameraOutputStatus,
        CreateDepthDataOutput,
        CreateDeferredVideoProcessingSession,
        RequireMemorySize,
        GetIdforCameraConcurrentType,
        GetConcurrentCameraAbility,
        GetTorchStatus,
        UnSetCameraCallback,
        UnSetMuteCallback,
        UnSetTorchCallback,
        UnSetFoldStatusCallback,
        CheckWhiteList,
        CreateMechSession,
        IsMechSupported,
        GetCameraStorageSize,
        CreatePhotoOutputOverride,
        GetVideoSessionForControlCenter,
        SetControlCenterCallback,
        UnSetControlCenterStatusCallback,
        EnableControlCenter,
        SetControlCenterPrecondition,
        SetDeviceControlCenterAbility,
        GetControlCenterStatus,
        CheckControlCenterPermission,
        AllowOpenByOHSide,
        NotifyCameraState,
        SetPeerCallback,
        UnsetPeerCallback,
        PrelaunchScanCamera,
    });
    func(fdp);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    Test(fdp);
    return 0;
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    if (SetSelfTokenID(718336240ull | (1ull << 32)) < 0) {
        return -1;
    }
    Init();
    return 0;
}