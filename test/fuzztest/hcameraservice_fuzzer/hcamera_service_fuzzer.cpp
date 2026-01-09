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

HCameraService& GetInstance()
{
    static sptr<HCameraService> hCameraService = new HCameraService(g_hCameraHostManager);
    return *hCameraService;
}

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
    GetInstance().CreateCameraDevice(cameraId, device);
}

void SetCameraCallback(FuzzedDataProvider& provider)
{
    auto cb = sptr<MockCameraServiceCallback>::MakeSptr();
    GetInstance().SetCameraCallback(cb);
}

void SetMuteCallback(FuzzedDataProvider& provider)
{
    auto cb = sptr<MockCameraMuteServiceCallback>::MakeSptr();
    GetInstance().SetMuteCallback(cb);
}

void SetTorchCallback(FuzzedDataProvider& provider)
{
    auto cb = sptr<MockTorchServiceCallback>::MakeSptr();
    GetInstance().SetTorchCallback(cb);
}

void GetCameras(FuzzedDataProvider& provider)
{
    std::vector<std::string> cameraIds;
    std::vector<std::shared_ptr<CameraMetadata>> cameraAbilityList;
    GetInstance().GetCameras(cameraIds, cameraAbilityList);
}

void CreateCaptureSession(FuzzedDataProvider& provider)
{
    sptr<ICaptureSession> session;
    int32_t operationMode = provider.ConsumeIntegral<int32_t>();
    GetInstance().CreateCaptureSession(session, operationMode);
}

void CreatePhotoOutput(FuzzedDataProvider& provider)
{
    sptr<IBufferProducer> producer = GetMockBufferProducer();
    int32_t format = provider.ConsumeIntegral<int32_t>();
    int32_t width = provider.ConsumeIntegral<int32_t>();
    int32_t height = provider.ConsumeIntegral<int32_t>();
    sptr<IStreamCapture> photoOutput;
    GetInstance().CreatePhotoOutput(producer, format, width, height, photoOutput);
}

void CreateDeferredPreviewOutput(FuzzedDataProvider& provider)
{
    int32_t format = provider.ConsumeIntegral<int32_t>();
    int32_t width = provider.ConsumeIntegral<int32_t>();
    int32_t height = provider.ConsumeIntegral<int32_t>();
    sptr<IStreamRepeat> previewOutput;
    GetInstance().CreateDeferredPreviewOutput(format, width, height, previewOutput);
}

void CreateVideoOutput(FuzzedDataProvider& provider)
{
    sptr<IBufferProducer> producer = GetMockBufferProducer();
    int32_t format = provider.ConsumeIntegral<int32_t>();
    int32_t width = provider.ConsumeIntegral<int32_t>();
    int32_t height = provider.ConsumeIntegral<int32_t>();
    sptr<IStreamRepeat> videoOutput;
    GetInstance().CreateVideoOutput(producer, format, width, height, videoOutput);
}

void SetListenerObject(FuzzedDataProvider& provider)
{
    auto remote = sptr<MockIRemoteObject>::MakeSptr();
    GetInstance().SetListenerObject(remote);
}

void CreateMetadataOutput(FuzzedDataProvider& provider)
{
    sptr<IBufferProducer> producer = GetMockBufferProducer();
    int32_t format = provider.ConsumeIntegral<int32_t>();
    std::vector<int32_t> metadataTypes = ConsumeIntList(provider);
    sptr<IStreamMetadata> metadataOutput;
    GetInstance().CreateMetadataOutput(producer, format, metadataTypes, metadataOutput);
}

void MuteCamera(FuzzedDataProvider& provider)
{
    bool muteMode = provider.ConsumeBool();
    GetInstance().MuteCamera(muteMode);
}

void IsCameraMuted(FuzzedDataProvider& provider)
{
    bool muteMode;
    GetInstance().IsCameraMuted(muteMode);
}

void IsTorchSupported(FuzzedDataProvider& provider)
{
    bool isTorchSupported;
    GetInstance().IsTorchSupported(isTorchSupported);
}

void IsCameraMuteSupported(FuzzedDataProvider& provider)
{
    bool isCameraMuteSupported;
    GetInstance().IsCameraMuteSupported(isCameraMuteSupported);
}

void PrelaunchCamera(FuzzedDataProvider& provider)
{
    int32_t flag = provider.ConsumeIntegral<int32_t>();
    GetInstance().PrelaunchCamera(flag);
}

void ResetRssPriority(FuzzedDataProvider& provider)
{
    GetInstance().ResetRssPriority();
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
    GetInstance().SetPrelaunchConfig(
        cameraId, static_cast<RestoreParamTypeOhos>(restoreParamType), activeTime, effectParam);
}

void SetTorchLevel(FuzzedDataProvider& provider)
{
    float level = provider.ConsumeFloatingPoint<float>();
    GetInstance().SetTorchLevel(level);
}

void PreSwitchCamera(FuzzedDataProvider& provider)
{
    std::string cameraId = provider.ConsumeRandomLengthString();
    GetInstance().PreSwitchCamera(cameraId);
}

void CreateDeferredPhotoProcessingSession(FuzzedDataProvider& provider)
{
    int32_t userId = provider.ConsumeIntegral<int32_t>();
    auto cb = sptr<MockDeferredPhotoProcessingSessionCallback>::MakeSptr();
    sptr<IDeferredPhotoProcessingSession> session;
    GetInstance().CreateDeferredPhotoProcessingSession(userId, cb, session);
}

void GetCameraIds(FuzzedDataProvider& provider)
{
    std::vector<std::string> cameraIds;
    GetInstance().GetCameraIds(cameraIds);
}

void GetCameraAbility(FuzzedDataProvider& provider)
{
    std::string cameraId = provider.ConsumeRandomLengthString();
    std::shared_ptr<CameraMetadata> cameraAbility;
    GetInstance().GetCameraAbility(cameraId, cameraAbility);
}

void DestroyStubObj(FuzzedDataProvider& provider)
{
    GetInstance().DestroyStubObj();
}

void MuteCameraPersist(FuzzedDataProvider& provider)
{
    int32_t policyType = provider.ConsumeIntegral<int32_t>();
    bool isMute = provider.ConsumeBool();
    GetInstance().MuteCameraPersist(static_cast<OHOS::CameraStandard::PolicyType>(policyType), isMute);
}

void ProxyForFreeze(FuzzedDataProvider& provider)
{
    std::set<int32_t> pidList;
    size_t numPids = provider.ConsumeIntegralInRange<size_t>(0, 10);
    for (size_t i = 0; i < numPids; ++i) {
        pidList.insert(provider.ConsumeIntegral<int32_t>());
    }
    bool isProxy = provider.ConsumeBool();
    GetInstance().ProxyForFreeze(pidList, isProxy);
}

void ResetAllFreezeStatus(FuzzedDataProvider& provider)
{
    GetInstance().ResetAllFreezeStatus();
}

void GetDmDeviceInfo(FuzzedDataProvider& provider)
{
    std::vector<dmDeviceInfo> deviceInfos;
    GetInstance().GetDmDeviceInfo(deviceInfos);
}

void SetFoldStatusCallback(FuzzedDataProvider& provider)
{
    auto cb = sptr<MockFoldServiceCallback>::MakeSptr();
    bool isInnerCallback = provider.ConsumeBool();
    GetInstance().SetFoldStatusCallback(cb, isInnerCallback);
}

void GetCameraOutputStatus(FuzzedDataProvider& provider)
{
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    int32_t status;
    GetInstance().GetCameraOutputStatus(pid, status);
}

void CreateDepthDataOutput(FuzzedDataProvider& provider)
{
    sptr<IBufferProducer> producer = GetMockBufferProducer();
    int32_t format = provider.ConsumeIntegral<int32_t>();
    int32_t width = provider.ConsumeIntegral<int32_t>();
    int32_t height = provider.ConsumeIntegral<int32_t>();
    sptr<IStreamDepthData> depthDataOutput;
    GetInstance().CreateDepthDataOutput(producer, format, width, height, depthDataOutput);
}

void CreateDeferredVideoProcessingSession(FuzzedDataProvider& provider)
{
    int32_t userId = provider.ConsumeIntegral<int32_t>();
    auto cb = sptr<MockDeferredVideoProcessingSessionCallback>::MakeSptr();
    sptr<IDeferredVideoProcessingSession> session;
    GetInstance().CreateDeferredVideoProcessingSession(userId, cb, session);
}

void RequireMemorySize(FuzzedDataProvider& provider)
{
    int32_t memSize = provider.ConsumeIntegral<int32_t>();
    GetInstance().RequireMemorySize(memSize);
}

void GetIdforCameraConcurrentType(FuzzedDataProvider& provider)
{
    int32_t cameraPosition = provider.ConsumeIntegral<int32_t>();
    std::string cameraId;
    GetInstance().GetIdforCameraConcurrentType(cameraPosition, cameraId);
}

void GetConcurrentCameraAbility(FuzzedDataProvider& provider)
{
    std::string cameraId = provider.ConsumeRandomLengthString();
    std::shared_ptr<CameraMetadata> cameraAbility;
    GetInstance().GetConcurrentCameraAbility(cameraId, cameraAbility);
}

void GetTorchStatus(FuzzedDataProvider& provider)
{
    int32_t status;
    GetInstance().GetTorchStatus(status);
}

void UnSetCameraCallback(FuzzedDataProvider& provider)
{
    GetInstance().UnSetCameraCallback();
}

void UnSetMuteCallback(FuzzedDataProvider& provider)
{
    GetInstance().UnSetMuteCallback();
}

void UnSetTorchCallback(FuzzedDataProvider& provider)
{
    GetInstance().UnSetTorchCallback();
}

void UnSetFoldStatusCallback(FuzzedDataProvider& provider)
{
    GetInstance().UnSetFoldStatusCallback();
}

void CheckWhiteList(FuzzedDataProvider& provider)
{
    bool isInWhiteList = provider.ConsumeBool();
    GetInstance().CheckWhiteList(isInWhiteList);
}

void CreateMechSession(FuzzedDataProvider& provider)
{
    int32_t userId = provider.ConsumeIntegral<int32_t>();
    sptr<IMechSession> session;
    GetInstance().CreateMechSession(userId, session);
}

void IsMechSupported(FuzzedDataProvider& provider)
{
    bool isMechSupported;
    GetInstance().IsMechSupported(isMechSupported);
}

void GetCameraStorageSize(FuzzedDataProvider& provider)
{
    long size;
    GetInstance().GetCameraStorageSize(size);
}

void CreatePhotoOutputOverride(FuzzedDataProvider& provider)
{
    int32_t format = provider.ConsumeIntegral<int32_t>();
    int32_t width = provider.ConsumeIntegral<int32_t>();
    int32_t height = provider.ConsumeIntegral<int32_t>();
    sptr<IStreamCapture> photoOutput;
    GetInstance().CreatePhotoOutput(format, width, height, photoOutput);
}

void GetVideoSessionForControlCenter(FuzzedDataProvider& provider)
{
    sptr<ICaptureSession> session;
    GetInstance().GetVideoSessionForControlCenter(session);
}

void SetControlCenterCallback(FuzzedDataProvider& provider)
{
    auto cb = sptr<MockControlCenterStatusCallbackStub>::MakeSptr();

    GetInstance().SetControlCenterCallback(cb);
}

void UnSetControlCenterStatusCallback(FuzzedDataProvider& provider)
{
    GetInstance().UnSetControlCenterStatusCallback();
}

void EnableControlCenter(FuzzedDataProvider& provider)
{
    bool status = provider.ConsumeBool();
    bool needPersistEnable = provider.ConsumeBool();
    GetInstance().EnableControlCenter(status, needPersistEnable);
}

void SetControlCenterPrecondition(FuzzedDataProvider& provider)
{
    bool condition = provider.ConsumeBool();
    GetInstance().SetControlCenterPrecondition(condition);
}

void SetDeviceControlCenterAbility(FuzzedDataProvider& provider)
{
    bool ability = provider.ConsumeBool();
    GetInstance().SetDeviceControlCenterAbility(ability);
}

void GetControlCenterStatus(FuzzedDataProvider& provider)
{
    bool status;
    GetInstance().GetControlCenterStatus(status);
}

void CheckControlCenterPermission(FuzzedDataProvider& provider)
{
    GetInstance().CheckControlCenterPermission();
}

void AllowOpenByOHSide(FuzzedDataProvider& provider)
{
    std::string cameraId = provider.ConsumeRandomLengthString();
    int32_t state = provider.ConsumeIntegral<int32_t>();
    bool canOpenCamera = provider.ConsumeBool();
    GetInstance().AllowOpenByOHSide(cameraId, state, canOpenCamera);
}

void NotifyCameraState(FuzzedDataProvider& provider)
{
    std::string cameraId = provider.ConsumeRandomLengthString();
    int32_t state = provider.ConsumeIntegral<int32_t>();
    GetInstance().NotifyCameraState(cameraId, state);
}

void SetPeerCallback(FuzzedDataProvider& provider)
{
    auto cb = sptr<MockCameraBroker>::MakeSptr();
    GetInstance().SetPeerCallback(cb);
}

void UnsetPeerCallback(FuzzedDataProvider& provider)
{
    GetInstance().UnsetPeerCallback();
}

void Init()
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "Get permission fail");
    g_hCameraHostManager = new HCameraHostManager(nullptr);
    GetInstance().serviceStatus_ = CameraServiceStatus::SERVICE_NOT_READY;
}

void Test(FuzzedDataProvider& fdp)
{
    CHECK_RETURN_ELOG(!g_hCameraHostManager, "g_hCameraHostManager permission fail");
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