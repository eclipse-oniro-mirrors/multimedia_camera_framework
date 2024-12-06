/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "hcamera_service_stub.h"

#include <cinttypes>

#include "camera_log.h"
#include "camera_service_ipc_interface_code.h"
#include "camera_util.h"
#include "camera_xcollie.h"
#include "hcamera_service.h"
#include "input/i_standard_camera_listener.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#ifdef MEMMGR_OVERRID
#include "mem_mgr_client.h"
#include "mem_mgr_constant.h"
#endif

namespace OHOS {
namespace CameraStandard {
HCameraServiceStub::HCameraServiceStub()
{
    MEDIA_DEBUG_LOG("0x%{public}06" PRIXPTR " Instances create", (POINTER_MASK & reinterpret_cast<uintptr_t>(this)));
}

HCameraServiceStub::~HCameraServiceStub()
{
    MEDIA_DEBUG_LOG("0x%{public}06" PRIXPTR " Instances destroy", (POINTER_MASK & reinterpret_cast<uintptr_t>(this)));
}

int HCameraServiceStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    DisableJeMalloc();
    int errCode = -1;
    CHECK_ERROR_RETURN_RET(data.ReadInterfaceToken() != GetDescriptor(), errCode);
    CameraXCollie cameraXCollie = CameraXCollie("CameraServiceStub " + std::to_string(code));
    switch (code) {
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_DEVICE):
            errCode = HCameraServiceStub::HandleCreateCameraDevice(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_CAMERA_CALLBACK):
            errCode = HCameraServiceStub::HandleSetCameraCallback(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_MUTE_CALLBACK):
            errCode = HCameraServiceStub::HandleSetMuteCallback(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_TORCH_CALLBACK):
            errCode = HCameraServiceStub::HandleSetTorchCallback(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_FOLD_CALLBACK):
            errCode = HCameraServiceStub::HandleSetFoldStatusCallback(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_GET_CAMERAS):
            errCode = HCameraServiceStub::HandleGetCameras(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_GET_CAMERA_IDS):
            errCode = HCameraServiceStub::HandleGetCameraIds(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_GET_CAMERA_ABILITY):
            errCode = HCameraServiceStub::HandleGetCameraAbility(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_CAPTURE_SESSION):
            errCode = HCameraServiceStub::HandleCreateCaptureSession(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_DEFERRED_PHOTO_PROCESSING_SESSION):
            errCode = HCameraServiceStub::HandleCreateDeferredPhotoProcessingSession(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_DEFERRED_VIDEO_PROCESSING_SESSION):
            errCode = HCameraServiceStub::HandleCreateDeferredVideoProcessingSession(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_PHOTO_OUTPUT):
            errCode = HCameraServiceStub::HandleCreatePhotoOutput(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_PREVIEW_OUTPUT):
            errCode = HCameraServiceStub::HandleCreatePreviewOutput(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_DEFERRED_PREVIEW_OUTPUT):
            errCode = HCameraServiceStub::HandleCreateDeferredPreviewOutput(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_DEPTH_DATA_OUTPUT):
            errCode = HCameraServiceStub::HandleCreateDepthDataOutput(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_VIDEO_OUTPUT):
            errCode = HCameraServiceStub::HandleCreateVideoOutput(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_LISTENER_OBJ):
            errCode = HCameraServiceStub::SetListenerObject(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_METADATA_OUTPUT):
            errCode = HCameraServiceStub::HandleCreateMetadataOutput(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_MUTE_CAMERA):
            errCode = HCameraServiceStub::HandleMuteCamera(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_MUTE_CAMERA_PERSIST):
            errCode = HCameraServiceStub::HandleMuteCameraPersist(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_IS_CAMERA_MUTED):
            cameraXCollie.CancelCameraXCollie();
            errCode = HCameraServiceStub::HandleIsCameraMuted(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_PRE_LAUNCH_CAMERA):
            errCode = HCameraServiceStub::HandlePrelaunchCamera(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_PRE_LAUNCH_CAMERA):
            errCode = HCameraServiceStub::HandleSetPrelaunchConfig(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_TORCH_LEVEL):
            errCode = HCameraServiceStub::HandleSetTorchLevel(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_PRE_SWITCH_CAMERA):
            errCode = HCameraServiceStub::HandlePreSwitchCamera(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_DESTROY_STUB_OBJ):
            errCode = HCameraServiceStub::DestroyStubObj();
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_PROXY_FOR_FREEZE):
            errCode = HCameraServiceStub::HandleProxyForFreeze(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_RESET_ALL_FREEZE_STATUS):
            errCode = HCameraServiceStub::HandleResetAllFreezeStatus(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceDHInterfaceCode::CAMERA_SERVICE_ALLOW_OPEN_BY_OHSIDE):
            errCode = HCameraServiceStub::HandleAllowOpenByOHSide(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceDHInterfaceCode::CAMERA_SERVICE_NOTIFY_CAMERA_STATE):
            errCode = HCameraServiceStub::HandleNotifyCameraState(data);
            break;
        case static_cast<uint32_t>(CameraServiceDHInterfaceCode::CAMERA_SERVICE_SET_PEER_CALLBACK):
            errCode = HCameraServiceStub::HandleSetPeerCallback(data);
            break;
        case static_cast<uint32_t>(CameraServiceDHInterfaceCode::CAMERA_SERVICE_UNSET_PEER_CALLBACK):
            errCode = HCameraServiceStub::HandleUnsetPeerCallback(data);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_GET_DM_DEVICE_INFOS):
            errCode = HCameraServiceStub::HandleGetDmDeviceInfo(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_GET_CAMERA_OUTPUT_STATUS):
            errCode = HCameraServiceStub::HandleGetCameraOutputStatus(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_REQUIRE_MEMORY_SIZE):
            errCode = HCameraServiceStub::HandleRequireMemorySize(data, reply);
            break;
        default:
            MEDIA_ERR_LOG("HCameraServiceStub request code %{public}d not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }

    return errCode;
}

int HCameraServiceStub::HandleGetCameras(MessageParcel& data, MessageParcel& reply)
{
    std::vector<std::string> cameraIds;
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList;

    int ret = GetCameras(cameraIds, cameraAbilityList);
    CHECK_ERROR_RETURN_RET_LOG(!reply.WriteStringVector(cameraIds), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleGetCameras WriteStringVector failed");

    int count = static_cast<int>(cameraAbilityList.size());
    CHECK_ERROR_RETURN_RET_LOG(!reply.WriteInt32(count), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleGetCameras Write vector size failed");

    for (auto cameraAbility : cameraAbilityList) {
        bool result = OHOS::Camera::MetadataUtils::EncodeCameraMetadata(cameraAbility, reply);
        CHECK_ERROR_RETURN_RET_LOG(!result, IPC_STUB_WRITE_PARCEL_ERR,
            "HCameraServiceStub HandleGetCameras write ability failed");
    }

    return ret;
}

int HCameraServiceStub::HandleGetCameraIds(MessageParcel& data, MessageParcel& reply)
{
    std::vector<std::string> cameraIds;
    int ret = GetCameraIds(cameraIds);
    CHECK_ERROR_RETURN_RET_LOG(!reply.WriteStringVector(cameraIds), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleGetCameras WriteStringVector failed");

    int count = static_cast<int>(cameraIds.size());
    CHECK_ERROR_RETURN_RET_LOG(!reply.WriteInt32(count), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleGetCameras Write vector size failed");

    return ret;
}

int HCameraServiceStub::HandleGetCameraAbility(MessageParcel& data, MessageParcel& reply)
{
    std::string cameraId = data.ReadString();
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    int ret = GetCameraAbility(cameraId, cameraAbility);
    bool result = OHOS::Camera::MetadataUtils::EncodeCameraMetadata(cameraAbility, reply);
    CHECK_ERROR_RETURN_RET_LOG(!result, IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleGetCameraAbility write ability failed");

    return ret;
}

int HCameraServiceStub::HandleCreateCameraDevice(MessageParcel& data, MessageParcel& reply)
{
    std::string cameraId = data.ReadString();
    sptr<ICameraDeviceService> device = nullptr;

    int ret = CreateCameraDevice(cameraId, device);
    CHECK_ERROR_RETURN_RET_LOG(ret != ERR_NONE, ret,
        "HCameraServiceStub HandleCreateCameraDevice Create camera device failed : %{public}d", ret);

    CHECK_ERROR_RETURN_RET_LOG(!reply.WriteRemoteObject(device->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleCreateCameraDevice Write CameraDevice obj failed");

    return ret;
}

int HCameraServiceStub::HandleMuteCamera(MessageParcel& data, MessageParcel& reply)
{
    CHECK_ERROR_RETURN_RET(!CheckSystemApp(), CAMERA_NO_PERMISSION);

    bool muteMode = data.ReadBool();
    MEDIA_DEBUG_LOG("HCameraServiceStub HandleMuteCamera read muteMode : %{public}d", muteMode);

    int32_t ret = MuteCamera(muteMode);
    MEDIA_INFO_LOG("HCameraServiceStub HandleMuteCamera MuteCamera result: %{public}d", ret);

    return ret;
}

int HCameraServiceStub::HandleMuteCameraPersist(MessageParcel& data, MessageParcel& reply)
{
    CHECK_ERROR_RETURN_RET(!CheckSystemApp(), CAMERA_NO_PERMISSION);

    int32_t policyType = data.ReadInt32();
    MEDIA_DEBUG_LOG("HCameraServiceStub HandleMuteCameraPersist read policyType : %{public}d", policyType);
    bool muteMode = data.ReadBool();
    MEDIA_DEBUG_LOG("HCameraServiceStub HandleMuteCameraPersist read muteMode : %{public}d", muteMode);

    int32_t ret = MuteCameraPersist(static_cast<PolicyType>(policyType), muteMode);
    MEDIA_INFO_LOG("HCameraServiceStub HandleMuteCameraPersist MuteCamera result: %{public}d", ret);

    return ret;
}

int HCameraServiceStub::HandlePrelaunchCamera(MessageParcel& data, MessageParcel& reply)
{
    MEDIA_DEBUG_LOG("HCameraServiceStub HandlePrelaunchCamera enter");
    CHECK_ERROR_RETURN_RET(!CheckSystemApp(), CAMERA_NO_PERMISSION);

    int32_t ret = PrelaunchCamera();
    MEDIA_INFO_LOG("HCameraServiceStub HandlePrelaunchCamera result: %{public}d", ret);

    return ret;
}

int HCameraServiceStub::HandlePreSwitchCamera(MessageParcel& data, MessageParcel& reply)
{
    MEDIA_DEBUG_LOG("HCameraServiceStub HandlePreSwitchCamera enter");
    CHECK_ERROR_RETURN_RET(!CheckSystemApp(), CAMERA_NO_PERMISSION);

    auto cameraId = data.ReadString();
    CHECK_ERROR_RETURN_RET(cameraId.empty() || cameraId.length() > PATH_MAX, CAMERA_INVALID_ARG);

    int32_t ret = PreSwitchCamera(cameraId);
    MEDIA_INFO_LOG("HCameraServiceStub HandlePreSwitchCamera result: %{public}d", ret);

    return ret;
}

int HCameraServiceStub::HandleSetPrelaunchConfig(MessageParcel& data, MessageParcel& reply)
{
    MEDIA_DEBUG_LOG("HCameraServiceStub HandleSetPrelaunchConfig enter");
    CHECK_ERROR_RETURN_RET(!CheckSystemApp(), CAMERA_NO_PERMISSION);

    std::string cameraId = data.ReadString();
    RestoreParamTypeOhos restoreTypeParam = static_cast<RestoreParamTypeOhos>(data.ReadUint32());
    int32_t activeTime = static_cast<int32_t>(data.ReadUint32());
    EffectParam effectParam;
    effectParam.skinSmoothLevel = static_cast<int>(data.ReadUint32());
    effectParam.faceSlender = static_cast<int32_t>(data.ReadUint32());
    effectParam.skinTone = static_cast<int32_t>(data.ReadUint32());
    int32_t ret = SetPrelaunchConfig(cameraId, restoreTypeParam, activeTime, effectParam);
    MEDIA_INFO_LOG("HCameraServiceStub HandleSetPrelaunchConfig result: %{public}d", ret);

    return ret;
}

int HCameraServiceStub::HandleIsCameraMuted(MessageParcel& data, MessageParcel& reply)
{
    CHECK_ERROR_RETURN_RET(!CheckSystemApp(), CAMERA_NO_PERMISSION);

    bool isMuted = false;
    int32_t ret = IsCameraMuted(isMuted);
    MEDIA_INFO_LOG("HCameraServiceStub HandleIsCameraMuted result: %{public}d, isMuted: %{public}d", ret, isMuted);
    CHECK_ERROR_RETURN_RET_LOG(!reply.WriteBool(isMuted), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleIsCameraMuted Write isMuted failed");

    return ret;
}

int HCameraServiceStub::HandleSetCameraCallback(MessageParcel& data, MessageParcel& reply)
{
    auto remoteObject = data.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObject == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleSetCameraCallback CameraServiceCallback is null");

    auto callback = iface_cast<ICameraServiceCallback>(remoteObject);
    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleSetCameraCallback callback is null");

    return SetCameraCallback(callback);
}

int HCameraServiceStub::HandleSetMuteCallback(MessageParcel& data, MessageParcel& reply)
{
    CHECK_ERROR_RETURN_RET(!CheckSystemApp(), CAMERA_NO_PERMISSION);

    auto remoteObject = data.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObject == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleSetMuteCallback CameraMuteServiceCallback is null");

    auto callback = iface_cast<ICameraMuteServiceCallback>(remoteObject);
    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleSetMuteCallback callback is null");

    return SetMuteCallback(callback);
}

int HCameraServiceStub::HandleSetTorchCallback(MessageParcel& data, MessageParcel& reply)
{
    auto remoteObject = data.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObject == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleSetTorchCallback TorchServiceCallback is null");

    auto callback = iface_cast<ITorchServiceCallback>(remoteObject);
    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleSetTorchCallback callback is null");

    return SetTorchCallback(callback);
}

int HCameraServiceStub::HandleSetFoldStatusCallback(MessageParcel& data, MessageParcel& reply)
{
    auto remoteObject = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObject != nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleSetFoldStatusCallback FoldServiceCallback is null");

    auto callback = iface_cast<IFoldServiceCallback>(remoteObject);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCameraServiceStub HandleSetFoldStatusCallback callback is null");
    bool isInnerCallback = data.ReadBool();
    return SetFoldStatusCallback(callback, isInnerCallback);
}

int HCameraServiceStub::HandleCreateCaptureSession(MessageParcel& data, MessageParcel& reply)
{
    sptr<ICaptureSession> session = nullptr;

    int32_t operationMode = data.ReadInt32();
    int ret = CreateCaptureSession(session, operationMode);
    CHECK_ERROR_RETURN_RET_LOG(ret != ERR_NONE, ret,
        "HandleCreateCaptureSession CreateCaptureSession failed : %{public}d", ret);

    CHECK_ERROR_RETURN_RET_LOG(!reply.WriteRemoteObject(session->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleCreateCaptureSession Write CaptureSession obj failed");

    return ret;
}

int HCameraServiceStub::HandleCreateDeferredPhotoProcessingSession(MessageParcel &data, MessageParcel &reply)
{
    CHECK_ERROR_RETURN_RET(!CheckSystemApp(), CAMERA_NO_PERMISSION);
    sptr<DeferredProcessing::IDeferredPhotoProcessingSession> session = nullptr;

    int32_t userId = data.ReadInt32();
    auto remoteObject = data.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObject == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HandleCreateDeferredPhotoProcessingSession DeferredPhotoProcessingSessionCallback is null");

    auto callback = iface_cast<DeferredProcessing::IDeferredPhotoProcessingSessionCallback>(remoteObject);
    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleCreateDeferredPhotoProcessingSession callback is null");

    int ret = CreateDeferredPhotoProcessingSession(userId, callback, session);
    CHECK_ERROR_RETURN_RET_LOG(ret != ERR_NONE, ret,
        "HandleCreateDeferredPhotoProcessingSession create failed : %{public}d", ret);
    CHECK_ERROR_RETURN_RET_LOG(!reply.WriteRemoteObject(session->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        "HandleCreateDeferredPhotoProcessingSession Write HandleCreateDeferredPhotoProcessingSession obj failed");

    return ret;
}

int HCameraServiceStub::HandleCreateDeferredVideoProcessingSession(MessageParcel &data, MessageParcel &reply)
{
    sptr<DeferredProcessing::IDeferredVideoProcessingSession> session = nullptr;

    int32_t userId = data.ReadInt32();
    auto remoteObject = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObject != nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HandleCreateDeferredVideoProcessingSession DeferredVideoProcessingSessionCallback is null");

    auto callback = iface_cast<DeferredProcessing::IDeferredVideoProcessingSessionCallback>(remoteObject);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleCreateDeferredVideoProcessingSession callback is null");
    int ret = CreateDeferredVideoProcessingSession(userId, callback, session);
    CHECK_ERROR_RETURN_RET_LOG(ret != ERR_NONE, ret,
        "HandleCreateDeferredVideoProcessingSession create failed : %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(reply.WriteRemoteObject(session->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        "HandleCreateDeferredVideoProcessingSession Write HandleCreateDeferredVideoProcessingSession obj failed");

    return ret;
}

int HCameraServiceStub::HandleCreatePhotoOutput(MessageParcel& data, MessageParcel& reply)
{
    sptr<IStreamCapture> photoOutput = nullptr;
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObj == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleCreatePhotoOutput BufferProducer is null");

    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleCreatePhotoOutput producer is null");

    int32_t format = data.ReadInt32();
    int32_t width = data.ReadInt32();
    int32_t height = data.ReadInt32();
    MEDIA_INFO_LOG(
        "HCameraServiceStub::HandleCreatePhotoOutput, format: %{public}d, width: %{public}d, height: %{public}d",
        format, width, height);
    int ret = CreatePhotoOutput(producer, format, width, height, photoOutput);
    CHECK_ERROR_RETURN_RET_LOG(ret != ERR_NONE, ret,
        "HCameraServiceStub::HandleCreatePhotoOutput Create photo output failed : %{public}d", ret);
    CHECK_ERROR_RETURN_RET_LOG(!reply.WriteRemoteObject(photoOutput->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleCreateCameraDevice Write photoOutput obj failed");

    return ret;
}

int HCameraServiceStub::HandleCreatePreviewOutput(MessageParcel& data, MessageParcel& reply)
{
    sptr<IStreamRepeat> previewOutput = nullptr;
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObj == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleCreatePreviewOutput BufferProducer is null");

    int32_t format = data.ReadInt32();
    int32_t width = data.ReadInt32();
    int32_t height = data.ReadInt32();
    MEDIA_INFO_LOG(
        "CreatePreviewOutput, format: %{public}d, width: %{public}d, height: %{public}d", format, width, height);
    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleCreatePreviewOutput producer is null");

    int ret = CreatePreviewOutput(producer, format, width, height, previewOutput);
    CHECK_ERROR_RETURN_RET_LOG(ret != ERR_NONE, ret,
        "HandleCreatePreviewOutput CreatePreviewOutput failed : %{public}d", ret);
    CHECK_ERROR_RETURN_RET_LOG(!reply.WriteRemoteObject(previewOutput->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleCreatePreviewOutput Write previewOutput obj failed");

    return ret;
}

int HCameraServiceStub::HandleCreateDeferredPreviewOutput(MessageParcel& data, MessageParcel& reply)
{
    CHECK_ERROR_RETURN_RET(!CheckSystemApp(), CAMERA_NO_PERMISSION);

    sptr<IStreamRepeat> previewOutput = nullptr;
    int32_t format = data.ReadInt32();
    int32_t width = data.ReadInt32();
    int32_t height = data.ReadInt32();
    MEDIA_INFO_LOG(
        "CreatePreviewOutput, format: %{public}d, width: %{public}d, height: %{public}d", format, width, height);
    int ret = CreateDeferredPreviewOutput(format, width, height, previewOutput);
    CHECK_ERROR_RETURN_RET_LOG(ret != ERR_NONE, ret,
        "HandleCreateDeferredPreviewOutput CreatePreviewOutput failed : %{public}d", ret);
    CHECK_ERROR_RETURN_RET_LOG(!reply.WriteRemoteObject(previewOutput->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleCreateDeferredPreviewOutput Write previewOutput obj failed");

    return ret;
}

int HCameraServiceStub::HandleCreateDepthDataOutput(MessageParcel& data, MessageParcel& reply)
{
    sptr<IStreamDepthData> depthDataOutput = nullptr;

    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObj != nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleCreateDepthDataOutput BufferProducer is null");
    int32_t format = data.ReadInt32();
    int32_t width = data.ReadInt32();
    int32_t height = data.ReadInt32();
    MEDIA_INFO_LOG(
        "CreateDepthDataOutput, format: %{public}d, width: %{public}d, height: %{public}d", format, width, height);
    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    CHECK_AND_RETURN_RET_LOG(producer != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCameraServiceStub HandleCreateDepthDataOutput producer is null");
    int errCode = CreateDepthDataOutput(producer, format, width, height, depthDataOutput);
    if (errCode != ERR_NONE) {
        MEDIA_ERR_LOG("HandleCreateDepthDataOutput CreateDepthDataOutput failed : %{public}d", errCode);
        return errCode;
    }
    CHECK_AND_RETURN_RET_LOG(reply.WriteRemoteObject(depthDataOutput->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleCreateDepthDataOutput Write previewOutput obj failed");
    return errCode;
}

int HCameraServiceStub::HandleCreateMetadataOutput(MessageParcel& data, MessageParcel& reply)
{
    sptr<IStreamMetadata> metadataOutput = nullptr;
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObj == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleCreateMetadataOutput BufferProducer is null");
 
    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleCreateMetadataOutput producer is null");
 
    int32_t format = data.ReadInt32();
    std::vector<int32_t> metadataTypes;
    CHECK_AND_PRINT_LOG(data.ReadInt32Vector(&metadataTypes),
        "HStreamMetadataStub Start metadataTypes is null");
    int ret = CreateMetadataOutput(producer, format, metadataTypes, metadataOutput);
    CHECK_ERROR_RETURN_RET_LOG(ret != ERR_NONE, ret,
        "HCameraServiceStub HandleCreateMetadataOutput CreateMetadataOutput failed : %{public}d", ret);
    CHECK_ERROR_RETURN_RET_LOG(!reply.WriteRemoteObject(metadataOutput->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleCreateMetadataOutput Write metadataOutput obj failed");
    return ret;
}

int HCameraServiceStub::HandleCreateVideoOutput(MessageParcel& data, MessageParcel& reply)
{
    sptr<IStreamRepeat> videoOutput = nullptr;
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObj == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleCreateVideoOutput BufferProducer is null");

    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleCreateVideoOutput producer is null");

    int32_t format = data.ReadInt32();
    int32_t width = data.ReadInt32();
    int32_t height = data.ReadInt32();
    int ret = CreateVideoOutput(producer, format, width, height, videoOutput);
    CHECK_ERROR_RETURN_RET_LOG(ret != ERR_NONE, ret,
        "HCameraServiceStub HandleCreateVideoOutput CreateVideoOutput failed : %{public}d", ret);
    CHECK_ERROR_RETURN_RET_LOG(!reply.WriteRemoteObject(videoOutput->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleCreateVideoOutput Write videoOutput obj failed");

    return ret;
}

int HCameraServiceStub::HandleSetTorchLevel(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_DEBUG_LOG("HCameraServiceStub HandleSetTorchLevel enter");
    float level = data.ReadFloat();
    int ret = SetTorchLevel(level);
    MEDIA_INFO_LOG("HCameraServiceStub HandleSetTorchLevel result: %{public}d", ret);

    return ret;
}

int32_t HCameraServiceStub::UnSetAllCallback(pid_t pid)
{
    return CAMERA_OK;
}

int32_t HCameraServiceStub::CloseCameraForDestory(pid_t pid)
{
    return CAMERA_OK;
}

int HCameraServiceStub::DestroyStubForPid(pid_t pid)
{
    UnSetAllCallback(pid);
    ClearCameraListenerByPid(pid);
    HCaptureSession::DestroyStubObjectForPid(pid);
    CloseCameraForDestory(pid);

    return CAMERA_OK;
}

void HCameraServiceStub::ClientDied(pid_t pid)
{
    DisableJeMalloc();
    MEDIA_ERR_LOG("client pid is dead, pid:%{public}d", pid);
    (void)DestroyStubForPid(pid);
}

void HCameraServiceStub::ClearCameraListenerByPid(pid_t pid)
{
    sptr<IStandardCameraListener> cameraListenerTmp = nullptr;
    if (cameraListenerMap_.Find(pid, cameraListenerTmp)) {
        if (cameraListenerTmp != nullptr && cameraListenerTmp->AsObject() != nullptr) {
            cameraListenerTmp->RemoveCameraDeathRecipient();
        }
        cameraListenerMap_.Erase(pid);
    }
}

int HCameraServiceStub::SetListenerObject(const sptr<IRemoteObject>& object)
{
    pid_t pid = IPCSkeleton::GetCallingPid();
    ClearCameraListenerByPid(pid); // Ensure cleanup before starting the listener if this is the second call
    CHECK_ERROR_RETURN_RET_LOG(object == nullptr, CAMERA_ALLOC_ERROR, "set listener object is nullptr");

    sptr<IStandardCameraListener> cameraListener = iface_cast<IStandardCameraListener>(object);
    CHECK_ERROR_RETURN_RET_LOG(cameraListener == nullptr, CAMERA_ALLOC_ERROR,
        "failed to cast IStandardCameraListener");

    sptr<CameraDeathRecipient> deathRecipient = new (std::nothrow) CameraDeathRecipient(pid);
    CHECK_ERROR_RETURN_RET_LOG(deathRecipient == nullptr, CAMERA_ALLOC_ERROR, "failed to new CameraDeathRecipient");

    auto thisPtr = wptr<HCameraServiceStub>(this);
    deathRecipient->SetNotifyCb([thisPtr](pid_t pid) {
        auto serviceStubPtr = thisPtr.promote();
        if (serviceStubPtr != nullptr) {
            serviceStubPtr->ClientDied(pid);
        }
    });
    cameraListener->AddCameraDeathRecipient(deathRecipient);
    cameraListenerMap_.EnsureInsert(pid, cameraListener);

    return CAMERA_OK;
}

int HCameraServiceStub::SetListenerObject(MessageParcel& data, MessageParcel& reply)
{
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET(object == nullptr, ERR_NULL_OBJECT);
    (void)reply.WriteInt32(SetListenerObject(object));

    return ERR_NONE;
}

int HCameraServiceStub::HandleAllowOpenByOHSide(MessageParcel& data, MessageParcel& reply)
{
    std::string cameraId = data.ReadString();
    int32_t state = data.ReadInt32();
    bool canOpenCamera = false;

    int ret = AllowOpenByOHSide(cameraId, state, canOpenCamera);
    CHECK_ERROR_RETURN_RET_LOG(!reply.WriteBool(canOpenCamera), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleAllowOpenByOHSide get camera failed");

    return ret;
}

int HCameraServiceStub::DestroyStubObj()
{
    pid_t pid = IPCSkeleton::GetCallingPid();
    MEDIA_DEBUG_LOG("DestroyStubObj client pid:%{public}d", pid);
    (void)DestroyStubForPid(pid);

    return CAMERA_OK;
}

int HCameraServiceStub::HandleNotifyCameraState(MessageParcel& data)
{
    std::string cameraId = data.ReadString();
    int32_t state = data.ReadInt32();

    int ret = NotifyCameraState(cameraId, state);
    CHECK_ERROR_PRINT_LOG(ret != ERR_NONE, "HCameraServiceStub HandleNotifyCameraState failed : %{public}d", ret);

    return ret;
}

int HCameraServiceStub::HandleSetPeerCallback(MessageParcel& data)
{
    auto remoteObject = data.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObject == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleSetPeerCallback Callback is null");

    MEDIA_INFO_LOG("HandleSetPeerCallback get callback");
    CHECK_ERROR_PRINT_LOG(remoteObject == nullptr, "HandleSetPeerCallback get null remoteObject");
    auto callback = iface_cast<ICameraBroker>(remoteObject);
    CHECK_ERROR_PRINT_LOG(callback == nullptr, "HandleSetPeerCallback get null callback");

    return SetPeerCallback(callback);
}

int HCameraServiceStub::HandleUnsetPeerCallback(MessageParcel& data)
{
    MEDIA_INFO_LOG("HandleUnsetPeerCallback called");
    return UnsetPeerCallback();
}

int HCameraServiceStub::HandleProxyForFreeze(MessageParcel& data, MessageParcel& reply)
{
    std::set<int32_t> pidList;
    int32_t size = data.ReadInt32();
    int32_t maxSize = 100;
    CHECK_ERROR_RETURN_RET(size >= maxSize, CAMERA_UNKNOWN_ERROR);

    for (int32_t i = 0; i < size; i++) {
        pidList.insert(data.ReadInt32());
    }
    bool isProxy = data.ReadBool();
    MEDIA_DEBUG_LOG("isProxy value: %{public}d", isProxy);
    int ret = ProxyForFreeze(pidList, isProxy);
    reply.WriteInt32(static_cast<int32_t>(ret));

    return ret;
}

int HCameraServiceStub::HandleResetAllFreezeStatus(MessageParcel& data, MessageParcel& reply)
{
    return ResetAllFreezeStatus();
}

int HCameraServiceStub::HandleGetDmDeviceInfo(MessageParcel& data, MessageParcel& reply)
{
    CHECK_ERROR_RETURN_RET(!CheckSystemApp(), CAMERA_NO_PERMISSION);

    std::vector<std::string> deviceInfos;
    int ret = GetDmDeviceInfo(deviceInfos);
    CHECK_ERROR_RETURN_RET_LOG(!reply.WriteStringVector(deviceInfos), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleGetDmDeviceInfo WriteStringVector failed");

    return ret;
}

int HCameraServiceStub::HandleGetCameraOutputStatus(MessageParcel& data, MessageParcel& reply)
{
    int32_t pid = data.ReadInt32();
    int32_t status = 0;
    int ret = GetCameraOutputStatus(pid, status);
    CHECK_ERROR_RETURN_RET_LOG(!reply.WriteInt32(status), IPC_STUB_WRITE_PARCEL_ERR,
        "GetCameraOutputStatus failed");
    return ret;
}

int HCameraServiceStub::HandleRequireMemorySize(MessageParcel& data, MessageParcel& reply)
{
    CHECK_ERROR_RETURN_RET(!CheckSystemApp(), CAMERA_NO_PERMISSION);
    int32_t memSize = data.ReadInt32();
    int ret = RequireMemorySize(memSize);
    CHECK_ERROR_RETURN_RET_LOG(ret != ERR_NONE, ret, "RequireMemorySize failed : %{public}d", ret);
    return ret;
}
} // namespace CameraStandard
} // namespace OHOS
