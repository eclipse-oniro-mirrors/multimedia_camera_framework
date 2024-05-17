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
#include "hcamera_service.h"
#include "input/camera_death_recipient.h"
#include "input/i_standard_camera_listener.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"

namespace OHOS {
namespace CameraStandard {
HCameraServiceStub::HCameraServiceStub()
{
    deathRecipientMap_.Clear();
    cameraListenerMap_.Clear();
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
    CHECK_AND_RETURN_RET(data.ReadInterfaceToken() == GetDescriptor(), errCode);
    const int TIME_OUT_SECONDS = 10;
    int32_t id = HiviewDFX::XCollie::GetInstance().SetTimer(
        "CameraServiceStub", TIME_OUT_SECONDS, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
    switch (code) {
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_DEVICE): {
            errCode = HCameraServiceStub::HandleCreateCameraDevice(data, reply);
            break;
        }
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_CALLBACK):
            errCode = HCameraServiceStub::HandleSetCallback(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_MUTE_CALLBACK):
            errCode = HCameraServiceStub::HandleSetMuteCallback(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_SET_TORCH_CALLBACK):
            errCode = HCameraServiceStub::HandleSetTorchCallback(data, reply);
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
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_PHOTO_OUTPUT):
            errCode = HCameraServiceStub::HandleCreatePhotoOutput(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_PREVIEW_OUTPUT): {
            errCode = HCameraServiceStub::HandleCreatePreviewOutput(data, reply);
            break;
        }
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_CREATE_DEFERRED_PREVIEW_OUTPUT):
            errCode = HCameraServiceStub::HandleCreateDeferredPreviewOutput(data, reply);
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
        case static_cast<uint32_t>(CameraServiceInterfaceCode::CAMERA_SERVICE_IS_CAMERA_MUTED):
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
        case static_cast<uint32_t>(CameraServiceDHInterfaceCode::CAMERA_SERVICE_ALLOW_OPEN_BY_OHSIDE):
            errCode = HCameraServiceStub::HandleAllowOpenByOHSide(data, reply);
            break;
        case static_cast<uint32_t>(CameraServiceDHInterfaceCode::CAMERA_SERVICE_NOTIFY_CAMERA_STATE):
            errCode = HCameraServiceStub::HandleNotifyCameraState(data);
            break;
        case static_cast<uint32_t>(CameraServiceDHInterfaceCode::CAMERA_SERVICE_SET_PEER_CALLBACK):
            errCode = HCameraServiceStub::HandleSetPeerCallback(data);
            break;
        default:
            MEDIA_ERR_LOG("HCameraServiceStub request code %{public}d not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }
    HiviewDFX::XCollie::GetInstance().CancelTimer(id);

    return errCode;
}

int HCameraServiceStub::HandleGetCameras(MessageParcel& data, MessageParcel& reply)
{
    std::vector<std::string> cameraIds;
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList;

    int errCode = GetCameras(cameraIds, cameraAbilityList);
    CHECK_AND_RETURN_RET_LOG(reply.WriteStringVector(cameraIds), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleGetCameras WriteStringVector failed");

    int count = static_cast<int>(cameraAbilityList.size());
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(count), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleGetCameras Write vector size failed");

    for (auto cameraAbility : cameraAbilityList) {
        if (!(OHOS::Camera::MetadataUtils::EncodeCameraMetadata(cameraAbility, reply))) {
            MEDIA_ERR_LOG("HCameraServiceStub HandleGetCameras write ability failed");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
    }

    return errCode;
}

int HCameraServiceStub::HandleGetCameraIds(MessageParcel& data, MessageParcel& reply)
{
    std::vector<std::string> cameraIds;
    int errCode = GetCameraIds(cameraIds);
    CHECK_AND_RETURN_RET_LOG(reply.WriteStringVector(cameraIds), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleGetCameras WriteStringVector failed");

    int count = static_cast<int>(cameraIds.size());
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(count), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleGetCameras Write vector size failed");

    return errCode;
}

int HCameraServiceStub::HandleGetCameraAbility(MessageParcel& data, MessageParcel& reply)
{
    std::string cameraId = data.ReadString();
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    int errCode = GetCameraAbility(cameraId, cameraAbility);
    if (!(OHOS::Camera::MetadataUtils::EncodeCameraMetadata(cameraAbility, reply))) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleGetCameras write ability failed");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return errCode;
}

int HCameraServiceStub::HandleCreateCameraDevice(MessageParcel& data, MessageParcel& reply)
{
    std::string cameraId = data.ReadString();
    sptr<ICameraDeviceService> device = nullptr;

    int errCode = CreateCameraDevice(cameraId, device);
    if (errCode != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleCreateCameraDevice Create camera device failed : %{public}d", errCode);
        return errCode;
    }

    CHECK_AND_RETURN_RET_LOG(reply.WriteRemoteObject(device->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleCreateCameraDevice Write CameraDevice obj failed");

    return errCode;
}

int HCameraServiceStub::HandleMuteCamera(MessageParcel& data, MessageParcel& reply)
{
    bool muteMode = data.ReadBool();
    MEDIA_DEBUG_LOG("HCameraServiceStub HandleMuteCamera read muteMode : %{public}d", muteMode);

    int32_t ret = MuteCamera(muteMode);
    MEDIA_INFO_LOG("HCameraServiceStub HandleMuteCamera MuteCamera result: %{public}d", ret);
    return ret;
}

int HCameraServiceStub::HandlePrelaunchCamera(MessageParcel& data, MessageParcel& reply)
{
    MEDIA_DEBUG_LOG("HCameraServiceStub HandlePrelaunchCamera enter");
    int32_t ret = PrelaunchCamera();
    MEDIA_INFO_LOG("HCameraServiceStub HandlePrelaunchCamera result: %{public}d", ret);
    return ret;
}

int HCameraServiceStub::HandlePreSwitchCamera(MessageParcel& data, MessageParcel& reply)
{
    MEDIA_DEBUG_LOG("HCameraServiceStub HandlePreSwitchCamera enter");
    auto cameraId = data.ReadString();
    if (cameraId.empty() || cameraId.length() > PATH_MAX) {
        return CAMERA_INVALID_ARG;
    }
    int32_t ret = PreSwitchCamera(cameraId);
    MEDIA_INFO_LOG("HCameraServiceStub HandlePreSwitchCamera result: %{public}d", ret);
    return ret;
}

int HCameraServiceStub::HandleSetPrelaunchConfig(MessageParcel& data, MessageParcel& reply)
{
    MEDIA_DEBUG_LOG("HCameraServiceStub HandleSetPrelaunchConfig enter");
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
    bool isMuted = false;
    int32_t ret = IsCameraMuted(isMuted);
    MEDIA_INFO_LOG("HCameraServiceStub HandleIsCameraMuted result: %{public}d, isMuted: %{public}d", ret, isMuted);
    CHECK_AND_RETURN_RET_LOG(reply.WriteBool(isMuted), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleIsCameraMuted Write isMuted failed");
    return ret;
}

int HCameraServiceStub::HandleSetCallback(MessageParcel& data, MessageParcel& reply)
{
    auto remoteObject = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObject != nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleSetCallback CameraServiceCallback is null");

    auto callback = iface_cast<ICameraServiceCallback>(remoteObject);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCameraServiceStub HandleSetCallback callback is null");
    return SetCallback(callback);
}

int HCameraServiceStub::HandleSetMuteCallback(MessageParcel& data, MessageParcel& reply)
{
    auto remoteObject = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObject != nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleSetMuteCallback CameraMuteServiceCallback is null");

    auto callback = iface_cast<ICameraMuteServiceCallback>(remoteObject);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCameraServiceStub HandleSetMuteCallback callback is null");
    return SetMuteCallback(callback);
}

int HCameraServiceStub::HandleSetTorchCallback(MessageParcel& data, MessageParcel& reply)
{
    auto remoteObject = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObject != nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleSetTorchCallback TorchServiceCallback is null");

    auto callback = iface_cast<ITorchServiceCallback>(remoteObject);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCameraServiceStub HandleSetTorchCallback callback is null");
    return SetTorchCallback(callback);
}

int HCameraServiceStub::HandleCreateCaptureSession(MessageParcel& data, MessageParcel& reply)
{
    sptr<ICaptureSession> session = nullptr;

    int32_t operationMode = data.ReadInt32();
    int errCode = CreateCaptureSession(session, operationMode);
    if (errCode != ERR_NONE) {
        MEDIA_ERR_LOG("HandleCreateCaptureSession CreateCaptureSession failed : %{public}d", errCode);
        return errCode;
    }

    CHECK_AND_RETURN_RET_LOG(reply.WriteRemoteObject(session->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleCreateCaptureSession Write CaptureSession obj failed");

    return errCode;
}

int HCameraServiceStub::HandleCreateDeferredPhotoProcessingSession(MessageParcel &data, MessageParcel &reply)
{
    sptr<DeferredProcessing::IDeferredPhotoProcessingSession> session = nullptr;

    int32_t userId = data.ReadInt32();
    auto remoteObject = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObject != nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HandleCreateDeferredPhotoProcessingSession DeferredPhotoProcessingSessionCallback is null");

    auto callback = iface_cast<DeferredProcessing::IDeferredPhotoProcessingSessionCallback>(remoteObject);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCameraServiceStub HandleCreateDeferredPhotoProcessingSession callback is null");
    int errCode = CreateDeferredPhotoProcessingSession(userId, callback, session);
    if (errCode != ERR_NONE) {
        MEDIA_ERR_LOG("HandleCreateDeferredPhotoProcessingSession create failed : %{public}d", errCode);
        return errCode;
    }

    CHECK_AND_RETURN_RET_LOG(reply.WriteRemoteObject(session->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        " HandleCreateDeferredPhotoProcessingSession Write HandleCreateDeferredPhotoProcessingSession obj failed");

    return errCode;
}

int HCameraServiceStub::HandleCreatePhotoOutput(MessageParcel& data, MessageParcel& reply)
{
    sptr<IStreamCapture> photoOutput = nullptr;
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();

    CHECK_AND_RETURN_RET_LOG(remoteObj != nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleCreatePhotoOutput BufferProducer is null");

    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    CHECK_AND_RETURN_RET_LOG(producer != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCameraServiceStub HandleCreatePhotoOutput producer is null");
    int32_t format = data.ReadInt32();
    int32_t width = data.ReadInt32();
    int32_t height = data.ReadInt32();
    int errCode = CreatePhotoOutput(producer, format, width, height, photoOutput);
    if (errCode != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceStub::HandleCreatePhotoOutput Create photo output failed : %{public}d", errCode);
        return errCode;
    }

    CHECK_AND_RETURN_RET_LOG(reply.WriteRemoteObject(photoOutput->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleCreateCameraDevice Write photoOutput obj failed");

    return errCode;
}

int HCameraServiceStub::HandleCreatePreviewOutput(MessageParcel& data, MessageParcel& reply)
{
    sptr<IStreamRepeat> previewOutput = nullptr;

    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObj != nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleCreatePreviewOutput BufferProducer is null");
    int32_t format = data.ReadInt32();
    int32_t width = data.ReadInt32();
    int32_t height = data.ReadInt32();
    MEDIA_INFO_LOG(
        "CreatePreviewOutput, format: %{public}d, width: %{public}d, height: %{public}d", format, width, height);
    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    CHECK_AND_RETURN_RET_LOG(producer != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCameraServiceStub HandleCreatePreviewOutput producer is null");
    int errCode = CreatePreviewOutput(producer, format, width, height, previewOutput);
    if (errCode != ERR_NONE) {
        MEDIA_ERR_LOG("HandleCreatePreviewOutput CreatePreviewOutput failed : %{public}d", errCode);
        return errCode;
    }
    CHECK_AND_RETURN_RET_LOG(reply.WriteRemoteObject(previewOutput->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleCreatePreviewOutput Write previewOutput obj failed");
    return errCode;
}

int HCameraServiceStub::HandleCreateDeferredPreviewOutput(MessageParcel& data, MessageParcel& reply)
{
    sptr<IStreamRepeat> previewOutput = nullptr;

    int32_t format = data.ReadInt32();
    int32_t width = data.ReadInt32();
    int32_t height = data.ReadInt32();
    MEDIA_INFO_LOG(
        "CreatePreviewOutput, format: %{public}d, width: %{public}d, height: %{public}d", format, width, height);

    int errCode = CreateDeferredPreviewOutput(format, width, height, previewOutput);
    if (errCode != ERR_NONE) {
        MEDIA_ERR_LOG("HandleCreatePreviewOutput CreatePreviewOutput failed : %{public}d", errCode);
        return errCode;
    }
    CHECK_AND_RETURN_RET_LOG(reply.WriteRemoteObject(previewOutput->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleCreatePreviewOutput Write previewOutput obj failed");
    return errCode;
}

int HCameraServiceStub::HandleCreateMetadataOutput(MessageParcel& data, MessageParcel& reply)
{
    sptr<IStreamMetadata> metadataOutput = nullptr;
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();

    CHECK_AND_RETURN_RET_LOG(remoteObj != nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleCreateMetadataOutput BufferProducer is null");
    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    CHECK_AND_RETURN_RET_LOG(producer != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCameraServiceStub HandleCreateMetadataOutput producer is null");
    int32_t format = data.ReadInt32();
    int errCode = CreateMetadataOutput(producer, format, metadataOutput);
    if (errCode != ERR_NONE) {
        MEDIA_ERR_LOG(
            "HCameraServiceStub HandleCreateMetadataOutput CreateMetadataOutput failed : %{public}d", errCode);
        return errCode;
    }
    CHECK_AND_RETURN_RET_LOG(reply.WriteRemoteObject(metadataOutput->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleCreateMetadataOutput Write metadataOutput obj failed");
    return errCode;
}

int HCameraServiceStub::HandleCreateVideoOutput(MessageParcel& data, MessageParcel& reply)
{
    sptr<IStreamRepeat> videoOutput = nullptr;
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();

    CHECK_AND_RETURN_RET_LOG(remoteObj != nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleCreateVideoOutput BufferProducer is null");

    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    CHECK_AND_RETURN_RET_LOG(producer != nullptr, IPC_STUB_INVALID_DATA_ERR,
                             "HCameraServiceStub HandleCreateVideoOutput producer is null");
    int32_t format = data.ReadInt32();
    int32_t width = data.ReadInt32();
    int32_t height = data.ReadInt32();
    int errCode = CreateVideoOutput(producer, format, width, height, videoOutput);
    if (errCode != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleCreateVideoOutput CreateVideoOutput failed : %{public}d", errCode);
        return errCode;
    }
    CHECK_AND_RETURN_RET_LOG(reply.WriteRemoteObject(videoOutput->AsObject()), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleCreateVideoOutput Write videoOutput obj failed");

    return errCode;
}

int HCameraServiceStub::HandleSetTorchLevel(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_DEBUG_LOG("HCameraServiceStub HandleSetTorchLevel enter");
    float level = data.ReadFloat();
    int errCode = SetTorchLevel(level);
    MEDIA_INFO_LOG("HCameraServiceStub HandleSetTorchLevel result: %{public}d", errCode);
    return errCode;
}

int32_t HCameraServiceStub::UnSetCallback(pid_t pid)
{
    return CAMERA_OK;
}

int32_t HCameraServiceStub::CloseCameraForDestory(pid_t pid)
{
    return CAMERA_OK;
}

int HCameraServiceStub::DestroyStubForPid(pid_t pid)
{
    sptr<CameraDeathRecipient> deathRecipient = nullptr;
    sptr<IStandardCameraListener> cameraListener = nullptr;
    if (deathRecipientMap_.Find(pid, deathRecipient)) {
        if (deathRecipient != nullptr) {
            deathRecipient->SetNotifyCb(nullptr);
        }
        deathRecipientMap_.Erase(pid);
    }
    if (cameraListenerMap_.Find(pid, cameraListener)) {
        if (cameraListener != nullptr && cameraListener->AsObject() != nullptr && deathRecipient != nullptr) {
            (void)cameraListener->AsObject()->RemoveDeathRecipient(deathRecipient);
        }
        cameraListenerMap_.Erase(pid);
    }
    HCaptureSession::DestroyStubObjectForPid(pid);
    CloseCameraForDestory(pid);
    UnSetCallback(pid);
    return CAMERA_OK;
}

void HCameraServiceStub::ClientDied(pid_t pid)
{
    DisableJeMalloc();
    MEDIA_ERR_LOG("client pid is dead, pid:%{public}d", pid);
    (void)DestroyStubForPid(pid);
}

int HCameraServiceStub::SetListenerObject(const sptr<IRemoteObject>& object)
{
    int errCode = -1;
    sptr<CameraDeathRecipient> deathRecipientTmp = nullptr;
    sptr<IStandardCameraListener> cameraListenerTmp = nullptr;
    pid_t pid = IPCSkeleton::GetCallingPid();
    if (deathRecipientMap_.Find(pid, deathRecipientTmp)) {
        deathRecipientMap_.Erase(pid);
    }
    if (cameraListenerMap_.Find(pid, cameraListenerTmp)) {
        if (cameraListenerTmp != nullptr && cameraListenerTmp->AsObject() != nullptr && deathRecipientTmp != nullptr) {
            (void)cameraListenerTmp->AsObject()->RemoveDeathRecipient(deathRecipientTmp);
        }
        cameraListenerMap_.Erase(pid);
    }
    CHECK_AND_RETURN_RET_LOG(object != nullptr, CAMERA_ALLOC_ERROR, "set listener object is nullptr");
    sptr<IStandardCameraListener> cameraListener = iface_cast<IStandardCameraListener>(object);
    CHECK_AND_RETURN_RET_LOG(
        cameraListener != nullptr, CAMERA_ALLOC_ERROR, "failed to convert IStandardCameraListener");
    sptr<CameraDeathRecipient> deathRecipient = new (std::nothrow) CameraDeathRecipient(pid);
    CHECK_AND_RETURN_RET_LOG(deathRecipient != nullptr, CAMERA_ALLOC_ERROR, "failed to new CameraDeathRecipient");
    deathRecipient->SetNotifyCb(std::bind(&HCameraServiceStub::ClientDied, this, std::placeholders::_1));
    if (cameraListener->AsObject() != nullptr) {
        (void)cameraListener->AsObject()->AddDeathRecipient(deathRecipient);
    }
    MEDIA_DEBUG_LOG("client pid pid:%{public}d", pid);
    cameraListenerMap_.EnsureInsert(pid, cameraListener);
    deathRecipientMap_.EnsureInsert(pid, deathRecipient);
    return errCode;
}

int HCameraServiceStub::SetListenerObject(MessageParcel& data, MessageParcel& reply)
{
    int errCode = -1;
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    (void)reply.WriteInt32(SetListenerObject(object));
    return errCode;
}

int HCameraServiceStub::HandleAllowOpenByOHSide(MessageParcel& data, MessageParcel& reply)
{
    std::string cameraId = data.ReadString();
    int32_t state = data.ReadInt32();
    bool canOpenCamera = false;

    int errCode = AllowOpenByOHSide(cameraId, state, canOpenCamera);
    CHECK_AND_RETURN_RET_LOG(reply.WriteBool(canOpenCamera), IPC_STUB_WRITE_PARCEL_ERR,
        "HCameraServiceStub HandleAllowOpenByOHSide get camera failed");
    return errCode;
}

int HCameraServiceStub::HandleNotifyCameraState(MessageParcel& data)
{
    std::string cameraId = data.ReadString();
    int32_t state = data.ReadInt32();

    int errCode = NotifyCameraState(cameraId, state);
    if (errCode != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleNotifyCameraState failed : %{public}d", errCode);
    }
    return errCode;
}

int HCameraServiceStub::HandleSetPeerCallback(MessageParcel& data)
{
    auto remoteObject = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(remoteObject != nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HCameraServiceStub HandleSetPeerCallback Callback is null");

    MEDIA_INFO_LOG("HandleSetPeerCallback get callback");
    if (remoteObject == nullptr) {
        MEDIA_ERR_LOG("HandleSetPeerCallback get null callback");
    }
    auto callback = iface_cast<ICameraBroker>(remoteObject);
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HandleSetPeerCallback get null callback");
    }
    return SetPeerCallback(callback);
}
} // namespace CameraStandard
} // namespace OHOS
