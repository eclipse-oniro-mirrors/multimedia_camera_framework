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
#include "metadata_utils.h"
#include "remote_request_code.h"
#include "input/camera_death_recipient.h"
#include "hcamera_service.h"
#include "input/i_standard_camera_listener.h"
#include "ipc_skeleton.h"
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"

namespace OHOS {
namespace CameraStandard {
HCameraServiceStub::HCameraServiceStub()
{
    RegisterMethod();
    deathRecipientMap_.Clear();
    cameraListenerMap_.Clear();
    MEDIA_DEBUG_LOG("0x%{public}06" PRIXPTR " Instances create",
        (POINTER_MASK & reinterpret_cast<uintptr_t>(this)));
}

HCameraServiceStub::~HCameraServiceStub()
{
    MEDIA_DEBUG_LOG("0x%{public}06" PRIXPTR " Instances destroy",
        (POINTER_MASK & reinterpret_cast<uintptr_t>(this)));
}

int HCameraServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DisableJeMalloc();
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        return -1;
    }
    const int TIME_OUT_SECONDS = 10;
    int32_t id = HiviewDFX::XCollie::GetInstance().SetTimer(
        "CameraServiceStub", TIME_OUT_SECONDS, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
    int32_t ret = CheckRequestCode(code, data, reply, option);
    HiviewDFX::XCollie::GetInstance().CancelTimer(id);
    return ret;
}

void HCameraServiceStub::RegisterMethod()
{
    methodFactory[CAMERA_SERVICE_MUTE_CAMERA] = &HCameraServiceStub::HandleMuteCamera;
    methodFactory[CAMERA_SERVICE_SET_MUTE_CALLBACK] = &HCameraServiceStub::HandleSetMuteCallback;
    methodFactory[CAMERA_SERVICE_IS_CAMERA_MUTED] = &HCameraServiceStub::HandleIsCameraMuted;
    methodFactory[CAMERA_SERVICE_CREATE_DEVICE] = &HCameraServiceStub::HandleCreateCameraDevice;
    methodFactory[CAMERA_SERVICE_SET_CALLBACK] = &HCameraServiceStub::HandleSetCallback;
    methodFactory[CAMERA_SERVICE_GET_CAMERAS] = &HCameraServiceStub::HandleGetCameras;
    methodFactory[CAMERA_SERVICE_CREATE_CAPTURE_SESSION] = &HCameraServiceStub::HandleCreateCaptureSession;
    methodFactory[CAMERA_SERVICE_CREATE_PHOTO_OUTPUT] = &HCameraServiceStub::HandleCreatePhotoOutput;
    methodFactory[CAMERA_SERVICE_CREATE_PREVIEW_OUTPUT] = &HCameraServiceStub::HandleCreatePreviewOutput;
    methodFactory[CAMERA_SERVICE_CREATE_DEFERRED_PREVIEW_OUTPUT] =
        &HCameraServiceStub::HandleCreateDeferredPreviewOutput;
    methodFactory[CAMERA_SERVICE_CREATE_METADATA_OUTPUT] = &HCameraServiceStub::HandleCreateMetadataOutput;
    methodFactory[CAMERA_SERVICE_CREATE_VIDEO_OUTPUT] = &HCameraServiceStub::HandleCreateVideoOutput;
    methodFactory[CAMERA_SERVICE_SET_LISTENER_OBJ] = &HCameraServiceStub::SetListenerObject;
}

int32_t HCameraServiceStub::CheckRequestCode(
    const uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    typedef std::map<uint32_t, HandleMethod>::const_iterator Iterator;
    Iterator iter = methodFactory.find(code);
    if (methodFactory.end() == iter) {
        MEDIA_ERR_LOG("HCameraServiceStub request code %{public}u not handled", code);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    HandleMethod method = iter->second;
    return (this->*method)(data, reply);
}

int HCameraServiceStub::HandleGetCameras(MessageParcel &data, MessageParcel &reply)
{
    std::vector<std::string> cameraIds;
    std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> cameraAbilityList;

    int errCode = GetCameras(cameraIds, cameraAbilityList);
    if (!reply.WriteStringVector(cameraIds)) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleGetCameras WriteStringVector failed");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    int count = static_cast<int>(cameraAbilityList.size());
    if (!reply.WriteInt32(count)) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleGetCameras Write vector size failed");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    for (auto cameraAbility : cameraAbilityList) {
        if (!(OHOS::Camera::MetadataUtils::EncodeCameraMetadata(cameraAbility, reply))) {
            MEDIA_ERR_LOG("HCameraServiceStub HandleGetCameras write ability failed");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
    }

    return errCode;
}

int HCameraServiceStub::HandleCreateCameraDevice(MessageParcel &data, MessageParcel &reply)
{
    std::string cameraId = data.ReadString();
    sptr<ICameraDeviceService> device = nullptr;

    int errCode = CreateCameraDevice(cameraId, device);
    if (errCode != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleCreateCameraDevice Create camera device failed : %{public}d", errCode);
        return errCode;
    }

    if (!reply.WriteRemoteObject(device->AsObject())) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleCreateCameraDevice Write CameraDevice obj failed");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return errCode;
}

int HCameraServiceStub::HandleMuteCamera(MessageParcel &data, MessageParcel &reply)
{
    bool muteMode = data.ReadBool();
    MEDIA_DEBUG_LOG("HCameraServiceStub HandleMuteCamera read muteMode : %{public}d", muteMode);

    int32_t ret = MuteCamera(muteMode);
    MEDIA_INFO_LOG("HCameraServiceStub HandleMuteCamera MuteCamera result: %{public}d", ret);
    return ret;
}

int HCameraServiceStub::HandleIsCameraMuted(MessageParcel &data, MessageParcel &reply)
{
    bool isMuted = false;
    int32_t ret = IsCameraMuted(isMuted);
    MEDIA_INFO_LOG("HCameraServiceStub HandleIsCameraMuted result: %{public}d, isMuted: %{public}d", ret, isMuted);
    if (!reply.WriteBool(isMuted)) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleIsCameraMuted Write isMuted failed");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ret;
}

int HCameraServiceStub::HandleSetCallback(MessageParcel &data, MessageParcel &reply)
{
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleSetCallback CameraServiceCallback is null");
        return IPC_STUB_INVALID_DATA_ERR;
    }

    auto callback = iface_cast<ICameraServiceCallback>(remoteObject);

    return SetCallback(callback);
}

int HCameraServiceStub::HandleSetMuteCallback(MessageParcel &data, MessageParcel &reply)
{
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleSetMuteCallback CameraMuteServiceCallback is null");
        return IPC_STUB_INVALID_DATA_ERR;
    }

    auto callback = iface_cast<ICameraMuteServiceCallback>(remoteObject);

    return SetMuteCallback(callback);
}

int HCameraServiceStub::HandleCreateCaptureSession(MessageParcel &data, MessageParcel &reply)
{
    sptr<ICaptureSession> session = nullptr;

    int errCode = CreateCaptureSession(session);
    if (errCode != ERR_NONE) {
        MEDIA_ERR_LOG("HandleCreateCaptureSession CreateCaptureSession failed : %{public}d", errCode);
        return errCode;
    }

    if (!reply.WriteRemoteObject(session->AsObject())) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleCreateCaptureSession Write CaptureSession obj failed");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return errCode;
}

int HCameraServiceStub::HandleCreatePhotoOutput(MessageParcel &data, MessageParcel &reply)
{
    sptr<IStreamCapture> photoOutput = nullptr;
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();

    if (remoteObj == nullptr) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleCreatePhotoOutput BufferProducer is null");
        return IPC_STUB_INVALID_DATA_ERR;
    }

    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    int32_t format = data.ReadInt32();
    int32_t width = data.ReadInt32();
    int32_t height = data.ReadInt32();
    int errCode = CreatePhotoOutput(producer, format, width, height, photoOutput);
    if (errCode != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceStub::HandleCreatePhotoOutput Create photo output failed : %{public}d", errCode);
        return errCode;
    }

    if (!reply.WriteRemoteObject(photoOutput->AsObject())) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleCreateCameraDevice Write photoOutput obj failed");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return errCode;
}

int HCameraServiceStub::HandleCreatePreviewOutput(MessageParcel &data, MessageParcel &reply)
{
    sptr<IStreamRepeat> previewOutput = nullptr;

    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    if (remoteObj == nullptr) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleCreatePreviewOutput BufferProducer is null");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    int32_t format = data.ReadInt32();
    int32_t width = data.ReadInt32();
    int32_t height = data.ReadInt32();
    MEDIA_INFO_LOG("CreatePreviewOutput, format: %{public}d, width: %{public}d, height: %{public}d",
                   format, width, height);
    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    int errCode = CreatePreviewOutput(producer, format, width, height, previewOutput);
    if (errCode != ERR_NONE) {
        MEDIA_ERR_LOG("HandleCreatePreviewOutput CreatePreviewOutput failed : %{public}d", errCode);
        return errCode;
    }
    if (!reply.WriteRemoteObject(previewOutput->AsObject())) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleCreatePreviewOutput Write previewOutput obj failed");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return errCode;
}

int HCameraServiceStub::HandleCreateDeferredPreviewOutput(MessageParcel &data, MessageParcel &reply)
{
    sptr<IStreamRepeat> previewOutput = nullptr;

    int32_t format = data.ReadInt32();
    int32_t width = data.ReadInt32();
    int32_t height = data.ReadInt32();
    MEDIA_INFO_LOG("CreatePreviewOutput, format: %{public}d, width: %{public}d, height: %{public}d",
                   format, width, height);

    int errCode = CreateDeferredPreviewOutput(format, width, height, previewOutput);
    if (errCode != ERR_NONE) {
        MEDIA_ERR_LOG("HandleCreatePreviewOutput CreatePreviewOutput failed : %{public}d", errCode);
        return errCode;
    }
    if (!reply.WriteRemoteObject(previewOutput->AsObject())) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleCreatePreviewOutput Write previewOutput obj failed");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return errCode;
}

int HCameraServiceStub::HandleCreateMetadataOutput(MessageParcel &data, MessageParcel &reply)
{
    sptr<IStreamMetadata> metadataOutput = nullptr;
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();

    if (remoteObj == nullptr) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleCreateMetadataOutput BufferProducer is null");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    int32_t format = data.ReadInt32();
    int errCode = CreateMetadataOutput(producer, format, metadataOutput);
    if (errCode != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleCreateMetadataOutput CreateMetadataOutput failed : %{public}d",
                      errCode);
        return errCode;
    }
    if (!reply.WriteRemoteObject(metadataOutput->AsObject())) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleCreateMetadataOutput Write metadataOutput obj failed");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return errCode;
}

int HCameraServiceStub::HandleCreateVideoOutput(MessageParcel &data, MessageParcel &reply)
{
    sptr<IStreamRepeat> videoOutput = nullptr;
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();

    if (remoteObj == nullptr) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleCreateVideoOutput BufferProducer is null");
        return IPC_STUB_INVALID_DATA_ERR;
    }

    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    int32_t format = data.ReadInt32();
    int32_t width = data.ReadInt32();
    int32_t height = data.ReadInt32();
    int errCode = CreateVideoOutput(producer, format, width, height, videoOutput);
    if (errCode != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleCreateVideoOutput CreateVideoOutput failed : %{public}d", errCode);
        return errCode;
    }
    if (!reply.WriteRemoteObject(videoOutput->AsObject())) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleCreateVideoOutput Write videoOutput obj failed");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

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

int HCameraServiceStub::SetListenerObject(const sptr<IRemoteObject> &object)
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
    CHECK_AND_RETURN_RET_LOG(cameraListener != nullptr, CAMERA_ALLOC_ERROR,
        "failed to convert IStandardCameraListener");
    sptr<CameraDeathRecipient> deathRecipient = new(std::nothrow) CameraDeathRecipient(pid);
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

int HCameraServiceStub::SetListenerObject(MessageParcel &data, MessageParcel &reply)
{
    int errCode = -1;
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    (void)reply.WriteInt32(SetListenerObject(object));
    return errCode;
}
} // namespace CameraStandard
} // namespace OHOS
