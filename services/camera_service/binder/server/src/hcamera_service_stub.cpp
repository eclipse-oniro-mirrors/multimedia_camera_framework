/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "media_log.h"
#include "metadata_utils.h"
#include "remote_request_code.h"

namespace OHOS {
namespace CameraStandard {
int HCameraServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int errCode = ERR_NONE;

    switch (code) {
        case CAMERA_SERVICE_CREATE_DEVICE:
            errCode = HCameraServiceStub::HandleCreateCameraDevice(data, reply);
            break;
        case CAMERA_SERVICE_SET_CALLBACK:
            errCode = HCameraServiceStub::HandleSetCallback(data);
            break;
        case CAMERA_SERVICE_GET_CAMERAS:
            errCode = HCameraServiceStub::HandleGetCameras(reply);
            break;
        case CAMERA_SERVICE_CREATE_CAPTURE_SESSION:
            errCode = HCameraServiceStub::HandleCreateCaptureSession(reply);
            break;
        case CAMERA_SERVICE_CREATE_PHOTO_OUTPUT:
            errCode = HCameraServiceStub::HandleCreatePhotoOutput(data, reply);
            break;
        case CAMERA_SERVICE_CREATE_PREVIEW_OUTPUT:
            errCode = HCameraServiceStub::HandleCreatePreviewOutput(data, reply);
            break;
        case CAMERA_SERVICE_CREATE_PREVIEW_OUTPUT_CUSTOM_SIZE:
            errCode = HCameraServiceStub::HandleCreatePreviewOutputCustomSize(data, reply);
            break;
        case CAMERA_SERVICE_CREATE_VIDEO_OUTPUT:
            errCode = HCameraServiceStub::HandleCreateVideoOutput(data, reply);
            break;
        default:
            MEDIA_ERR_LOG("HCameraServiceStub request code %{public}d not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }

    return errCode;
}

int HCameraServiceStub::HandleGetCameras(MessageParcel& reply)
{
    std::vector<std::string> cameraIds;
    std::vector<std::shared_ptr<CameraMetadata>> cameraAbilityList;

    int errCode = GetCameras(cameraIds, cameraAbilityList);
    if (!reply.WriteStringVector(cameraIds)) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleGetCameras WriteStringVector failed");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    int count = cameraAbilityList.size();
    if (!reply.WriteInt32(count)) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleGetCameras Write vector size failed");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    for (auto cameraAbility : cameraAbilityList) {
        bool bRet = MetadataUtils::EncodeCameraMetadata(cameraAbility, reply);
        if (!bRet) {
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

int HCameraServiceStub::HandleSetCallback(MessageParcel &data)
{
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleSetCallback CameraServiceCallback is null");
        return IPC_STUB_INVALID_DATA_ERR;
    }

    auto callback = iface_cast<ICameraServiceCallback>(remoteObject);

    return SetCallback(callback);
}

int HCameraServiceStub::HandleCreateCaptureSession(MessageParcel &reply)
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
    int errCode = CreatePhotoOutput(producer, photoOutput);
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

    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    int errCode = CreatePreviewOutput(producer, previewOutput);
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

int HCameraServiceStub::HandleCreatePreviewOutputCustomSize(MessageParcel &data, MessageParcel &reply)
{
    sptr<IStreamRepeat> previewOutput = nullptr;

    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    if (remoteObj == nullptr) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleCreatePreviewOutput BufferProducer is null");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    int32_t width = data.ReadInt32();
    int32_t height = data.ReadInt32();
    MEDIA_INFO_LOG("CreatePreviewOutput with custom sizes, width: %{public}d, height: %{public}d", width, height);
    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    int errCode = CreateCustomPreviewOutput(producer, width, height, previewOutput);
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

int HCameraServiceStub::HandleCreateVideoOutput(MessageParcel &data, MessageParcel &reply)
{
    sptr<IStreamRepeat> videoOutput = nullptr;
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();

    if (remoteObj == nullptr) {
        MEDIA_ERR_LOG("HCameraServiceStub HandleCreateVideoOutput BufferProducer is null");
        return IPC_STUB_INVALID_DATA_ERR;
    }

    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    int errCode = CreateVideoOutput(producer, videoOutput);
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
} // namespace CameraStandard
} // namespace OHOS
