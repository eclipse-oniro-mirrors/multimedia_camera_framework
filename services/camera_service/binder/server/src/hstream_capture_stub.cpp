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

#include "hstream_capture_stub.h"
#include "camera_dynamic_loader.h"
#include "camera_server_photo_proxy.h"
#include "camera_log.h"
#include "camera_photo_proxy.h"
#include "camera_service_ipc_interface_code.h"
#include "camera_util.h"
#include "metadata_utils.h"
#include "picture_proxy.h"

namespace OHOS {
namespace CameraStandard {
int HStreamCaptureStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DisableJeMalloc();
    int errCode = -1;

    CHECK_ERROR_RETURN_RET(data.ReadInterfaceToken() != GetDescriptor(), errCode);
    errCode = OperatePermissionCheck(code);
    CHECK_ERROR_RETURN_RET(errCode != CAMERA_OK, errCode);
    switch (code) {
        case static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_START):
            errCode = HStreamCaptureStub::HandleCapture(data);
            break;
        case static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_CANCEL):
            errCode = CancelCapture();
            break;
        case static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_CONFIRM):
            errCode = HStreamCaptureStub::HandleConfirmCapture(data);
            break;
        case static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_SET_CALLBACK):
            errCode = HStreamCaptureStub::HandleSetCallback(data);
            break;
        case static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_UNSET_CALLBACK):
            errCode = UnSetCallback();
            break;
        case static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_RELEASE):
            errCode = Release();
            break;
        case static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_SERVICE_SET_THUMBNAIL):
            errCode = HandleSetThumbnail(data);
            break;
        case static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_ENABLE_RAW_DELIVERY):
            errCode = HandleEnableRawDelivery(data);
            break;
        case static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_ENABLE_MOVING_PHOTO):
            errCode = HandleEnableMovingPhoto(data);
            break;
        case static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_SERVICE_ENABLE_DEFERREDTYPE):
            errCode = HandleEnableDeferredType(data);
            break;
        case static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_GET_DEFERRED_PHOTO):
            errCode = IsDeferredPhotoEnabled();
            break;
        case static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_GET_DEFERRED_VIDEO):
            errCode = IsDeferredVideoEnabled();
            break;
        case static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_SET_VIDEO_CODEC_TYPE):
            errCode = HandleSetMovingPhotoVideoCodecType(data);
            break;
        case static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_SET_BUFFER_PRODUCER_INFO):
            errCode = HandleSetBufferProducerInfo(data);
            break;
        case static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_PHOTO_ROTATION):
            errCode = HandleSetCameraPhotoRotation(data);
            break;
        case static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_ADD_MEDIA_LIBRARY_PHOTO_PROXY):
            errCode = HandleAddMediaLibraryPhotoProxy(data);
            break;
        case static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_CAPTURE_DFX):
            errCode = HandleAcquireBufferToPrepareProxy(data);
            break;
        case static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_ENABLE_OFFLINE_PHOTO):
            errCode = HandleEnableOfflinePhoto(data);
            break;
        case static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_CREATE_MEDIA_LIBRARY_MANAGER):
            errCode = HandleCreateMediaLibrary(data, reply);
            break;
        case static_cast<uint32_t>(
            StreamCaptureInterfaceCode::CAMERA_STREAM_CREATE_MEDIA_LIBRARY_MANAGER_PICTURE):
            errCode = HandleCreateMediaLibraryForPicture(data, reply);
            break;
        default:
            MEDIA_ERR_LOG("HStreamCaptureStub request code %{public}u not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }

    return errCode;
}

int32_t HStreamCaptureStub::HandleCapture(MessageParcel &data)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = nullptr;
    OHOS::Camera::MetadataUtils::DecodeCameraMetadata(data, metadata);

    return Capture(metadata);
}

int32_t HStreamCaptureStub::HandleConfirmCapture(MessageParcel &data)
{
    CHECK_ERROR_RETURN_RET(!CheckSystemApp(), CAMERA_NO_PERMISSION);
    return ConfirmCapture();
}

int32_t HStreamCaptureStub::HandleSetThumbnail(MessageParcel &data)
{
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObj == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HStreamCaptureStub HandleCreatePhotoOutput BufferProducer is null");
    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HStreamCaptureStub HandleSetThumbnail producer is null");
    bool isEnabled = data.ReadBool();
    int32_t ret = SetThumbnail(isEnabled, producer);
    MEDIA_DEBUG_LOG("HStreamCaptureStub HandleSetThumbnail result: %{public}d", ret);
    return ret;
}

int32_t HStreamCaptureStub::HandleEnableRawDelivery(MessageParcel &data)
{
    bool enabled = data.ReadBool();
    int32_t ret = EnableRawDelivery(enabled);
    MEDIA_DEBUG_LOG("HStreamCaptureStub HandleEnableRawDelivery result: %{public}d", ret);
    return ret;
}

int32_t HStreamCaptureStub::HandleEnableMovingPhoto(MessageParcel &data)
{
    bool enabled = data.ReadBool();
    int32_t ret = EnableMovingPhoto(enabled);
    MEDIA_DEBUG_LOG("HStreamCaptureStub HandleEnableRawDelivery result: %{public}d", ret);
    return ret;
}

int32_t HStreamCaptureStub::HandleSetBufferProducerInfo(MessageParcel &data)
{
    std::string bufferName = data.ReadString();
    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObj == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HStreamCaptureStub HandleSetBufferProducerInfo BufferProducer is null");
    sptr<OHOS::IBufferProducer> producer = iface_cast<OHOS::IBufferProducer>(remoteObj);
    CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HStreamCaptureStub HandleSetBufferProducerInfo producer is null");
    int32_t ret = SetBufferProducerInfo(bufferName, producer);
    MEDIA_DEBUG_LOG("HStreamCaptureStub HandleSetBufferProducerInfo result: %{public}d", ret);
    return ret;
}

int32_t HStreamCaptureStub::HandleEnableDeferredType(MessageParcel &data)
{
    CHECK_ERROR_RETURN_RET(!CheckSystemApp(), CAMERA_NO_PERMISSION);
    int32_t type = data.ReadInt32();
    int32_t ret = DeferImageDeliveryFor(type);
    MEDIA_DEBUG_LOG("HStreamCaptureStub HandleEnableDeferredType result: %{public}d", ret);
    return ret;
}

int32_t HStreamCaptureStub::HandleSetMovingPhotoVideoCodecType(MessageParcel &data)
{
    int32_t type = data.ReadInt32();
    int32_t ret = SetMovingPhotoVideoCodecType(type);
    MEDIA_DEBUG_LOG("HStreamCaptureStub HandleSetMovingPhotoVideoCodecType result: %{public}d", ret);
    return ret;
}

int32_t HStreamCaptureStub::HandleSetCallback(MessageParcel &data)
{
    auto remoteObject = data.ReadRemoteObject();
    CHECK_ERROR_RETURN_RET_LOG(remoteObject == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HStreamCaptureStub HandleSetCallback StreamCaptureCallback is null");

    auto callback = iface_cast<IStreamCaptureCallback>(remoteObject);
    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HStreamCaptureStub HandleSetCallback callback is null");
    return SetCallback(callback);
}

int32_t HStreamCaptureStub::HandleAddMediaLibraryPhotoProxy(MessageParcel& data)
{
    sptr<CameraPhotoProxy> photoProxy = new CameraPhotoProxy();
    photoProxy->ReadFromParcel(data);
    int ret = UpdateMediaLibraryPhotoAssetProxy(photoProxy);
    CHECK_ERROR_PRINT_LOG(ret != ERR_NONE,
        "HStreamCaptureStub::HandleAddMediaLibraryPhotoProxy failed : %{public}d", ret);
    return ret;
}

int32_t HStreamCaptureStub::HandleSetCameraPhotoRotation(MessageParcel& data)
{
    bool isEnable = data.ReadBool();

    int ret = SetCameraPhotoRotation(isEnable);
    CHECK_ERROR_PRINT_LOG(ret != ERR_NONE, "HStreamCaptureStub::SetCameraPhotoRotation failed : %{public}d", ret);
    return ret;
}

int32_t HStreamCaptureStub::HandleAcquireBufferToPrepareProxy(MessageParcel& data)
{
    int32_t captureId = data.ReadInt32();
    int32_t ret = AcquireBufferToPrepareProxy(captureId);
    CHECK_ERROR_PRINT_LOG(ret != ERR_NONE,
                          "HStreamCaptureStub::HandleAcquireBufferToPrepareProxy failed : %{public}d", ret);
    return ret;
}

int32_t HStreamCaptureStub::HandleEnableOfflinePhoto(MessageParcel& data)
{
    bool isEnable = data.ReadBool();
    int32_t ret = EnableOfflinePhoto(isEnable);
    CHECK_ERROR_PRINT_LOG(ret != ERR_NONE,
        "HStreamCaptureStub::HandleEnableOfflinePhoto failed : %{public}d", ret);
    return ret;
}

int32_t HStreamCaptureStub::HandleCreateMediaLibrary(MessageParcel& data, MessageParcel &reply)
{
    sptr<CameraPhotoProxy> photoProxy = new CameraPhotoProxy();
    photoProxy->ReadFromParcel(data);
    int64_t timestamp = data.ReadInt64();
    CHECK_ERROR_RETURN_RET_LOG(photoProxy == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HStreamCaptureStub HandleCreateMediaLibrary photoProxy is null");
    std::string uri;
    int32_t cameraShotType = 0;
    std::string burstKey;
    int32_t ret = CreateMediaLibrary(photoProxy, uri, cameraShotType, burstKey, timestamp);
    CHECK_ERROR_RETURN_RET_LOG((!reply.WriteString(uri) || !reply.WriteInt32(cameraShotType) ||
        !reply.WriteString(burstKey)), IPC_STUB_WRITE_PARCEL_ERR,
        "HStreamCaptureStub HandleCreateMediaLibrary Write uri and cameraShotType failed");
    return ret;
}

int32_t HStreamCaptureStub::HandleCreateMediaLibraryForPicture(MessageParcel& data, MessageParcel &reply)
{
    std::shared_ptr<PictureIntf> pictureProxy = PictureProxy::CreatePictureProxy();
    CHECK_ERROR_RETURN_RET_LOG(pictureProxy == nullptr || pictureProxy.use_count() != 1, IPC_STUB_INVALID_DATA_ERR,
        "pictureProxy use count is not 1");    
    MEDIA_DEBUG_LOG("HStreamCaptureStub HandleCreateMediaLibraryForPicture Picture::Unmarshalling E");
    pictureProxy->Unmarshalling(data);
    MEDIA_DEBUG_LOG("HStreamCaptureStub HandleCreateMediaLibraryForPicture Picture::Unmarshalling X");
    CHECK_ERROR_RETURN_RET_LOG(pictureProxy == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HStreamCaptureStub HandleCreateMediaLibrary picture is null");
    sptr<CameraPhotoProxy> photoProxy = new CameraPhotoProxy();
    photoProxy->ReadFromParcel(data);
    CHECK_ERROR_RETURN_RET_LOG(photoProxy == nullptr, IPC_STUB_INVALID_DATA_ERR,
        "HStreamCaptureStub HandleCreateMediaLibrary photoProxy is null");
    int64_t timestamp = data.ReadInt64();
    std::string uri;
    int32_t cameraShotType = 0;
    std::string burstKey;
    MEDIA_DEBUG_LOG("HStreamCaptureStub HandleCreateMediaLibraryForPicture E");
    int32_t ret = CreateMediaLibrary(pictureProxy, photoProxy, uri, cameraShotType, burstKey, timestamp);
    MEDIA_DEBUG_LOG("HStreamCaptureStub HandleCreateMediaLibraryForPicture X");
    CHECK_ERROR_RETURN_RET_LOG((!(reply.WriteString(uri)) || !(reply.WriteInt32(cameraShotType)) ||
        !(reply.WriteString(burstKey))), IPC_STUB_WRITE_PARCEL_ERR,
        "HStreamCaptureStub HandleCreateMediaLibrary Write uri and cameraShotType failed");
    return ret;
}
} // namespace CameraStandard
} // namespace OHOS
