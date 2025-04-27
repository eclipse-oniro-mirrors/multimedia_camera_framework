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

#include "hstream_capture_proxy.h"
#include "camera_log.h"
#include "camera_photo_proxy.h"
#include "camera_service_ipc_interface_code.h"
#include "metadata_utils.h"
#include "picture_interface.h"

namespace OHOS {
namespace CameraStandard {
HStreamCaptureProxy::HStreamCaptureProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStreamCapture>(impl) { }

int32_t HStreamCaptureProxy::Capture(const std::shared_ptr<Camera::CameraMetadata> &captureSettings)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    CHECK_ERROR_RETURN_RET_LOG(!(Camera::MetadataUtils::EncodeCameraMetadata(captureSettings, data)), IPC_PROXY_ERR,
        "HStreamCaptureProxy Capture EncodeCameraMetadata failed");

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_START), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamCaptureProxy Capture failed, error: %{public}d", error);

    return error;
}

int32_t HStreamCaptureProxy::CancelCapture()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_CANCEL), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamCaptureProxy CancelCapture failed, error: %{public}d", error);

    return error;
}

int32_t HStreamCaptureProxy::ConfirmCapture()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_CONFIRM), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamCaptureProxy ConfirmCapture failed, error: %{public}d", error);

    return error;
}

int32_t HStreamCaptureProxy::Release()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_RELEASE), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamCaptureProxy Release failed, error: %{public}d", error);

    return error;
}

int32_t HStreamCaptureProxy::SetCallback(sptr<IStreamCaptureCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, IPC_PROXY_ERR, "HStreamCaptureProxy SetCallback callback is null");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(callback->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_SET_CALLBACK), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamCaptureProxy SetCallback failed, error: %{public}d", error);

    return error;
}

int32_t HStreamCaptureProxy::UnSetCallback()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_UNSET_CALLBACK), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamCaptureProxy SetCallback failed, error: %{public}d", error);
    }
    return error;
}

int32_t HStreamCaptureProxy::SetThumbnail(bool isEnabled, const sptr<OHOS::IBufferProducer> &producer)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, IPC_PROXY_ERR,
        "HStreamCaptureProxy CreatePhotoOutput producer is null");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(producer->AsObject());
    data.WriteBool(isEnabled);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_SERVICE_SET_THUMBNAIL), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamCaptureProxy SetThumbnail failed, error: %{public}d", error);
    return error;
}

int32_t HStreamCaptureProxy::EnableRawDelivery(bool enabled)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteBool(enabled);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_ENABLE_RAW_DELIVERY), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamCaptureProxy EnableRawDelivery failed, error: %{public}d", error);
    return error;
}

int32_t HStreamCaptureProxy::EnableMovingPhoto(bool enabled)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteBool(enabled);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_ENABLE_MOVING_PHOTO), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamCaptureProxy EnableMovingPhoto failed, error: %{public}d", error);
    return error;
}

int32_t HStreamCaptureProxy::SetBufferProducerInfo(const std::string bufName,
    const sptr<OHOS::IBufferProducer> &producer)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, IPC_PROXY_ERR,
        "HStreamCaptureProxy SetRawPhotoStreamInfo producer is null");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(bufName);
    data.WriteRemoteObject(producer->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_SET_BUFFER_PRODUCER_INFO), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamCaptureProxy SetBufferProducerInfo failed, error: %{public}d",
        error);
    return error;
}

int32_t HStreamCaptureProxy::DeferImageDeliveryFor(int32_t type)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(type);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_SERVICE_ENABLE_DEFERREDTYPE), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamCaptureProxy DeferImageDeliveryFor failed, error: %{public}d",
        error);
    return error;
}

int32_t HStreamCaptureProxy::IsDeferredPhotoEnabled()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_GET_DEFERRED_PHOTO), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamCaptureProxy IsDeferredPhotoEnabled failed, error: %{public}d",
        error);
    return error;
}

int32_t HStreamCaptureProxy::IsDeferredVideoEnabled()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_GET_DEFERRED_VIDEO), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamCaptureProxy IsDeferredVideoEnabled failed, error: %{public}d",
        error);
    return error;
}

int32_t HStreamCaptureProxy::SetMovingPhotoVideoCodecType(int32_t videoCodecType)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(videoCodecType);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_SET_VIDEO_CODEC_TYPE), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE,
        "HStreamCaptureProxy IsDeferredVideoEnabled failed, error: %{public}d", error);
    return error;
}

int32_t HStreamCaptureProxy::UpdateMediaLibraryPhotoAssetProxy(sptr<CameraPhotoProxy> photoProxy)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    CHECK_ERROR_RETURN_RET_LOG(photoProxy == nullptr, IPC_PROXY_ERR,
        "HStreamCaptureProxy UpdateMediaLibraryPhotoAssetProxy photoProxy is null");
    data.WriteInterfaceToken(GetDescriptor());
    photoProxy->WriteToParcel(data);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_ADD_MEDIA_LIBRARY_PHOTO_PROXY),
        data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamRepeatProxy SetCameraRotation failed, error: %{public}d", error);
    return error;
}

int32_t HStreamCaptureProxy::SetCameraPhotoRotation(bool isEnable)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteBool(isEnable);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_PHOTO_ROTATION), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamCaptureProxy SetCameraPhotoRotation failed, error: %{public}d", error);
    }
    return error;
}

int32_t HStreamCaptureProxy::AcquireBufferToPrepareProxy(int32_t captureId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(captureId);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_CAPTURE_DFX), data, reply, option);
    CHECK_ERROR_PRINT_LOG(
        error != ERR_NONE, "HStreamRepeatProxy AcquireBufferToPrepareProxy failed, error: %{public}d", error);
    return error;
}


int32_t HStreamCaptureProxy::EnableOfflinePhoto(bool isEnable)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteBool(isEnable);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_ENABLE_OFFLINE_PHOTO), data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "HStreamRepeatProxy EnableOfflinePhoto failed, error: %{public}d", error);
    return error;
}

int32_t HStreamCaptureProxy::CreateMediaLibrary(sptr<CameraPhotoProxy> &photoProxy,
    std::string &uri, int32_t &cameraShotType, std::string &burstKey, int64_t timestamp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    CHECK_ERROR_RETURN_RET_LOG(photoProxy == nullptr, IPC_PROXY_ERR,
        "HCaptureSessionProxy CreateMediaLibrary photoProxy is null");
    data.WriteInterfaceToken(GetDescriptor());
    photoProxy->WriteToParcel(data);
    data.WriteInt64(timestamp);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_CREATE_MEDIA_LIBRARY_MANAGER),
        data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE,
        "HCaptureSessionProxy CreateMediaLibrary failed, error: %{public}d", error);
    uri = reply.ReadString();
    cameraShotType = reply.ReadInt32();
    burstKey = reply.ReadString();
    return error;
}

int32_t HStreamCaptureProxy::CreateMediaLibrary(std::shared_ptr<PictureIntf> picture,
    sptr<CameraPhotoProxy> &photoProxy, std::string &uri, int32_t &cameraShotType,
    std::string &burstKey, int64_t timestamp)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (picture == nullptr || photoProxy == nullptr) {
        MEDIA_ERR_LOG("HStreamCaptureProxy CreateMediaLibrary picture or photoProxy is null");
        return IPC_PROXY_ERR;
    }
    data.WriteInterfaceToken(GetDescriptor());
    MEDIA_DEBUG_LOG("HStreamCaptureProxy CreateMediaLibrary picture->Marshalling E");
    CHECK_ERROR_PRINT_LOG(!picture->Marshalling(data), "HStreamCaptureProxy picture Marshalling failed");
    MEDIA_DEBUG_LOG("HStreamCaptureProxy CreateMediaLibrary picture->Marshalling X");
    photoProxy->WriteToParcel(data);
    data.WriteInt64(timestamp);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_CREATE_MEDIA_LIBRARY_MANAGER_PICTURE),
        data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamCaptureProxy CreateMediaLibrary failed, error: %{public}d", error);
    }
    uri = reply.ReadString();
    cameraShotType = reply.ReadInt32();
    burstKey = reply.ReadString();
    return error;
}
} // namespace CameraStandard
} // namespace OHOS
