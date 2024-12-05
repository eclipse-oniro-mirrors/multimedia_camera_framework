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
#include "metadata_utils.h"
#include "camera_service_ipc_interface_code.h"

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
    if (!(Camera::MetadataUtils::EncodeCameraMetadata(captureSettings, data))) {
        MEDIA_ERR_LOG("HStreamCaptureProxy Capture EncodeCameraMetadata failed");
        return IPC_PROXY_ERR;
    }

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_START), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamCaptureProxy Capture failed, error: %{public}d", error);
    }

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
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamCaptureProxy CancelCapture failed, error: %{public}d", error);
    }

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
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamCaptureProxy ConfirmCapture failed, error: %{public}d", error);
    }

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
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamCaptureProxy Release failed, error: %{public}d", error);
    }

    return error;
}

int32_t HStreamCaptureProxy::SetCallback(sptr<IStreamCaptureCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (callback == nullptr) {
        MEDIA_ERR_LOG("HStreamCaptureProxy SetCallback callback is null");
        return IPC_PROXY_ERR;
    }

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(callback->AsObject());

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_STREAM_CAPTURE_SET_CALLBACK), data, reply, option);
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

    if (producer == nullptr) {
        MEDIA_ERR_LOG("HStreamCaptureProxy CreatePhotoOutput producer is null");
        return IPC_PROXY_ERR;
    }

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteRemoteObject(producer->AsObject());
    data.WriteBool(isEnabled);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCaptureInterfaceCode::CAMERA_SERVICE_SET_THUMBNAIL), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamCaptureProxy SetThumbnail failed, error: %{public}d", error);
    }
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
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamCaptureProxy EnableRawDelivery failed, error: %{public}d", error);
    }
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
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamCaptureProxy IsDeferredVideoEnabled failed, error: %{public}d", error);
    }
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
        static_cast<uint32_t>(StreamRepeatInterfaceCode::CAMERA_PHOTO_ROTATION), data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamCaptureProxy SetCameraPhotoRotation failed, error: %{public}d", error);
    }
    return error;
}
} // namespace CameraStandard
} // namespace OHOS
