/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hstream_capture_photo_callback_proxy.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {

HStreamCapturePhotoCallbackProxy::HStreamCapturePhotoCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStreamCapturePhotoCallback>(impl)
{
    MEDIA_INFO_LOG("HStreamCapturePhotoCallbackProxy new E");
}

int32_t HStreamCapturePhotoCallbackProxy::OnPhotoAvailable(
    sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp, bool isRaw)
{
    MEDIA_INFO_LOG("HStreamCapturePhotoCallbackProxy::OnPhotoAvailable is called!");
    CHECK_RETURN_RET_ELOG(surfaceBuffer == nullptr, ERR_INVALID_VALUE, "surfaceBuffer is null");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    option.SetFlags(option.TF_ASYNC);

    data.WriteInterfaceToken(GetDescriptor());
    surfaceBuffer->WriteToMessageParcel(data);
    sptr<BufferExtraData> bufferExtraData = surfaceBuffer->GetExtraData();
    CHECK_RETURN_RET_ELOG(bufferExtraData == nullptr, ERR_INVALID_VALUE, "bufferExtraData is null");
    GSError ret = bufferExtraData->WriteToParcel(data);
    CHECK_RETURN_RET_ELOG(ret != GSERROR_OK, ERR_INVALID_VALUE, "WriteToParcel failed, ret:%{public}d", ret);
    data.WriteInt64(timestamp);
    data.WriteBool(isRaw);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCapturePhotoCallbackInterfaceCode::CAMERA_STREAM_CAPTURE_ON_PHOTO_AVAILABLE),
        data,
        reply,
        option);
    CHECK_PRINT_ELOG(
        error != ERR_NONE, "HStreamCapturePhotoCallbackProxy OnPhotoAvailable failed, error: %{public}d", error);
    return error;
}

#ifdef CAMERA_CAPTURE_YUV
int32_t HStreamCapturePhotoCallbackProxy::OnPhotoAvailable(std::shared_ptr<PictureIntf> picture)
{
    MEDIA_INFO_LOG("HStreamCapturePhotoCallbackProxy::OnPhotoAvailable is called!");
    CHECK_RETURN_RET_ELOG(picture == nullptr, ERR_INVALID_VALUE, "picture is null");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    option.SetFlags(option.TF_ASYNC);

    data.WriteInterfaceToken(GetDescriptor());
    CHECK_RETURN_RET_ELOG(!picture->Marshalling(data), ERR_INVALID_VALUE, "Marshalling picture failed");

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(StreamCapturePhotoCallbackInterfaceCode::CAMERA_STREAM_CAPTURE_ON_PICTURE_AVAILABLE),
        data,
        reply,
        option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HStreamCapturePhotoCallbackProxy OnPhotoAvailable failed, error: %{public}d", error);
    }
    return error;
}
#endif

namespace {
bool WriteAuxiliarySurfaceBuffer(MessageParcel& data, const sptr<SurfaceBuffer>& surfaceBuffer)
{
    if (surfaceBuffer == nullptr) {
        data.WriteBool(false);
        return true;
    }
    data.WriteBool(true);
    surfaceBuffer->WriteToMessageParcel(data);
    sptr<BufferExtraData> bufferExtraData = surfaceBuffer->GetExtraData();
    CHECK_RETURN_RET_ELOG(bufferExtraData == nullptr, false, "bufferExtraData is null");
    GSError ret = bufferExtraData->WriteToParcel(data);
    CHECK_RETURN_RET_ELOG(ret != GSERROR_OK, false, "WriteToParcel failed, ret:%{public}d", ret);
    return true;
}
}

int32_t HStreamCapturePhotoCallbackProxy::OnPhotoAvailable(sptr<SurfaceBuffer> mainBuffer,
    sptr<SurfaceBuffer> oxygenBuffer, sptr<SurfaceBuffer> pigmentationBuffer, int64_t timestamp, bool isRaw)
{
    MEDIA_INFO_LOG("HStreamCapturePhotoCallbackProxy::OnPhotoAvailable with auxiliary is called!");
    CHECK_RETURN_RET_ELOG(mainBuffer == nullptr, ERR_INVALID_VALUE, "mainBuffer is null");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    option.SetFlags(option.TF_ASYNC);

    data.WriteInterfaceToken(GetDescriptor());
    CHECK_RETURN_RET_ELOG(!WriteAuxiliarySurfaceBuffer(data, mainBuffer), ERR_INVALID_VALUE,
        "Write mainBuffer failed");
    CHECK_RETURN_RET_ELOG(!WriteAuxiliarySurfaceBuffer(data, oxygenBuffer), ERR_INVALID_VALUE,
        "Write oxygenBuffer failed");
    CHECK_RETURN_RET_ELOG(!WriteAuxiliarySurfaceBuffer(data, pigmentationBuffer), ERR_INVALID_VALUE,
        "Write pigmentationBuffer failed");
    data.WriteInt64(timestamp);
    data.WriteBool(isRaw);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(
            StreamCapturePhotoCallbackInterfaceCode::CAMERA_STREAM_CAPTURE_ON_PHOTO_AVAILABLE_WITH_AUXILIARY),
        data,
        reply,
        option);
    CHECK_PRINT_ELOG(
        error != ERR_NONE, "HStreamCapturePhotoCallbackProxy OnPhotoAvailable failed, error: %{public}d", error);
    return error;
}
}  // namespace CameraStandard
}  // namespace OHOS
