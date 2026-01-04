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

#include "hstream_capture_photo_callback_stub.h"
#include "camera_log.h"
#ifdef CAMERA_CAPTURE_YUV
#include "picture_proxy.h"
#endif

namespace OHOS {
namespace CameraStandard {
// LCOV_EXCL_START
int HStreamCapturePhotoCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int errCode = -1;
    CHECK_RETURN_RET(data.ReadInterfaceToken() != GetDescriptor(), errCode);
    switch (code) {
        case static_cast<uint32_t>(StreamCapturePhotoCallbackInterfaceCode::CAMERA_STREAM_CAPTURE_ON_PHOTO_AVAILABLE):
            errCode = HandleOnPhotoAvailable(data);
            break;
#ifdef CAMERA_CAPTURE_YUV
        case static_cast<uint32_t>(StreamCapturePhotoCallbackInterfaceCode::CAMERA_STREAM_CAPTURE_ON_PICTURE_AVAILABLE):
            errCode = HandleOnPictureAvailable(data);
            break;
#endif
        default:
            MEDIA_ERR_LOG("HStreamCaptureCallbackStub request code %{public}u not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }
    return errCode;
}
 
int HStreamCapturePhotoCallbackStub::HandleOnPhotoAvailable(MessageParcel& data)
{
    MEDIA_INFO_LOG("HStreamCapturePhotoCallbackStub::OnPhotoAvailable is called!");
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    surfaceBuffer->ReadFromMessageParcel(data);
    sptr<BufferExtraData> bufferExtraData = surfaceBuffer->GetExtraData();
    bufferExtraData->ReadFromParcel(data);
    surfaceBuffer->SetExtraData(bufferExtraData);
    int64_t timestamp = data.ReadInt64();
    bool isRaw = data.ReadBool();
    return OnPhotoAvailable(surfaceBuffer, timestamp, isRaw);
}

#ifdef CAMERA_CAPTURE_YUV
int HStreamCapturePhotoCallbackStub::HandleOnPictureAvailable(MessageParcel& data)
{
    MEDIA_INFO_LOG("HStreamCapturePhotoCallbackStub::OnPictureAvailable is called!");
    std::shared_ptr<PictureIntf> pictureProxy = PictureProxy::CreatePictureProxy();
    CHECK_EXECUTE(pictureProxy, pictureProxy->UnmarshallingPicture(data));
    return OnPhotoAvailable(pictureProxy);
}
#endif
// LCOV_EXCL_STOP
}  // namespace CameraStandard
}  // namespace OHOS
