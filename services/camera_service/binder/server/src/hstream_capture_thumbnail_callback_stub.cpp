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

#include "hstream_capture_thumbnail_callback_stub.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
// LCOV_EXCL_START
int HStreamCaptureThumbnailCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int errCode = -1;
    CHECK_RETURN_RET(data.ReadInterfaceToken() != GetDescriptor(), errCode);
    switch (code) {
        case static_cast<uint32_t>(
            StreamCaptureThumbnailCallbackInterfaceCode::CAMERA_STREAM_CAPTURE_ON_THUMBNAIL_AVAILABLE):
            errCode = HandleOnThumbnailAvailable(data);
            break;
        default:
            MEDIA_ERR_LOG("HStreamCaptureThumbnailCallbackStub request code %{public}u not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }
    return errCode;
}

int HStreamCaptureThumbnailCallbackStub::HandleOnThumbnailAvailable(MessageParcel &data)
{
    MEDIA_INFO_LOG("HStreamCaptureThumbnailCallbackStub::OnThumbnailAvailable is called!");
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    surfaceBuffer->ReadFromMessageParcel(data);
    sptr<BufferExtraData> bufferExtraData = surfaceBuffer->GetExtraData();
    bufferExtraData->ReadFromParcel(data);
    surfaceBuffer->SetExtraData(bufferExtraData);
    int64_t timestamp = data.ReadInt64();
    return OnThumbnailAvailable(surfaceBuffer, timestamp);
}
// LCOV_EXCL_STOP
}  // namespace CameraStandard
}  // namespace OHOS
