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

#include "hstream_capture_thumbnail_callback_proxy.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {

HStreamCaptureThumbnailCallbackProxy::HStreamCaptureThumbnailCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStreamCaptureThumbnailCallback>(impl)
{
    MEDIA_INFO_LOG("HStreamCapturePhotoAssetCallbackProxy new E");
}

int32_t HStreamCaptureThumbnailCallbackProxy::OnThumbnailAvailable(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp)
{
    MEDIA_INFO_LOG("HStreamCaptureThumbnailCallbackProxy::OnThumbnailAvailable is called!");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    option.SetFlags(option.TF_ASYNC);

    data.WriteInterfaceToken(GetDescriptor());
    surfaceBuffer->WriteToMessageParcel(data);
    sptr<BufferExtraData> bufferExtraData = surfaceBuffer->GetExtraData();
    bufferExtraData->WriteToParcel(data);
    data.WriteInt64(timestamp);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(
            StreamCaptureThumbnailCallbackInterfaceCode::CAMERA_STREAM_CAPTURE_ON_THUMBNAIL_AVAILABLE),
        data,
        reply,
        option);
    CHECK_PRINT_ELOG(error != ERR_NONE,
        "HStreamCaptureThumbnailCallbackProxy OnThumbnailAvailable failed, error: %{public}d", error);
    return error;
}
}  // namespace CameraStandard
}  // namespace OHOS
