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

#include "photo_buffer_consumer.h"

#include "camera_log.h"
#include "task_manager.h"
#include "camera_surface_buffer_util.h"
#include "camera_report_dfx_uitls.h"
#include "hstream_capture.h"

namespace OHOS {
namespace CameraStandard {

PhotoBufferConsumer::PhotoBufferConsumer(wptr<HStreamCapture> streamCapture, bool isRaw)
    : streamCapture_(streamCapture), isRaw_(isRaw)
{
    MEDIA_INFO_LOG("PhotoBufferConsumer new E, isRaw:%{public}d", isRaw);
}

PhotoBufferConsumer::~PhotoBufferConsumer()
{
    MEDIA_INFO_LOG("PhotoBufferConsumer ~ E");
}

void PhotoBufferConsumer::OnBufferAvailable()
{
    MEDIA_INFO_LOG("PhotoBufferConsumer OnBufferAvailable E");
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_ERROR_RETURN_LOG(streamCapture == nullptr, "streamCapture is null");
    CHECK_ERROR_RETURN_LOG(streamCapture->photoTask_ == nullptr, "photoTask is null");
    wptr<PhotoBufferConsumer> thisPtr(this);
    streamCapture->photoTask_->SubmitTask([thisPtr]() {
        auto listener = thisPtr.promote();
        CHECK_EXECUTE(listener, listener->ExecuteOnBufferAvailable());
    });
    MEDIA_INFO_LOG("PhotoBufferConsumer OnBufferAvailable X");
}

void PhotoBufferConsumer::ExecuteOnBufferAvailable()
{

    MEDIA_INFO_LOG("PhotoBufferConsumer ExecuteOnBufferAvailable E");
    CAMERA_SYNC_TRACE;
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_ERROR_RETURN_LOG(streamCapture == nullptr, "streamCapture is null");
    sptr<Surface> surface;
    if (isRaw_) {
        surface = streamCapture->rawSurface_;
    } else {
        surface = streamCapture->surface_;
    }
    CHECK_ERROR_RETURN_LOG(surface == nullptr, "surface is null");
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    SurfaceError surfaceRet = surface->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    CHECK_ERROR_RETURN_LOG(surfaceRet != SURFACE_ERROR_OK, "PhotoBufferConsumer Failed to acquire surface buffer");
    int32_t isDegradedImage = CameraSurfaceBufferUtil::GetIsDegradedImage(surfaceBuffer);
    MEDIA_INFO_LOG("PhotoBufferConsumer ts isDegradedImage:%{public}d", isDegradedImage);
    MEDIA_INFO_LOG("PhotoBufferConsumer ts is:%{public}" PRId64, timestamp);
    // deep copy surfaceBuffer
    sptr<SurfaceBuffer> newSurfaceBuffer = CameraSurfaceBufferUtil::DeepCopyBuffer(surfaceBuffer);
    // release surfaceBuffer to bufferQueue
    surface->ReleaseBuffer(surfaceBuffer, -1);
    CHECK_ERROR_RETURN_LOG(newSurfaceBuffer == nullptr, "newSurfaceBuffer is null");
    int32_t captureId = CameraSurfaceBufferUtil::GetCaptureId(newSurfaceBuffer);
    CameraReportDfxUtils::GetInstance()->SetFirstBufferEndInfo(captureId);
    CameraReportDfxUtils::GetInstance()->SetPrepareProxyStartInfo(captureId);
    streamCapture->OnPhotoAvailable(newSurfaceBuffer, timestamp, isRaw_);
    MEDIA_INFO_LOG("PhotoBufferConsumer ExecuteOnBufferAvailable X");
}
}  // namespace CameraStandard
}  // namespace OHOS