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

#include "thumbnail_buffer_consumer.h"

#include "camera_log.h"
#include "camera_surface_buffer_util.h"
#include "hstream_capture.h"
#include "task_manager.h"
#include "camera_server_photo_proxy.h"
namespace OHOS {
namespace CameraStandard {

ThumbnailBufferConsumer::ThumbnailBufferConsumer(wptr<HStreamCapture> streamCapture) : streamCapture_(streamCapture)
{
    MEDIA_INFO_LOG("ThumbnailBufferConsumer new E");
}

ThumbnailBufferConsumer::~ThumbnailBufferConsumer()
{
    MEDIA_INFO_LOG("ThumbnailBufferConsumer ~ E");
}

void ThumbnailBufferConsumer::OnBufferAvailable()
{
    MEDIA_INFO_LOG("ThumbnailBufferConsumer OnBufferAvailable E");
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_RETURN_ELOG(streamCapture == nullptr, "streamCapture is null");
    CHECK_RETURN_ELOG(streamCapture->photoTask_ == nullptr, "photoTask is null");
    wptr<ThumbnailBufferConsumer> thisPtr(this);
    streamCapture->photoTask_->SubmitTask([thisPtr]() {
        auto listener = thisPtr.promote();
        CHECK_EXECUTE(listener, listener->ExecuteOnBufferAvailable());
    });
    MEDIA_INFO_LOG("ThumbnailBufferConsumer OnBufferAvailable X");
}

void ThumbnailBufferConsumer::ExecuteOnBufferAvailable()
{
    MEDIA_INFO_LOG("T_ExecuteOnBufferAvailable E");
    CAMERA_SYNC_TRACE;
    sptr<HStreamCapture> streamCapture = streamCapture_.promote();
    CHECK_RETURN_ELOG(streamCapture == nullptr, "streamCapture is null");
    constexpr int32_t memSize = 20 * 1024;
    streamCapture->RequireMemorySize(memSize);
    CHECK_RETURN_ELOG(streamCapture->thumbnailSurface_ == nullptr, "surface is null");
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    SurfaceError surfaceRet = streamCapture->thumbnailSurface_->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    CHECK_RETURN_ELOG(surfaceRet != SURFACE_ERROR_OK, "ThumbnailBufferConsumer Failed to acquire surface buffer");
    // burst captreu skip thumbnail
    int32_t burstSeqId = CameraSurfaceBufferUtil::GetBurstSequenceId(surfaceBuffer);
    if (burstSeqId != -1) {
        streamCapture->thumbnailSurface_->ReleaseBuffer(surfaceBuffer, -1);
        MEDIA_INFO_LOG("T_ExecuteOnBufferAvailable X, burstCapture skip thumbnail");
        return;
    }
    sptr<SurfaceBuffer> newSurfaceBuffer = CameraSurfaceBufferUtil::DeepCopyThumbnailBuffer(surfaceBuffer);
    MEDIA_DEBUG_LOG("ThumbnailListener ReleaseBuffer begin");
    streamCapture->thumbnailSurface_->ReleaseBuffer(surfaceBuffer, -1);
    CHECK_RETURN_ELOG(newSurfaceBuffer == nullptr, "newSurfaceBuffer is null");
    MEDIA_DEBUG_LOG("ThumbnailListener ReleaseBuffer end");
    streamCapture->OnThumbnailAvailable(newSurfaceBuffer, timestamp);
    if (streamCapture->isYuvCapture_) {
        sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
        cameraPhotoProxy->GetServerPhotoProxyInfo(newSurfaceBuffer);
        constexpr int32_t yuvFormat = 3;
        cameraPhotoProxy->SetFormat(yuvFormat);
        cameraPhotoProxy->SetImageFormat(yuvFormat);
        streamCapture->UpdateMediaLibraryPhotoAssetProxy(cameraPhotoProxy);
    }
    MEDIA_INFO_LOG("T_ExecuteOnBufferAvailable X");
}
}  // namespace CameraStandard
}  // namespace OHOS
