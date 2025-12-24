/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "video_buffer_wrapper.h"
#include "camera_log.h"
#include "sync_fence.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {

VideoBufferWrapper::VideoBufferWrapper(sptr<SurfaceBuffer> videoBuffer, int64_t timestamp,
                             GraphicTransformType transformType,
                             sptr<Surface> inputSurface,
                             sptr<Surface> outputSurface)
    : BufferWrapperBase(Type::VIDEO, timestamp), videoBuffer_(videoBuffer),
      transformType_(transformType), inputSurface_(wptr<Surface>(inputSurface)),
      outputSurface_(wptr<Surface>(outputSurface)) 
{
    MEDIA_DEBUG_LOG("VideoBufferWrapper %{public}" PRId64, timestamp);
}

VideoBufferWrapper::~VideoBufferWrapper()
{
    MEDIA_DEBUG_LOG("~VideoBufferWrapper %{public}" PRId64, GetTimestamp());
    videoBuffer_ = nullptr;
    transformType_ = GRAPHIC_ROTATE_NONE;
}

bool VideoBufferWrapper::Release()
{
    sptr<Surface> surface = inputSurface_.promote();
    CHECK_RETURN_RET_ELOG(surface == nullptr, false, "inputSurface is nullptr");
    GSError ret = surface->AttachBufferToQueue(videoBuffer_);
    CHECK_RETURN_RET_ELOG(ret != GSERROR_OK, false, "Failed to AttachBuffer %{public}d", ret);
    ret = surface->ReleaseBuffer(videoBuffer_, SyncFence::INVALID_FENCE);
    CHECK_RETURN_RET_ELOG(ret != GSERROR_OK, false, "Failed to Release buffer %{public}d", ret);
    return true;
}

bool VideoBufferWrapper::DetachBufferFromOutputSurface()
{
    CHECK_RETURN_RET_ELOG(videoBuffer_ == nullptr, false, "videoBuffer_ has released");
    CHECK_RETURN_RET_ELOG(outputSurface_ == nullptr, false, "outputSurface_ has released");
    sptr<SurfaceBuffer> releaseBuffer;
    sptr<SyncFence> syncFence = SyncFence::INVALID_FENCE;
    BufferRequestConfig requestConfig = {
        .width = videoBuffer_->GetWidth(),
        .height = videoBuffer_->GetHeight(),
        .strideAlignment = 0x8, // default stride is 8 Bytes.
        .format = videoBuffer_->GetFormat(),
        .usage = videoBuffer_->GetUsage(),
        .timeout = 0,
        .colorGamut = videoBuffer_->GetSurfaceBufferColorGamut(),
        .transform = videoBuffer_->GetSurfaceBufferTransform(),
    };
    SurfaceError ret = outputSurface_->RequestBuffer(releaseBuffer, syncFence, requestConfig);
    CHECK_RETURN_RET_ELOG(ret != SURFACE_ERROR_OK, false, "RequestBuffer failed. %{public}d", ret);
    constexpr uint32_t waitForEver = -1;
    (void)syncFence->Wait(waitForEver);
    CHECK_RETURN_RET_ELOG(releaseBuffer == nullptr, ret, "Failed to request codec Buffer");
    ret = outputSurface_->DetachBufferFromQueue(releaseBuffer);
    CHECK_RETURN_RET_ELOG(ret != SURFACE_ERROR_OK, false, "Failed to detach buffer %{public}d", ret);
    return true;
}

bool VideoBufferWrapper::Flush2Target()
{
    CHECK_RETURN_RET_ELOG(videoBuffer_ == nullptr, false, "video buffer is nullptr");
    CHECK_RETURN_RET_ELOG(outputSurface_ == nullptr, false, "outputSurface_ has released");
    SurfaceError ret = outputSurface_->AttachBufferToQueue(videoBuffer_);
    if (ret != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("AttachBufferToQueue ret: %{public}d", ret);
        Release();
        return false;
    }
    constexpr int32_t invalidFence = -1;
    BufferFlushConfig flushConfig = {
        .damage = {
            .w = videoBuffer_->GetWidth(),
            .h = videoBuffer_->GetHeight(),
        },
        .timestamp = GetTimestamp(),
    };
    ret = outputSurface_->FlushBuffer(videoBuffer_, invalidFence, flushConfig);
    CHECK_RETURN_RET_ELOG(ret != 0, false, "FlushBuffer failed");
    return true;
}

void VideoBufferWrapper::ReleaseMetaBuffer()
{
    CHECK_EXECUTE(metaBuffer_, metaBuffer_->Release());
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP