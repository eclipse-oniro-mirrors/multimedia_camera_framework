/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "frame_record.h"

#include "moving_photo_surface_wrapper.h"

namespace OHOS {
namespace CameraStandard {

FrameRecord::FrameRecord(sptr<SurfaceBuffer> videoBuffer, int64_t timestamp, GraphicTransformType type)
    : videoBuffer_(videoBuffer), timestamp_(timestamp), transformType_(type)
{
    frameId_ = std::to_string(timestamp);
    size = make_shared<Size>();
    size->width = static_cast<uint32_t>(videoBuffer->GetSurfaceBufferWidth());
    size->height = static_cast<uint32_t>(videoBuffer->GetSurfaceBufferHeight());
    bufferSize = videoBuffer->GetSize();
    format = videoBuffer->GetFormat();
    usage = videoBuffer->GetUsage();
}

FrameRecord::~FrameRecord()
{
    MEDIA_DEBUG_LOG("FrameRecord::~FrameRecord");
    encodedBuffer = nullptr;
}

void FrameRecord::ReleaseSurfaceBuffer(sptr<MovingPhotoSurfaceWrapper> surfaceWrapper)
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (videoBuffer_ && !IsReadyConvert()) {
        CHECK_EXECUTE(surfaceWrapper != nullptr, surfaceWrapper->RecycleBuffer(videoBuffer_));
        videoBuffer_ = nullptr;
        MEDIA_DEBUG_LOG("release buffer end %{public}s", frameId_.c_str());
    }
}

void FrameRecord::ReleaseMetaBuffer(sptr<Surface> surface, bool reuse)
{
    std::unique_lock<std::mutex> lock(metaBufferMutex_);
    sptr<SurfaceBuffer> buffer = nullptr;
    if (status != STATUS_NONE && metaBuffer_) {
        buffer = SurfaceBuffer::Create();
        DeepCopyBuffer(buffer, metaBuffer_);
    }
    if (metaBuffer_) {
        if (reuse) {
            SurfaceError surfaceRet = surface->AttachBufferToQueue(metaBuffer_);
            CHECK_RETURN_ELOG(surfaceRet != SURFACE_ERROR_OK,
                "Failed to attach meta buffer %{public}d", surfaceRet);
            surfaceRet = surface->ReleaseBuffer(metaBuffer_, -1);
            CHECK_RETURN_ELOG(surfaceRet != SURFACE_ERROR_OK,
                "Failed to Release meta Buffer %{public}d", surfaceRet);
        }
        metaBuffer_ = buffer;
        MEDIA_DEBUG_LOG("release meta buffer end %{public}s", frameId_.c_str());
    }
}

void FrameRecord::NotifyBufferRelease()
{
    MEDIA_DEBUG_LOG("notifyBufferRelease");
    status = STATUS_FINISH_ENCODE;
    canReleased_.notify_one();
}

void FrameRecord::DeepCopyBuffer(sptr<SurfaceBuffer> newSurfaceBuffer, sptr<SurfaceBuffer> surfaceBuffer) const
{
    BufferRequestConfig requestConfig = {
        .height = surfaceBuffer->GetHeight(),
        .strideAlignment = 0x8, // default stride is 8 Bytes.
        .format = surfaceBuffer->GetFormat(),
        .usage = surfaceBuffer->GetUsage(),
        .width = surfaceBuffer->GetWidth(),
        .timeout = 0,
        .colorGamut = surfaceBuffer->GetSurfaceBufferColorGamut(),
        .transform = surfaceBuffer->GetSurfaceBufferTransform(),
    };
    auto allocErrorCode = newSurfaceBuffer->Alloc(requestConfig);
    CHECK_RETURN_ELOG(allocErrorCode != GSERROR_OK, "SurfaceBuffer alloc ret: %d", allocErrorCode);
    CHECK_PRINT_ELOG(memcpy_s(newSurfaceBuffer->GetVirAddr(), newSurfaceBuffer->GetSize(),
        surfaceBuffer->GetVirAddr(), surfaceBuffer->GetSize()) != EOK, "SurfaceBuffer memcpy_s failed");
}
} // namespace CameraStandard
} // namespace OHOS