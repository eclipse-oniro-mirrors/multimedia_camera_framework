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

#include "moving_photo/moving_photo_surface_wrapper.h"

#include <memory>
#include <mutex>
#include <new>

#include "camera_log.h"
#include "graphic_common_c.h"
#include "surface_type.h"
#include "sync_fence.h"

namespace OHOS {
namespace CameraStandard {
sptr<MovingPhotoSurfaceWrapper> MovingPhotoSurfaceWrapper::CreateMovingPhotoSurfaceWrapper(
    int32_t width, int32_t height)
{
    if (width <= 0 || height <= 0) {
        MEDIA_ERR_LOG("MovingPhotoSurfaceWrapper::CreateMovingPhotoSurfaceWrapper size "
                      "invalid, width:%{public}d, height:%{public}d",
            width, height);
        return nullptr;
    }
    sptr<MovingPhotoSurfaceWrapper> movingPhotoSurfaceWrapper = new (std::nothrow) MovingPhotoSurfaceWrapper();
    if (movingPhotoSurfaceWrapper == nullptr) {
        MEDIA_ERR_LOG("MovingPhotoSurfaceWrapper::CreateMovingPhotoSurfaceWrapper fail.");
        return nullptr;
    }
    bool initResult = movingPhotoSurfaceWrapper->Init(width, height);
    if (initResult) {
        return movingPhotoSurfaceWrapper;
    }
    MEDIA_ERR_LOG("MovingPhotoSurfaceWrapper::CreateMovingPhotoSurfaceWrapper init fail.");
    return nullptr;
}

MovingPhotoSurfaceWrapper::~MovingPhotoSurfaceWrapper()
{
    MEDIA_INFO_LOG("MovingPhotoSurfaceWrapper::~MovingPhotoSurfaceWrapper");
}

sptr<OHOS::IBufferProducer> MovingPhotoSurfaceWrapper::GetProducer() const
{
    std::lock_guard<std::recursive_mutex> lock(videoSurfaceMutex_);
    if (videoSurface_ == nullptr) {
        return nullptr;
    }
    return videoSurface_->GetProducer();
}

bool MovingPhotoSurfaceWrapper::Init(int32_t width, int32_t height)
{
    std::lock_guard<std::recursive_mutex> lock(videoSurfaceMutex_);
    videoSurface_ = Surface::CreateSurfaceAsConsumer("movingPhoto");
    if (videoSurface_ == nullptr) {
        MEDIA_ERR_LOG("MovingPhotoSurfaceWrapper::Init create surface fail.");
        return false;
    }
    auto err = videoSurface_->SetDefaultUsage(BUFFER_USAGE_VIDEO_ENCODER);
    if (err != GSERROR_OK) {
        MEDIA_ERR_LOG("MovingPhotoSurfaceWrapper::Init SetDefaultUsage fail.");
        return false;
    }
    bufferConsumerListener_ = new (std::nothrow) BufferConsumerListener(this);
    err = videoSurface_->RegisterConsumerListener(bufferConsumerListener_);
    if (err != GSERROR_OK) {
        MEDIA_ERR_LOG("MovingPhotoSurfaceWrapper::Init RegisterConsumerListener fail.");
        return false;
    }
    err = videoSurface_->SetDefaultWidthAndHeight(width, height);
    if (err != GSERROR_OK) {
        MEDIA_ERR_LOG("MovingPhotoSurfaceWrapper::Init SetDefaultWidthAndHeight fail.");
        return false;
    }
    return true;
}

void MovingPhotoSurfaceWrapper::OnBufferArrival()
{
    std::lock_guard<std::recursive_mutex> lock(videoSurfaceMutex_);
    if (videoSurface_ == nullptr) {
        MEDIA_ERR_LOG("MovingPhotoSurfaceWrapper::OnBufferArrival surface is nullptr");
        return;
    }
    auto transform = videoSurface_->GetTransform();
    MEDIA_DEBUG_LOG("MovingPhotoSurfaceWrapper::OnBufferArrival queueSize %{public}u, transform %{public}d",
        videoSurface_->GetQueueSize(), transform);

    int64_t timestamp;
    OHOS::Rect damage;
    sptr<SurfaceBuffer> buffer;
    sptr<SyncFence> syncFence = SyncFence::INVALID_FENCE;
    GSError err = videoSurface_->AcquireBuffer(buffer, syncFence, timestamp, damage);
    if (err != GSERROR_OK) {
        MEDIA_ERR_LOG("Failed to acquire surface buffer");
        return;
    }

    auto surfaceBufferListener = GetSurfaceBufferListener();
    if (surfaceBufferListener == nullptr) {
        MEDIA_DEBUG_LOG("MovingPhotoSurfaceWrapper::OnBufferArrival surfaceBufferListener_ is nullptr.");
        err = videoSurface_->ReleaseBuffer(buffer, SyncFence::INVALID_FENCE);
        CHECK_ERROR_PRINT_LOG(err != GSERROR_OK,
            "MovingPhotoSurfaceWrapper::OnBufferArrival ReleaseBuffer fail.");
        return;
    }

    err = videoSurface_->DetachBufferFromQueue(buffer);
    if (err != GSERROR_OK) {
        MEDIA_ERR_LOG("MovingPhotoSurfaceWrapper::OnBufferArrival detach buffer fail. %{public}d", err);
        return;
    }
    MEDIA_DEBUG_LOG("MovingPhotoSurfaceWrapper::OnBufferArrival buffer %{public}d x %{public}d, stride is %{public}d",
        buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight(), buffer->GetStride());
    surfaceBufferListener->OnBufferArrival(buffer, timestamp, transform);
}

MovingPhotoSurfaceWrapper::BufferConsumerListener::BufferConsumerListener(
    sptr<MovingPhotoSurfaceWrapper> surfaceWrapper)
    : movingPhotoSurfaceWrapper_(surfaceWrapper)
{}

void MovingPhotoSurfaceWrapper::BufferConsumerListener::OnBufferAvailable()
{
    auto surfaceWrapper = movingPhotoSurfaceWrapper_.promote();
    if (surfaceWrapper != nullptr) {
        surfaceWrapper->OnBufferArrival();
    }
}

void MovingPhotoSurfaceWrapper::RecycleBuffer(sptr<SurfaceBuffer> buffer)
{
    std::lock_guard<std::recursive_mutex> lock(videoSurfaceMutex_);

    GSError err = videoSurface_->AttachBufferToQueue(buffer);
    CHECK_ERROR_RETURN_LOG(err != GSERROR_OK, "Failed to attach buffer %{public}d", err);
    err = videoSurface_->ReleaseBuffer(buffer, SyncFence::INVALID_FENCE);
    CHECK_ERROR_RETURN_LOG(err != GSERROR_OK, "Failed to Release buffer %{public}d", err);
}
} // namespace CameraStandard
} // namespace OHOS