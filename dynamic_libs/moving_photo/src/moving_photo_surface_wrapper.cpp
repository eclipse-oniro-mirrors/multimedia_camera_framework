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

#include "moving_photo_surface_wrapper.h"

#include <memory>
#include <mutex>
#include <new>

#include "utils/camera_log.h"
#include "graphic_common_c.h"
#include "surface_type.h"
#include "sync_fence.h"

namespace OHOS {
namespace CameraStandard {
sptr<MovingPhotoSurfaceWrapper> MovingPhotoSurfaceWrapper::CreateMovingPhotoSurfaceWrapper(
    int32_t width, int32_t height)
{
    CHECK_ERROR_RETURN_RET_LOG(width <= 0 || height <= 0, nullptr,
        "MovingPhotoSurfaceWrapper::CreateMovingPhotoSurfaceWrapper size "
        "invalid, width:%{public}d, height:%{public}d", width, height);
    sptr<MovingPhotoSurfaceWrapper> movingPhotoSurfaceWrapper = new (std::nothrow) MovingPhotoSurfaceWrapper();
    CHECK_ERROR_RETURN_RET_LOG(movingPhotoSurfaceWrapper == nullptr, nullptr,
        "MovingPhotoSurfaceWrapper::CreateMovingPhotoSurfaceWrapper fail.");
    bool initResult = movingPhotoSurfaceWrapper->Init(width, height);
    CHECK_ERROR_RETURN_RET(initResult, movingPhotoSurfaceWrapper);
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
    CHECK_ERROR_RETURN_RET(videoSurface_ == nullptr, nullptr);
    return videoSurface_->GetProducer();
}

bool MovingPhotoSurfaceWrapper::Init(int32_t width, int32_t height)
{
    std::lock_guard<std::recursive_mutex> lock(videoSurfaceMutex_);
    videoSurface_ = Surface::CreateSurfaceAsConsumer("movingPhoto");
    CHECK_ERROR_RETURN_RET_LOG(videoSurface_ == nullptr, false, "MovingPhotoSurfaceWrapper::Init create surface fail.");
    auto err = videoSurface_->SetDefaultUsage(BUFFER_USAGE_VIDEO_ENCODER);
    CHECK_ERROR_RETURN_RET_LOG(err != GSERROR_OK, false, "MovingPhotoSurfaceWrapper::Init SetDefaultUsage fail.");
    bufferConsumerListener_ = new (std::nothrow) BufferConsumerListener(this);
    err = videoSurface_->RegisterConsumerListener(bufferConsumerListener_);
    CHECK_ERROR_RETURN_RET_LOG(err != GSERROR_OK, false,
        "MovingPhotoSurfaceWrapper::Init RegisterConsumerListener fail.");
    err = videoSurface_->SetDefaultWidthAndHeight(width, height);
    CHECK_ERROR_RETURN_RET_LOG(err != GSERROR_OK, false,
        "MovingPhotoSurfaceWrapper::Init SetDefaultWidthAndHeight fail.");
    return true;
}

void MovingPhotoSurfaceWrapper::OnBufferArrival()
{
    std::lock_guard<std::recursive_mutex> lock(videoSurfaceMutex_);
    CHECK_ERROR_RETURN_LOG(videoSurface_ == nullptr, "MovingPhotoSurfaceWrapper::OnBufferArrival surface is nullptr");
    auto transform = videoSurface_->GetTransform();
    MEDIA_DEBUG_LOG("MovingPhotoSurfaceWrapper::OnBufferArrival queueSize %{public}u, transform %{public}d",
        videoSurface_->GetQueueSize(), transform);

    int64_t timestamp;
    OHOS::Rect damage;
    sptr<SurfaceBuffer> buffer;
    sptr<SyncFence> syncFence = SyncFence::INVALID_FENCE;
    GSError err = videoSurface_->AcquireBuffer(buffer, syncFence, timestamp, damage);
    CHECK_ERROR_RETURN_LOG(err != GSERROR_OK, "Failed to acquire surface buffer");

    auto surfaceBufferListener = GetSurfaceBufferListener();
    if (surfaceBufferListener == nullptr) {
        MEDIA_DEBUG_LOG("MovingPhotoSurfaceWrapper::OnBufferArrival surfaceBufferListener_ is nullptr.");
        err = videoSurface_->ReleaseBuffer(buffer, SyncFence::INVALID_FENCE);
        CHECK_ERROR_PRINT_LOG(err != GSERROR_OK, "MovingPhotoSurfaceWrapper::OnBufferArrival ReleaseBuffer fail.");
        return;
    }

    err = videoSurface_->DetachBufferFromQueue(buffer);
    CHECK_ERROR_RETURN_LOG(err != GSERROR_OK,
        "MovingPhotoSurfaceWrapper::OnBufferArrival detach buffer fail. %{public}d", err);
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
    CHECK_EXECUTE(surfaceWrapper != nullptr, surfaceWrapper->OnBufferArrival());
}

void MovingPhotoSurfaceWrapper::RecycleBuffer(sptr<SurfaceBuffer> buffer)
{
    std::lock_guard<std::recursive_mutex> lock(videoSurfaceMutex_);

    GSError err = videoSurface_->AttachBufferToQueue(buffer);
    CHECK_ERROR_RETURN_LOG(err != GSERROR_OK, "Failed to attach buffer %{public}d", err);
    err = videoSurface_->ReleaseBuffer(buffer, SyncFence::INVALID_FENCE);
    CHECK_ERROR_RETURN_LOG(err != GSERROR_OK, "Failed to Release Buffer %{public}d", err);
}
} // namespace CameraStandard
} // namespace OHOS