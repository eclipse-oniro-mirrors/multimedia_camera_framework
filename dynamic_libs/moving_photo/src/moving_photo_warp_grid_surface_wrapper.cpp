/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "moving_photo_warp_grid_surface_wrapper.h"
#include "moving_photo_lifecycle_manager.h"
#include "moving_photo_listener.h"

#include "surface.h"
#include "iconsumer_surface.h"
#include "sync_fence.h"
#include "camera_log.h"
#include "camera_timer.h"
#include "fcntl.h"
#include <fstream>

namespace OHOS {
namespace CameraStandard {

MovingPhotoStageEisListener::MovingPhotoStageEisListener(wptr<Surface> firstStageEisSurface,
                                                         wptr<MovingPhotoListener> videoListener,
                                                         shared_ptr<FixedSizeList<MetaElementType>> stageEisCache)
    : firstStageEidSurface_(firstStageEisSurface), videoListener_(videoListener), stageEisCache_(stageEisCache),
      lifecycleManager_(nullptr)
{
    MEDIA_DEBUG_LOG("MovingPhotoStageEisListener ctor is called");
}

void MovingPhotoStageEisListener::SetLifecycleManager(wptr<MovingPhotoLifecycleManager> lifecycleManager)
{
    lifecycleManager_ = lifecycleManager;
}

void MovingPhotoStageEisListener::UnregisterFromSurface()
{
    auto surface = firstStageEidSurface_.promote();
    if (surface != nullptr) {
        MEDIA_INFO_LOG("MovingPhotoStageEisListener::UnregisterFromSurface");
        surface->UnregisterConsumerListener();
    }
}

MovingPhotoStageEisListener::~MovingPhotoStageEisListener()
{
    MEDIA_DEBUG_LOG("MovingPhotoStageEisListener dtor is called");
    StopProcessTimer();
    cachedBufferQueue_.clear();
}

bool MovingPhotoStageEisListener::ProcessSingleBuffer(sptr<SurfaceBuffer> buffer, int64_t timestamp)
{
    if (buffer == nullptr) {
        MEDIA_ERR_LOG("MovingPhotoStageEisListener::ProcessSingleBuffer buffer is null");
        return false;
    }
    auto videoLisenter = videoListener_.promote();
    if (videoLisenter == nullptr) {
        MEDIA_ERR_LOG("MovingPhotoStageEisListener::ProcessSingleBuffer videoListener is null");
        return false;
    }
    sptr<FrameRecord> frameRecord;
    bool isNeedAddStageEisCache = !videoLisenter->RefillStageEis(buffer, timestamp, frameRecord);
    if (!isNeedAddStageEisCache && frameRecord != nullptr) {
        int32_t ret = videoLisenter->StageEisSesionProcess(buffer, frameRecord);
        if (ret != 0) {
            MEDIA_INFO_LOG("MovingPhotoStageEisListener::ProcessSingleBuffer RequestBuffer no free buffer, need cache");
            return true;
        }
    } else {
        MEDIA_INFO_LOG("MovingPhotoStageEisListener::ProcessSingleBuffer current not find video buffer");
    }
    return false;
}

void MovingPhotoStageEisListener::ReleaseWarpBufffer(sptr<Surface> firstStageEisSurface,
    sptr<SurfaceBuffer>& warpGridBuffer, int64_t timeStamp)
{
    CHECK_RETURN_ELOG(firstStageEisSurface == nullptr, "firstStageEisSurface is null, timestamp:%{public}llu",
        (long long unsigned)timeStamp);
    SurfaceError surfaceRet = firstStageEisSurface->AttachBufferToQueue(warpGridBuffer);
    CHECK_EXECUTE(surfaceRet != SURFACE_ERROR_OK,
        MEDIA_ERR_LOG("firstStageEisSurface AttachBuffer, surfaceRet = %{public}d, timestamp:%{public}llu", surfaceRet,
        (long long unsigned)timeStamp));
    surfaceRet = firstStageEisSurface->ReleaseBuffer(warpGridBuffer, -1);
    CHECK_EXECUTE(surfaceRet != SURFACE_ERROR_OK,
        MEDIA_ERR_LOG("firstStageEisSurface ReleaseBuffer, surfaceRet = %{public}d, timestamp:%{public}llu", surfaceRet,
        (long long unsigned)timeStamp));
}

void MovingPhotoStageEisListener::ProcessCachedBuffers()
{
    std::lock_guard<std::mutex> lock(cacheMutex_);
    if (cachedBufferQueue_.empty()) {
        return;
    }
    auto videoLisenter = videoListener_.promote();
    if (videoLisenter == nullptr) {
        MEDIA_ERR_LOG("MovingPhotoStageEisListener::ProcessCachedBuffers videoListener is null");
        return;
    }
    while (!cachedBufferQueue_.empty()) {
        auto [buffer, timestamp] = cachedBufferQueue_.front();
        MEDIA_INFO_LOG("MovingPhotoStageEisListener::ProcessCachedBuffers processing cached buffer, "
                       "timestamp: %{public}llu", (long long unsigned)timestamp);
        bool needCache = ProcessSingleBuffer(buffer, timestamp);
        if (needCache) {
            MEDIA_INFO_LOG("MovingPhotoStageEisListener::ProcessCachedBuffers RequestBuffer no free buffer, stop");
            break;
        }
        auto firstStageEidSurface = firstStageEidSurface_.promote();
        ReleaseWarpBufffer(firstStageEidSurface, buffer, timestamp);
        cachedBufferQueue_.pop_front();
    }
    if (cachedBufferQueue_.empty()) {
        StopProcessTimer();
    }
}

void MovingPhotoStageEisListener::StartProcessTimer()
{
    std::lock_guard<std::mutex> lock(timerMutex_);
    if (processTimerId_ != 0) {
        return;
    }
    MEDIA_INFO_LOG("MovingPhotoStageEisListener::StartProcessTimer");
    auto weakThis = wptr<MovingPhotoStageEisListener>(this);
    auto callback = [weakThis]() {
        auto thisPtr = weakThis.promote();
        if (thisPtr != nullptr) {
            thisPtr->OnProcessTimerCallback();
        }
    };
    processTimerId_ = CameraTimer::GetInstance().Register(callback, PROCESS_TIMER_INTERVAL_MS, false);
}

void MovingPhotoStageEisListener::StopProcessTimer()
{
    std::lock_guard<std::mutex> lock(timerMutex_);
    if (processTimerId_ != 0) {
        MEDIA_INFO_LOG("MovingPhotoStageEisListener::StopProcessTimer");
        CameraTimer::GetInstance().Unregister(processTimerId_);
        processTimerId_ = 0;
    }
}

void MovingPhotoStageEisListener::OnProcessTimerCallback()
{
    MEDIA_INFO_LOG("MovingPhotoStageEisListener::OnProcessTimerCallback");
    ProcessCachedBuffers();
}

void MovingPhotoStageEisListener::OnBufferAvailable()  // warp grid buffer
{
    MEDIA_INFO_LOG("MovingPhotoStageEisListener::OnBufferAvailable is called");
    if (firstStageEidSurface_ == nullptr) {
        MEDIA_INFO_LOG("MovingPhotoStageEisListener::OnBufferAvailable firstStageEidSurface is nullptr");
        return;
    }
    sptr<Surface> firstStageEisSurface = firstStageEidSurface_.promote();
    if (firstStageEisSurface == nullptr) {
        MEDIA_ERR_LOG("MovingPhotoStageEisListener::OnBufferAvailable firstStageEisSurface is null");
        return;
    }
    int64_t timestamp;
    OHOS::Rect damage;
    sptr<SurfaceBuffer> buffer;
    sptr<SyncFence> syncFence = SyncFence::INVALID_FENCE;
    SurfaceError surfaceRet = firstStageEisSurface->AcquireBuffer(buffer, syncFence, timestamp, damage);
    CHECK_RETURN_ELOG(surfaceRet != SURFACE_ERROR_OK, "Failed to acquire stage eis buffer. %{public}d", surfaceRet);
    MEDIA_INFO_LOG("firstStageEis surface_ push buffer %{public}d x %{public}d, stride is %{public}d,"
                   "timestamp %{public}llu, size %{public}d",
                   buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight(), buffer->GetStride(),
                   (long long unsigned)timestamp, buffer->GetSize());
    surfaceRet = firstStageEisSurface->DetachBufferFromQueue(buffer);
    CHECK_RETURN_ELOG(surfaceRet != SURFACE_ERROR_OK, "Failed to detach stage eis buffer. %{public}d", surfaceRet);
    MEDIA_DEBUG_LOG("MovingPhotoStageEisListener::OnBufferAvailable warpBuffer cache size: %{public}zu",
        cachedBufferQueue_.size());
    if (cachedBufferQueue_.size() > MOVING_PHOTO_WARP_BUFFER_SIZE) {
        firstStageEisSurface->AttachBufferToQueue(buffer);
        firstStageEisSurface->ReleaseBuffer(buffer, -1);
        return;
    }
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        cachedBufferQueue_.emplace_back(buffer, timestamp);
    }
    StartProcessTimer();
}

MovingPhotoMediaOfflineSessionListener::MovingPhotoMediaOfflineSessionListener(
    sptr<MovingPhotoListener> movingPhotoListener)
    : movingPhotoListener_(movingPhotoListener),
      eisBufferQueue_("EisFrameRecordQueue", OFFLINE_EIS_BUFFER_QUEUE_SIZE),
      lifecycleManager_(nullptr)
{
    MEDIA_DEBUG_LOG("MovingPhotoMediaOfflineSessionListener ctor is called");
}

void MovingPhotoMediaOfflineSessionListener::SetLifecycleManager(wptr<MovingPhotoLifecycleManager> lifecycleManager)
{
    lifecycleManager_ = lifecycleManager;
}

void MovingPhotoMediaOfflineSessionListener::OnDrainCachedVideoBuffer(sptr<DrainImageManager> drainImageManager,
    int64_t timestamp)
{
    std::vector<sptr<FrameRecord>> frameRecords = eisBufferQueue_.GetAllElements();
    auto listener = movingPhotoListener_.promote();
    CHECK_RETURN_ELOG(listener == nullptr, "listener is nullptr");
    int64_t frontTimeStamp = static_cast<int64_t>(timestamp - 1600000000);
    vector<sptr<FrameRecord>> cacheFrameRecords;
    for (auto frame : frameRecords) {
        if (frame->GetTimeStamp() >= frontTimeStamp && frame->GetOfflineStatus()) {
            cacheFrameRecords.push_back(frame);
        }
    }
    MEDIA_DEBUG_LOG("MovingPhotoMediaOfflineSessionListener::OnDrainCachedVideoBuffer: %{public}zu",
        cacheFrameRecords.size());
    listener->DrainOutCacheStageEisImage(drainImageManager, cacheFrameRecords);
}

MovingPhotoMediaOfflineSessionListener::~MovingPhotoMediaOfflineSessionListener()
{
    MEDIA_DEBUG_LOG("MovingPhotoMediaOfflineSessionListener dctor is called");
    eisBufferQueue_.Clear();
}

void MovingPhotoMediaOfflineSessionListener::EnqueueBuffer(sptr<SurfaceBuffer> stageEisBuffer,
                                                           sptr<SurfaceBuffer> metaBuffer, int64_t timeStamp)
{
    MEDIA_DEBUG_LOG("EnqueueBuffer timeStamp %{public}llu", (long long unsigned)timeStamp);
    CHECK_RETURN_ELOG(stageEisBuffer == nullptr, "stageEisBuffer is nullptr");
    CHECK_RETURN_ELOG(metaBuffer == nullptr, "metaBuffer is nullptr");

    auto listener = movingPhotoListener_.promote();
    CHECK_RETURN_ELOG(listener == nullptr, "MovingPhotoListener is null");
    GraphicTransformType transform = listener->GetFrontTransformType();
    sptr<FrameRecord> frameRecord = new (std::nothrow) FrameRecord(stageEisBuffer, timeStamp, transform);
    CHECK_RETURN_ELOG(frameRecord == nullptr, "EnqueueBuffer create FrameRecord failed");
    frameRecord->SetMetaBuffer(metaBuffer);

    if (eisBufferQueue_.Full()) {
        MEDIA_INFO_LOG("EnqueueBuffer queue full, pop the oldest frame");
        sptr<FrameRecord> popFrame = eisBufferQueue_.Pop();
    }

    bool ret = eisBufferQueue_.Push(frameRecord);
    CHECK_RETURN_ELOG(!ret, "EnqueueBuffer push failed, queue is full");
}

sptr<SurfaceBuffer> MovingPhotoMediaOfflineSessionListener::GetBuffer(int64_t timeStamp)
{
    auto allElements = eisBufferQueue_.GetAllElements();
    for (auto &frameRecord : allElements) {
        if (frameRecord != nullptr && frameRecord->GetTimeStamp() == timeStamp) {
            return frameRecord->GetSurfaceBuffer();
        }
    }
    MEDIA_INFO_LOG("GetBuffer timestamp %{public}llu not found", (long long unsigned)timeStamp);
    return nullptr;
}

sptr<SurfaceBuffer> MovingPhotoMediaOfflineSessionListener::GetMetaBuffer(int64_t timeStamp)
{
    auto allElements = eisBufferQueue_.GetAllElements();
    for (auto &frameRecord : allElements) {
        if (frameRecord != nullptr && frameRecord->GetTimeStamp() == timeStamp) {
            sptr<SurfaceBuffer> metaSurfaceBuffer = frameRecord->GetMetaBuffer();
            frameRecord->UnLockMetaBuffer();
            return metaSurfaceBuffer;
        }
    }
    MEDIA_INFO_LOG("GetMetaBuffer: timestamp %{public}llu not found", (long long unsigned)timeStamp);
    return nullptr;
}

void MovingPhotoMediaOfflineSessionListener::OnOfflineSessionBufferDone(sptr<SurfaceBuffer> stageEisBuffer,
                                                                        int64_t timeStamp, bool isEosFlag)
{
    MEDIA_DEBUG_LOG("OnOfflineSessionBufferDone timestamp %{public}llu", (long long unsigned)timeStamp);
    sptr<FrameRecord> frameRecord = nullptr;
    auto allElements = eisBufferQueue_.GetAllElements();
    for (const auto &record : allElements) {
        if (record->GetTimeStamp() == timeStamp) {
            frameRecord = record;
            break;
        }
    }
    CHECK_RETURN_ELOG(frameRecord == nullptr, "OnOfflineSessionBufferDone: no matching frameRecord");
    frameRecord->SetStageEisManual(stageEisBuffer);
    frameRecord->SetOfflineStatus(true);

    auto listener = movingPhotoListener_.promote();
    CHECK_RETURN_ELOG(listener == nullptr, "listener is nullptr");
    listener->DrainOutStageEisImage(frameRecord, isEosFlag);
}

void MovingPhotoMediaOfflineSessionListener::OnOfflineSessionMetaBufferDone(sptr<Surface> offlineEisMetaSurface,
    sptr<SurfaceBuffer> metaBuffer, int64_t timeStamp, bool isEosFlag)
{
    MEDIA_DEBUG_LOG("OnOfflineSessionMetaBufferDone timestamp %{public}llu", (long long unsigned)timeStamp);
    sptr<SurfaceBuffer> metaBufferCopy = SurfaceBuffer::Create();
    CameraSurfaceBufferUtil::DeepCopyMetaBuffer(metaBuffer, metaBufferCopy);
    CHECK_RETURN_ELOG(metaBufferCopy == nullptr, "DeepCopyBuffer failed");
    SurfaceError ret = offlineEisMetaSurface->ReleaseBuffer(metaBuffer, SyncFence::INVALID_FENCE);
    if (ret != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("ReleaseBuffer metaBuffer failed, ret : %{public}d", ret);
    }
    sptr<FrameRecord> frameRecord = nullptr;
    auto allElements = eisBufferQueue_.GetAllElements();
    for (const auto &record : allElements) {
        if (record->GetTimeStamp() == timeStamp) {
            record->SetMetaBuffer(metaBufferCopy);
            frameRecord = record;
            break;
        }
    }
    CHECK_RETURN_ELOG(frameRecord == nullptr, "OnOfflineSessionBufferDone: no matching frameRecord");
}
}  // namespace CameraStandard
}  // namespace OHOS