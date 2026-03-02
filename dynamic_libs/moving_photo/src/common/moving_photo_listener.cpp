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

#include "moving_photo_listener.h"
#include "camera_log.h"
#include "sync_fence.h"
#include "moving_photo_video_cache.h"

namespace OHOS::CameraStandard {
SessionDrainImageCallback::SessionDrainImageCallback(std::vector<sptr<FrameRecord>>& frameCacheList,
                                                     wptr<MovingPhotoListener> listener,
                                                     wptr<MovingPhotoVideoCache> movingPhotoVideoCache,
                                                     uint64_t timestamp,
                                                     int32_t rotation,
                                                     int32_t captureId)
    : frameCacheList_(frameCacheList),
      listener_(listener),
      movingPhotoVideoCache_(movingPhotoVideoCache),
      timestamp_(timestamp),
      rotation_(rotation),
      captureId_(captureId)
{
}

SessionDrainImageCallback::~SessionDrainImageCallback()
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("~SessionDrainImageCallback enter");
    timestamp_ = 0;
    rotation_ = 0;
    captureId_ = 0;
    // LCOV_EXCL_STOP
}

void SessionDrainImageCallback::OnDrainImage(sptr<FrameRecord> frame)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("OnDrainImage enter");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        frameCacheList_.push_back(frame);
    }
    OnDrainFrameRecord(frame);
    // LCOV_EXCL_STOP
}

void SessionDrainImageCallback::OnDrainFrameRecord(sptr<FrameRecord> frame)
{
    MEDIA_DEBUG_LOG("OnDrainFrameRecord start");
    CHECK_RETURN_ELOG(frame == nullptr, "frame is null");
    auto videoCache = movingPhotoVideoCache_.promote();
    CHECK_RETURN_ELOG(videoCache == nullptr, "movingPhotoVideoCache is null");
    if (frame->IsIdle() && videoCache) {
        videoCache->CacheFrame(frame);
    } else if (frame->IsFinishCache() && videoCache) {
        videoCache->OnImageEncoded(frame, frame->IsEncoded());
    } else if (frame->IsReadyConvert()) {
        MEDIA_DEBUG_LOG("frame is ready convert");
    } else {
        MEDIA_INFO_LOG("videoCache and frame is not useful");
    }
}

void SessionDrainImageCallback::OnDrainImageFinish(bool isFinished)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("OnDrainImageFinish enter");
    auto movingPhotoVideoCache = movingPhotoVideoCache_.promote();
    CHECK_RETURN_ELOG(movingPhotoVideoCache == nullptr, "movingPhotoVideoCache is null");
    std::lock_guard<std::mutex> lock(mutex_);
    movingPhotoVideoCache->GetFrameCachedResult(
        frameCacheList_,
        [movingPhotoVideoCache](const std::vector<sptr<FrameRecord>> &lframeRecords,
                                uint64_t ltimestamp,
                                int32_t lrotation,
                                int32_t lcaptureId) {
            movingPhotoVideoCache->DoMuxerVideo(lframeRecords, ltimestamp, lrotation, lcaptureId);
        },
        timestamp_,
        rotation_,
        captureId_);
    auto listener = listener_.promote();
    CHECK_RETURN(!listener || !isFinished);
    listener->RemoveDrainImageManager(this);
    // LCOV_EXCL_STOP
}

// LCOV_EXCL_START
MovingPhotoListener::MovingPhotoListener(sptr<MovingPhotoSurfaceWrapper> surfaceWrapper, wptr<Surface> metaSurface,
    shared_ptr<FixedSizeList<MetaElementType>> metaCache, uint32_t preCacheFrameCount, uint32_t postCacheFrameCount,
    VideoType listenerType)
    : movingPhotoSurfaceWrapper_(surfaceWrapper),
      listenerXtStyleType_(listenerType),
      metaSurface_(metaSurface),
      metaCache_(metaCache),
      recorderBufferQueue_("videoBuffer", preCacheFrameCount),
      postCacheFrameCount_(postCacheFrameCount)
{
    shutterTime_ = 0;
}

MovingPhotoListener::~MovingPhotoListener()
{
    recorderBufferQueue_.SetActive(false);
    if (metaCache_) {
        metaCache_->clear();
    }
    recorderBufferQueue_.Clear();
    MEDIA_ERR_LOG("HStreamRepeat::LivePhotoListener ~ end");
}

void MovingPhotoListener::RemoveDrainImageManager(sptr<SessionDrainImageCallback> callback)
{
    callbackMap_.Erase(callback);
    MEDIA_INFO_LOG("RemoveDrainImageManager drainImageManagerVec_ Start %d", callbackMap_.Size());
}

void MovingPhotoListener::ClearCache(uint64_t timestamp)
{
    CHECK_RETURN(!isNeededClear_.load());
    MEDIA_INFO_LOG("ClearCache enter");
    shutterTime_ = static_cast<int64_t>(timestamp);
    while (!recorderBufferQueue_.Empty()) {
        sptr<FrameRecord> popFrame = recorderBufferQueue_.Front();
        MEDIA_DEBUG_LOG("surface_ release surface buffer %{public}llu, timestamp %{public}llu",
            (long long unsigned)popFrame->GetTimeStamp(), (long long unsigned)timestamp);
        if (popFrame->GetTimeStamp() > shutterTime_) {
            isNeededClear_ = false;
            MEDIA_INFO_LOG("ClearCache end");
            return;
        }
        recorderBufferQueue_.Pop();
        popFrame->ReleaseSurfaceBuffer(movingPhotoSurfaceWrapper_);
    }
    isNeededPop_ = true;
}

void MovingPhotoListener::SetClearFlag()
{
    MEDIA_INFO_LOG("need clear cache!");
    isNeededClear_ = true;
}

void MovingPhotoListener::StopDrainOut()
{
    MEDIA_INFO_LOG("StopDrainOut drainImageManagerVec_ Start %d", callbackMap_.Size());
    callbackMap_.Iterate([](const sptr<SessionDrainImageCallback> callback, sptr<DrainImageManager> manager) {
        manager->DrainFinish(false);
    });
    callbackMap_.Clear();
}

void MovingPhotoListener::OnBufferArrival(sptr<SurfaceBuffer> buffer, int64_t timestamp, GraphicTransformType transform)
{
    MEDIA_DEBUG_LOG("OnBufferArrival timestamp %{public}llu", (long long unsigned)timestamp);
    if (recorderBufferQueue_.Full()) {
        MEDIA_DEBUG_LOG("surface_ release surface buffer");
        sptr<FrameRecord> popFrame = recorderBufferQueue_.Pop();
        popFrame->ReleaseSurfaceBuffer(movingPhotoSurfaceWrapper_);
        sptr<Surface> metaSurface = metaSurface_.promote();
        if (metaSurface) {
            popFrame->ReleaseMetaBuffer(metaSurface, true);
        }
        MEDIA_DEBUG_LOG("surface_ release surface buffer: %{public}s, refCount: %{public}d",
                        popFrame->GetFrameId().c_str(), popFrame->GetSptrRefCount());
    }
    MEDIA_DEBUG_LOG("surface_ push buffer %{public}d x %{public}d, stride is %{public}d",
                    buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight(), buffer->GetStride());
    sptr<FrameRecord> frameRecord = new (std::nothrow) FrameRecord(buffer, timestamp, transform);
    CHECK_RETURN_ELOG(frameRecord == nullptr, "MovingPhotoListener::OnBufferAvailable create FrameRecord fail!");
    bool shouldClearAndPopBuffer = isNeededClear_ && isNeededPop_;
    if (shouldClearAndPopBuffer) {
        if (timestamp < shutterTime_) {
            frameRecord->ReleaseSurfaceBuffer(movingPhotoSurfaceWrapper_);
            MEDIA_INFO_LOG("Drop this frame in cache");
            return;
        } else {
            isNeededClear_ = false;
            isNeededPop_ = false;
            MEDIA_INFO_LOG("ClearCache end");
        }
    }
    recorderBufferQueue_.Push(frameRecord);
    auto metaPair =
        metaCache_->find_if([timestamp](const MetaElementType &value) { return value.first == timestamp; });
    if (metaPair.has_value()) {
        MEDIA_DEBUG_LOG("frame has meta");
        frameRecord->SetMetaBuffer(metaPair.value().second);
    }
    vector<sptr<SessionDrainImageCallback>> callbacks;
    callbackMap_.Iterate(
        [frameRecord, &callbacks](const sptr<SessionDrainImageCallback> callback, sptr<DrainImageManager> manager) {
            callbacks.push_back(callback);
        });
    for (sptr<SessionDrainImageCallback> drainImageCallback : callbacks) {
        sptr<DrainImageManager> drainImageManager;
        if (callbackMap_.Find(drainImageCallback, drainImageManager)) {
            std::lock_guard<std::mutex> lock(drainImageManager->drainImageLock_);
            drainImageManager->DrainImage(frameRecord);
        }
    }
}

uint32_t MovingPhotoListener::FrameAlign(sptr<SessionDrainImageCallback> drainImageCallback,
    std::vector<sptr<FrameRecord>>& frameList)
{
    shared_ptr<OnceRecordTimeInfo> recordInfo =
        std::make_shared<OnceRecordTimeInfo>(GetQueueFrontTimestamp(), GetQueueBackTimestamp());
    CHECK_RETURN_RET(!recordInfo->first, 0);
    timeInfoMap_.EnsureInsert(drainImageCallback->GetTimestamp(), recordInfo);
    MEDIA_INFO_LOG("%{public}d timestamp:drainImageCallback->GetTimestamp()%{public}" PRIu64,
        static_cast<int32_t>(listenerXtStyleType_), drainImageCallback->GetTimestamp());
    shared_ptr<OnceRecordTimeInfo> brotherRecordInfo = nullptr;
    {
        lock_guard<mutex> lock(brotherListenerMutex_);
        auto brotherListener = brotherListener_.promote();
        CHECK_RETURN_RET_ELOG(brotherListener == nullptr, 0, "brotherListener is nullptr. no need FrameAlign");
        int32_t loopCnt = 10;
        while (loopCnt--) {
            brotherRecordInfo = brotherListener->timeInfoMap_.ReadVal(drainImageCallback->GetTimestamp());
            MEDIA_INFO_LOG("wait brotherListener ReadVal %{public}d, %{public}d",
                loopCnt, static_cast<int32_t>(listenerXtStyleType_));
            CHECK_BREAK(brotherRecordInfo != nullptr);
            constexpr auto sleepTime = 5;
            std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));
        }
    }
    CHECK_RETURN_RET_ELOG(brotherRecordInfo == nullptr, 0, "FrameAlign brotherRecordInfo is nullptr");
    MEDIA_INFO_LOG("movingphoto frame align frameListSizeBefore:%{public}zu %{public}d",
        frameList.size(), static_cast<int32_t>(listenerXtStyleType_));
    uint32_t eraseCnt = 0;
    for (auto iter = frameList.begin(); iter != frameList.end() && (*iter)->GetTimeStamp() < brotherRecordInfo->first;
        iter++, eraseCnt++) {
        MEDIA_INFO_LOG("%{public}d, iter->GetTimeStamp():%{public}" PRIi64
                       ", brotherRecordInfo->first:%{public}" PRIi64,
            static_cast<int32_t>(listenerXtStyleType_), (*iter)->GetTimeStamp(), brotherRecordInfo->first);
    }
    CHECK_EXECUTE(eraseCnt, frameList.erase(frameList.begin(), frameList.begin() + eraseCnt));
    MEDIA_INFO_LOG("movingphoto frame align frameListSizeAfter:%{public}zu %{public}d",
        frameList.size(), static_cast<int32_t>(listenerXtStyleType_));

    CHECK_RETURN_RET(frameList.empty(), 0);
    return frameList.back()->GetTimeStamp() < brotherRecordInfo->second ? static_cast<uint32_t>(
        std::round((brotherRecordInfo->second - frameList.back()->GetTimeStamp()) / VIDEO_FRAME_INTERVAL_NS)) : 0;
}

bool MovingPhotoListener::RefillMeta(sptr<SurfaceBuffer> buffer, int64_t timestamp)
{
    std::queue<sptr<FrameRecord>> tempRecordQueue;
    bool isFind = false;
    while (!recorderBufferQueue_.Empty()) {
        if (recorderBufferQueue_.Back()->GetTimeStamp() == timestamp) {
            recorderBufferQueue_.Back()->SetMetaBuffer(buffer);
            isFind = true;
        }
        if (recorderBufferQueue_.Back()->GetTimeStamp() <= timestamp) {
            break;
        }
        tempRecordQueue.push(recorderBufferQueue_.PopBack());
    }
    MEDIA_DEBUG_LOG("tempRecordQueue.size():%{public}zu isFind:%{public}d", tempRecordQueue.size(), isFind);
    while (!tempRecordQueue.empty()) {
        recorderBufferQueue_.Push(tempRecordQueue.front());
        tempRecordQueue.pop();
    }
    return isFind;
}

void MovingPhotoListener::DrainOutImage(sptr<SessionDrainImageCallback> drainImageCallback)
{
    // Convert recorderBufferQueue_ to a vector
    MEDIA_INFO_LOG("MovingPhotoListener DrainOutImage E %{public}d", static_cast<int32_t>(listenerXtStyleType_));
    std::vector<sptr<FrameRecord>> frameList = recorderBufferQueue_.GetAllElements();
    uint32_t supCnt = FrameAlign(drainImageCallback, frameList);
    MEDIA_INFO_LOG("listenerType:%{public}d FrameAlign supCnt:%{public}u",
        static_cast<int32_t>(listenerXtStyleType_), supCnt);
    size_t totalFrameCount = frameList.size() + static_cast<size_t>(postCacheFrameCount_) + static_cast<size_t>(supCnt);
    sptr<DrainImageManager> drainImageManager =
        new DrainImageManager(drainImageCallback, totalFrameCount);
    MEDIA_INFO_LOG("DrainOutImage enter %{public}zu", totalFrameCount);
    callbackMap_.Insert(drainImageCallback, drainImageManager);
    CHECK_EXECUTE(!frameList.empty(), frameList.back()->SetCoverFrame());
    std::lock_guard<std::mutex> lock(drainImageManager->drainImageLock_);
    for (const auto& frame : frameList) {
        MEDIA_DEBUG_LOG("DrainOutImage enter DrainImage");
        drainImageManager->DrainImage(frame);
    }
}

void MovingPhotoMetaListener::OnBufferAvailable()
{
    sptr<Surface> metaSurface = surface_.promote();
    CHECK_RETURN_ELOG(!metaSurface, "streamRepeat surface is null");
    MEDIA_DEBUG_LOG("metaSurface_ OnBufferAvailable %{public}u", metaSurface->GetQueueSize());
    int64_t timestamp;
    OHOS::Rect damage;
    sptr<SurfaceBuffer> buffer;
    sptr<SyncFence> syncFence = SyncFence::INVALID_FENCE;
    SurfaceError surfaceRet = metaSurface->AcquireBuffer(buffer, syncFence, timestamp, damage);
    CHECK_RETURN_ELOG(surfaceRet != SURFACE_ERROR_OK, "Failed to acquire meta surface buffer");
    surfaceRet = metaSurface->DetachBufferFromQueue(buffer);
    CHECK_RETURN_ELOG(surfaceRet != SURFACE_ERROR_OK, "Failed to detach meta buffer. %{public}d", surfaceRet);
    auto videoListener = videoListener_.promote();
    bool isNeedAddMetaCache = true;
    CHECK_EXECUTE(videoListener, isNeedAddMetaCache = !videoListener->RefillMeta(buffer, timestamp));
    CHECK_EXECUTE(isNeedAddMetaCache, metaCache_->add({timestamp, buffer}));
}

MovingPhotoMetaListener::MovingPhotoMetaListener(wptr<Surface> surface,
    shared_ptr<FixedSizeList<MetaElementType>> metaCache, wptr<MovingPhotoListener> videoListener)
    : surface_(surface), metaCache_(metaCache), videoListener_(videoListener)
{
}

MovingPhotoMetaListener::~MovingPhotoMetaListener()
{
    MEDIA_ERR_LOG("HStreamRepeat::MovingPhotoMetaListener ~ end");
}
// LCOV_EXCL_STOP
} // namespace OHOS::CameraStandard