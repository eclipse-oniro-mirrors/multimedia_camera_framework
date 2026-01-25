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

#ifndef OHOS_CAMERA_MOVING_PHOTO_LISTENER_H
#define OHOS_CAMERA_MOVING_PHOTO_LISTENER_H
 
#include "drain_manager.h"
#include "moving_photo_proxy.h"
#include "safe_map.h"
#include "moving_photo_surface_wrapper.h"
#include "surface.h"
#include "fixed_size_list.h"
#include "blocking_queue.h"

namespace OHOS::CameraStandard {
class SessionDrainImageCallback;
using MetaElementType = std::pair<int64_t, sptr<SurfaceBuffer>>;
using OnceRecordTimeInfo = std::pair<int64_t, int64_t>;
class MovingPhotoListener : public MovingPhotoSurfaceWrapper::SurfaceBufferListener {
public:
    explicit MovingPhotoListener(sptr<MovingPhotoSurfaceWrapper> surfaceWrapper, wptr<Surface> metaSurface,
        shared_ptr<FixedSizeList<MetaElementType>> metaCache, uint32_t preCacheFrameCount,
        uint32_t postCacheFrameCount, VideoType listenerType);
    ~MovingPhotoListener() override;
    void OnBufferArrival(sptr<SurfaceBuffer> buffer, int64_t timestamp, GraphicTransformType transform) override;
    void DrainOutImage(sptr<SessionDrainImageCallback> drainImageCallback);
    void RemoveDrainImageManager(sptr<SessionDrainImageCallback> drainImageCallback);
    void StopDrainOut();
    void ClearCache(uint64_t timestamp);
    void SetClearFlag();
    uint32_t FrameAlign(sptr<SessionDrainImageCallback> drainImageCallback, std::vector<sptr<FrameRecord>>& frameList);
    bool RefillMeta(sptr<SurfaceBuffer> buffer, int64_t timestamp);

    inline int64_t GetQueueFrontTimestamp()
    {
        CHECK_RETURN_RET_ELOG(recorderBufferQueue_.Empty(), 0, "recorderBufferQueue_ is empty");
        return recorderBufferQueue_.Front()->GetTimeStamp();
    }

    inline int64_t GetQueueBackTimestamp()
    {
        CHECK_RETURN_RET_ELOG(recorderBufferQueue_.Empty(), 0, "recorderBufferQueue_ is empty");
        return recorderBufferQueue_.Back()->GetTimeStamp();
    }

    inline void SetBrotherListener(sptr<MovingPhotoListener> anotherListener)
    {
        lock_guard<mutex> lock(brotherListenerMutex_);
        brotherListener_ = anotherListener;
        CHECK_RETURN_ELOG(anotherListener == nullptr, "SetBrotherListener nullptr");
    }

    inline void SetXtStyleType(VideoType type)
    {
        lock_guard<mutex> lock(xtTypeMutex_);
        listenerXtStyleType_ = type;
    }

    inline VideoType GetXtStyleType()
    {
        lock_guard<mutex> lock(xtTypeMutex_);
        return listenerXtStyleType_;
    }
    
    inline int64_t GetTopTimeStamp()
    {
        CHECK_RETURN_RET_ELOG(recorderBufferQueue_.Empty(), 0, "recorderBufferQueue_ is empty");
        if (recorderBufferQueue_.Front() != nullptr) {
            return recorderBufferQueue_.Front()->GetTimeStamp();
        }
        return 0;
    }
    sptr<MovingPhotoSurfaceWrapper> movingPhotoSurfaceWrapper_;
private:
    VideoType listenerXtStyleType_ = VideoType::ORIGIN_VIDEO;
    wptr<Surface> metaSurface_;
    shared_ptr<FixedSizeList<MetaElementType>> metaCache_;
    BlockingQueue<sptr<FrameRecord>> recorderBufferQueue_;
    SafeMap<sptr<SessionDrainImageCallback>, sptr<DrainImageManager>> callbackMap_;
    SafeMap<uint64_t, shared_ptr<OnceRecordTimeInfo>> timeInfoMap_;
    std::atomic<bool> isNeededClear_ { false };
    std::atomic<bool> isNeededPop_ { false };
    int64_t shutterTime_;
    uint64_t postCacheFrameCount_;
    wptr<MovingPhotoListener> brotherListener_ = nullptr;
    mutex brotherListenerMutex_;
    mutex xtTypeMutex_;
};

class MovingPhotoMetaListener : public IBufferConsumerListener {
public:
    explicit MovingPhotoMetaListener(wptr<Surface> surface, shared_ptr<FixedSizeList<MetaElementType>> metaCache,
        wptr<MovingPhotoListener> videoListener);
    ~MovingPhotoMetaListener();
    void OnBufferAvailable() override;
private:
    wptr<Surface> surface_;
    shared_ptr<FixedSizeList<MetaElementType>> metaCache_;
    wptr<MovingPhotoListener> videoListener_;
};

class SessionDrainImageCallback : public DrainImageCallback {
public:
    explicit SessionDrainImageCallback(std::vector<sptr<FrameRecord>>& frameCacheList,
                                       wptr<MovingPhotoListener> listener,
                                       wptr<MovingPhotoVideoCache> movingPhotoVideoCache,
                                       uint64_t timestamp,
                                       int32_t rotation,
                                       int32_t captureId);
    ~SessionDrainImageCallback();
    void OnDrainImage(sptr<FrameRecord> frame) override;
    void OnDrainImageFinish(bool isFinished) override;
    inline uint64_t GetTimestamp()
    {
        return timestamp_;
    }
private:
    void OnDrainFrameRecord(sptr<FrameRecord> frame);
    std::mutex mutex_;
    std::vector<sptr<FrameRecord>> frameCacheList_;
    wptr<MovingPhotoListener> listener_;
    wptr<MovingPhotoVideoCache> movingPhotoVideoCache_ = nullptr;
    uint64_t timestamp_;
    int32_t rotation_;
    int32_t captureId_;
};
} // namespace OHOS::CameraStandard
#endif // OHOS_CAMERA_MOVING_PHOTO_LISTENER_H