/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_MOVING_PHOTO_STAGE_SURFACE_WRAPPER_H
#define OHOS_CAMERA_MOVING_PHOTO_STAGE_SURFACE_WRAPPER_H

#include <condition_variable>
#include <deque>
#include <mutex>
#include <map>
#include <functional>
#include "surface.h"
#include "iconsumer_surface.h"
#include "frame_record.h"
#include "blocking_queue.h"
#include "moving_photo_listener.h"
#include "fixed_size_list.h"
#include "camera_surface_buffer_util.h"
#include "moving_photo_proxy.h"
#include "moving_photo_listener.h"
#include "camera_timer.h"

namespace OHOS {
namespace CameraStandard {

constexpr uint32_t MOVING_PHOTO_WARP_BUFFER_SIZE = 45;

// Forward declarations
class MovingPhotoLifecycleManager;

using StageEisElementType = std::pair<int64_t, sptr<SurfaceBuffer>>;

class MovingPhotoStageEisListener : public IBufferConsumerListener {
public:
    MovingPhotoStageEisListener(wptr<Surface> firstStageEisSurface, wptr<MovingPhotoListener> videoListener,
                                 shared_ptr<FixedSizeList<MetaElementType>> stageEisCache);
    ~MovingPhotoStageEisListener();
    void OnBufferAvailable() override;
    void SetLifecycleManager(wptr<MovingPhotoLifecycleManager> lifecycleManager);
    void UnregisterFromSurface();
    void ProcessCachedBuffers();
    void ReleaseWarpBufffer(sptr<Surface> firstStageEidSurface, sptr<SurfaceBuffer>& warpGridBuffer,
        int64_t timeStamp);

private:
    static constexpr uint32_t PROCESS_TIMER_INTERVAL_MS = 20;
    bool ProcessSingleBuffer(sptr<SurfaceBuffer> buffer, int64_t timestamp);
    void StartProcessTimer();
    void StopProcessTimer();
    void OnProcessTimerCallback();

    wptr<Surface> firstStageEidSurface_;
    wptr<MovingPhotoListener> videoListener_;
    shared_ptr<FixedSizeList<StageEisElementType>> stageEisCache_;
    wptr<MovingPhotoLifecycleManager> lifecycleManager_;
    std::deque<std::pair<sptr<SurfaceBuffer>, int64_t>> cachedBufferQueue_;
    std::mutex cacheMutex_;
    uint32_t processTimerId_ = 0;
    std::mutex timerMutex_;
};

class MovingPhotoMediaOfflineSessionListener : public MovingPhotoOfflineSessionCbIntf {
public:
    explicit MovingPhotoMediaOfflineSessionListener(sptr<MovingPhotoListener> movingPhotoListener);
    ~MovingPhotoMediaOfflineSessionListener();
    void EnqueueBuffer(sptr<SurfaceBuffer> stageEisBuffer, sptr<SurfaceBuffer> metaBuffer, int64_t timeStamp) override;
    sptr<SurfaceBuffer> GetBuffer(int64_t timeStamp) override;
    sptr<SurfaceBuffer> GetMetaBuffer(int64_t timeStamp) override;
    void OnOfflineSessionBufferDone(sptr<SurfaceBuffer> stageEisBuffer, int64_t timeStamp, bool isEosFlag) override;
    void OnOfflineSessionMetaBufferDone(sptr<Surface> offlineEisMetaSurface, sptr<SurfaceBuffer> metaBuffer,
                                        int64_t timeStamp, bool isEosFlag) override;
    void SetLifecycleManager(wptr<MovingPhotoLifecycleManager> lifecycleManager);
    void OnDrainCachedVideoBuffer(sptr<DrainImageManager> drainImageManager, int64_t timestamp);
private:
    static constexpr uint32_t OFFLINE_EIS_BUFFER_QUEUE_SIZE = 48;
    wptr<MovingPhotoListener> movingPhotoListener_;
    BlockingQueue<sptr<FrameRecord>> eisBufferQueue_;
    wptr<MovingPhotoLifecycleManager> lifecycleManager_;
};
}  // namespace CameraStandard
}  // namespace OHOS
#endif