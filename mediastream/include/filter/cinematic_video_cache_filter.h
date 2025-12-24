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

#ifndef OHOS_CAMERA_CINEMATIC_CACHE_FILTER_H
#define OHOS_CAMERA_CINEMATIC_CACHE_FILTER_H

#include <deque>
#include "avbuffer_queue.h"
#include "surface.h"
#include "cfilter.h"
#include "sync_fence.h"

namespace OHOS {
namespace CameraStandard {

struct BufferProcessInfo {
    sptr<SurfaceBuffer> inputBuffer {nullptr};
    sptr<SurfaceBuffer> outputBuffer {nullptr};
    sptr<SyncFence> inputSyncFence {SyncFence::INVALID_FENCE};
    sptr<SyncFence> outputSyncFence {SyncFence::INVALID_FENCE};
    int64_t timestamp {-1};
};

class CinematicVideoCacheFilter : public CFilter, public std::enable_shared_from_this<CinematicVideoCacheFilter> {
public:
    explicit CinematicVideoCacheFilter(std::string name, CFilterType type);
    ~CinematicVideoCacheFilter() override;
    void Init(const std::shared_ptr<CEventReceiver> &receiver,
        const std::shared_ptr<CFilterCallback> &callback) override;
    Status Configure(const std::shared_ptr<Meta> &parameter);
    sptr<Surface> GetInputSurface() override;
    Status DoPrepare() override;
    Status DoStart() override;
    Status DoPause() override;
    Status DoResume() override;
    Status DoStop() override;
    Status DoFlush() override;
    Status DoRelease() override;
    Status LinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType) override;
    Status UpdateNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType) override;
    Status UnLinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType) override;
    CFilterType GetFilterType();
    void OnLinkedResult(const sptr<AVBufferQueueProducer> &outputBufferQueue, std::shared_ptr<Meta> &meta);
    void OnUpdatedResult(std::shared_ptr<Meta> &meta);
    void OnUnlinkedResult(std::shared_ptr<Meta> &meta);
    void OnBufferAvailable();

protected:
    Status OnLinked(CStreamType inType, const std::shared_ptr<Meta> &meta,
        const std::shared_ptr<CFilterLinkCallback> &callback) override;
    Status OnUpdated(CStreamType inType, const std::shared_ptr<Meta> &meta,
        const std::shared_ptr<CFilterLinkCallback> &callback) override;
    Status OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback) override;

private:
    GSError AcquireInputBuffer(BufferProcessInfo& bufferProcessInfo);
    GSError AttachInputBuffer(BufferProcessInfo& bufferProcessInfo);
    GSError DetachInputBuffer(BufferProcessInfo& bufferProcessInfo);
    GSError ReleaseInputBuffer(BufferProcessInfo& bufferProcessInfo);
    GSError ReleaseOutputBuffer(BufferProcessInfo& bufferProcessInfo);
    GSError AttachAndFlushOutputBuffer(BufferProcessInfo& bufferProcessInfo);
    GSError RequestAndDetachOutputBuffer(BufferProcessInfo& bufferProcessInfo);
    GSError ReturnBuffers(BufferProcessInfo& bufferProcessInfo);
    GSError AttachAndReleaseInputBuffer(BufferProcessInfo& bufferProcessInfo);
    GSError AttachAndFlushInputBuffer(BufferProcessInfo& bufferProcessInfo);
    void ExchangeBuffer(sptr<SurfaceBuffer>& inputBuffer, sptr<SurfaceBuffer>& outputBuffer);
    void AcquireAndDetachBufferFromQueue(sptr<Surface>& surface, sptr<SurfaceBuffer>& buffer);
    void AttachAndReleaseBufferToQueue(sptr<Surface>& surface, sptr<SurfaceBuffer>& buffer);
    void ProcessCachedFrames();
    BufferRequestConfig GetBufferRequestConfig(const sptr<SurfaceBuffer>& buffer);
    void UpdateOutputSurfaceInfo();
    void UpdateOutputTransform();
    void UpdateOutputBufferQueueSize();
    void UpdateOutputCycleBuffersNumber();

    std::string name_;
    CFilterType filterType_ = CFilterType::CINEMATIC_VIDEO_CACHE;

    std::shared_ptr<CEventReceiver> eventReceiver_;
    std::shared_ptr<CFilterCallback> filterCallback_;

    std::shared_ptr<Meta> configureParameter_;
    std::shared_ptr<CFilter> nextFilter_;

    sptr<Surface> inputSurface_;
    sptr<Surface> outputSurface_;

    std::deque<BufferProcessInfo> cachedBufferProcessInfoList_;
    int64_t firstFrameTimestamp_ {-1};

    GraphicTransformType outputSurfaceTransform_ {GRAPHIC_ROTATE_BUTT};
    bool isOutputBufferQueueSizeSet_ {false};
    bool isOutputCycleBuffersNumberSet_ {false};
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CINEMATIC_CACHE_FILTER_H