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

#ifndef VIDEO_CACHE_FILTER_H
#define VIDEO_CACHE_FILTER_H

#include "avbuffer_queue.h"
#include "surface.h"
#include "blocking_queue.h"
#include "video_buffer_wrapper.h"
#include "meta_buffer_wrapper.h"
#include "engine_context_ext.h"
#include "cfilter.h"
#include "sp_holder.h"

namespace OHOS {
namespace CameraStandard {

using OHOS::Media::Task;
class VideoCacheFilter : public CFilter, public std::enable_shared_from_this<VideoCacheFilter>,
    public EngineContextExt {
public:
    const int32_t DEFAULT_BUFFER_SIZE = 45;
    const int32_t PRE_CACHE_FRAME_COUNT = 45;
    const int32_t POST_CACHE_FRAME_COUNT = 45;

    explicit VideoCacheFilter(std::string name, CFilterType type);
    ~VideoCacheFilter() override;
    Status SetCodecFormat(const std::shared_ptr<Meta> &format);
    void Init(const std::shared_ptr<CEventReceiver> &receiver,
        const std::shared_ptr<CFilterCallback> &callback) override;
    Status Configure(const std::shared_ptr<Meta> &parameter);
    sptr<Surface> GetInputSurface() override;
    void SetCacheFrameCount(uint32_t preCacheFrameCount, uint32_t postCacheFrameCount);

    // 根据pipeline的callback做链接
    Status DoPrepare() override;
    Status DoStart() override;
    Status DoPause() override;
    Status DoResume() override;
    Status DoStop() override;
    Status DoFlush() override;
    Status DoRelease() override;
    Status NotifyEos();
    void SetParameter(const std::shared_ptr<Meta> &parameter) override;
    void GetParameter(std::shared_ptr<Meta> &parameter) override;
    Status LinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType) override;
    Status UpdateNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType) override;
    Status UnLinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType) override;
    CFilterType GetFilterType();
    void OnLinkedResult(const sptr<AVBufferQueueProducer> &outputBufferQueue, std::shared_ptr<Meta> &meta);
    void OnUpdatedResult(std::shared_ptr<Meta> &meta);
    void OnUnlinkedResult(std::shared_ptr<Meta> &meta);
    void OnBufferAvailable();

    void StartOnceRecord(int32_t rotation, int32_t captureId);
    inline void SetClearFlag()
    {
        clearFlag_ = true;
    }
    void ClearCache(uint64_t shutterTime);
protected:
    Status OnLinked(CStreamType inType, const std::shared_ptr<Meta> &meta,
        const std::shared_ptr<CFilterLinkCallback> &callback) override;
    Status OnUpdated(CStreamType inType, const std::shared_ptr<Meta> &meta,
        const std::shared_ptr<CFilterLinkCallback> &callback) override;
    Status OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback) override;

private:
    sptr<MetaBufferWrapper> FindMetaBuffer(int64_t timestamp);
    void DrainImage(sptr<VideoBufferWrapper> videoBufferWrapper);

    std::shared_ptr<Task> taskPtr_{nullptr};
    std::atomic<bool> clearFlag_ { false };
    std::atomic<bool> popFlag_ { false };

    int64_t shutterTime_ = 0;

    std::string name_;
    CFilterType filterType_ = CFilterType::MOVING_PHOTO_VIDEO_CACHE;

    std::shared_ptr<CEventReceiver> eventReceiver_;
    std::shared_ptr<CFilterCallback> filterCallback_;

    std::shared_ptr<CFilterLinkCallback> onLinkedResultCallback_;
    std::shared_ptr<Meta> configureParameter_;
    SpHolder<std::shared_ptr<CFilter>> nextFilter_;

    sptr<AVBufferQueueProducer> outputBufferQueueProducer_;

    sptr<Surface> inputSurface_;
    sptr<Surface> outputSurface_;
    bool isStop_{false};
    bool refreshTotalPauseTime_{false};
    int64_t latestBufferTime_{-1};
    int64_t latestPausedTime_{-1};
    int64_t totalPausedTime_{0};

    BlockingQueue<sptr<VideoBufferWrapper>> videoBufferWrapperQueue_;
    uint32_t preCacheFrameCount_ = PRE_CACHE_FRAME_COUNT;
    uint32_t postCacheFrameCount_ = POST_CACHE_FRAME_COUNT;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // VIDEO_CACHE_FILTER_H
