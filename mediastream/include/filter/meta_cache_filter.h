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

#ifndef META_CACHE_FILTER_H
#define META_CACHE_FILTER_H

#include "avbuffer_queue.h"
#include "surface.h"
#include "blocking_queue.h"
#include "video_buffer_wrapper.h"
#include "fixed_size_list.h"
#include "meta_buffer_wrapper.h"
#include "engine_context_ext.h"
#include "cfilter.h"

namespace OHOS {
namespace CameraStandard {

using OHOS::Media::Task;
class MetaCacheFilter : public CFilter, public std::enable_shared_from_this<MetaCacheFilter>, public EngineContextExt {
public:

    explicit MetaCacheFilter(std::string name, CFilterType type);
    ~MetaCacheFilter() override;
    Status SetCodecFormat(const std::shared_ptr<Meta> &format);
    void Init(const std::shared_ptr<CEventReceiver> &receiver,
        const std::shared_ptr<CFilterCallback> &callback) override;
    Status Configure(const std::shared_ptr<Meta> &parameter);
    sptr<Surface> GetInputSurface() override;

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
    sptr<MetaBufferWrapper> FindMetaBufferWrapper(int64_t timestamp);
protected:
    Status OnLinked(CStreamType inType, const std::shared_ptr<Meta> &meta,
        const std::shared_ptr<CFilterLinkCallback> &callback) override;
    Status OnUpdated(CStreamType inType, const std::shared_ptr<Meta> &meta,
        const std::shared_ptr<CFilterLinkCallback> &callback) override;
    Status OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback) override;

private:
    std::shared_ptr<Task> taskPtr_{nullptr};
    std::shared_ptr<FixedSizeList<sptr<MetaBufferWrapper>>> metaCache_{nullptr};
    std::string name_;
    CFilterType filterType_ = CFilterType::MOVING_PHOTO_META_CACHE;

    std::shared_ptr<CEventReceiver> eventReceiver_;
    std::shared_ptr<CFilterCallback> filterCallback_;

    std::shared_ptr<CFilterLinkCallback> onLinkedResultCallback_;
    std::shared_ptr<Meta> configureParameter_;
    std::shared_ptr<CFilter> nextFilter_;

    sptr<AVBufferQueueProducer> outputBufferQueueProducer_;

    sptr<Surface> inputSurface_;
    sptr<Surface> outputSurface_;
    bool isStop_{false};
    bool refreshTotalPauseTime_{false};
    int64_t latestBufferTime_{-1};
    int64_t latestPausedTime_{-1};
    int64_t totalPausedTime_{0};
};
} // namespace CameraStandard
} // namespace OHOS
#endif // META_CACHE_FILTER_H
