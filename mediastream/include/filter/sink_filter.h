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

#ifndef OHOS_CAMERA_SINK_FILTER_H
#define OHOS_CAMERA_SINK_FILTER_H

#include "avbuffer_queue_define.h"
#include "cfilter.h"
#include "media_demuxer.h"

namespace OHOS {
namespace CameraStandard {
class SinkFilter;
class SinkTrack : public Media::IConsumerListener {
public:
    SinkTrack(const std::weak_ptr<SinkFilter>& filter);
    ~SinkTrack() = default;

    std::shared_ptr<AVBuffer> GetBuffer();
    void ReleaseBuffer(std::shared_ptr<AVBuffer>& outBuffer);
    void OnBufferAvailable() override;

    int32_t trackId_ = -1;
    std::string mimeType_ = {};
    std::shared_ptr<Meta> trackMeta_ = nullptr;
    sptr<AVBufferQueueProducer> producer_ = nullptr;
    sptr<AVBufferQueueConsumer> consumer_ = nullptr;
    std::shared_ptr<AVBufferQueue> bufferQueuq_ = nullptr;
    uint64_t writeCount_ = 0;

private:
    std::atomic<int32_t> bufferAvailableCount_ = 0;
    std::weak_ptr<SinkFilter> filter_;
};

class SinkFilter : public CFilter, public std::enable_shared_from_this<SinkFilter> {
public:
    explicit SinkFilter(std::string name, CFilterType type);
    ~SinkFilter() override;

    void Init(
        const std::shared_ptr<CEventReceiver>& receiver, const std::shared_ptr<CFilterCallback>& callback) override;
    Status DoPrepare() override;
    Status DoStart() override;
    Status DoStop() override;
    Status DoPause() override;
    Status DoResume() override;
    Status DoFlush() override;
    Status DoRelease() override;

    Status LinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    Status UpdateNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    Status UnLinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;

    void OnLinkedResult(const sptr<AVBufferQueueProducer>& outputBufferQueue, std::shared_ptr<Meta>& meta);
    void OnUpdatedResult(std::shared_ptr<Meta>& meta);
    void OnUnlinkedResult(std::shared_ptr<Meta>& meta);
    void ReleaseBuffer();
    void OnBufferAvailable();

protected:
    Status OnLinked(CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback) override;
    Status OnUpdated(CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback) override;
    Status OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback) override;

private:
    std::atomic_bool isLoopStarted {false};
    std::shared_ptr<CFilter> nextFilter_ {nullptr};
    std::shared_ptr<CFilterLinkCallback> onLinkedResultCallback_ {nullptr};
    std::shared_ptr<CEventReceiver> receiver_ {nullptr};
    std::shared_ptr<CFilterCallback> callback_ {nullptr};
    sptr<AVBufferQueueProducer> outputBufferProducer_ {nullptr};
    sptr<SinkTrack> audioTrack_ {nullptr};
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_SINK_FILTER_H
