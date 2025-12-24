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

#ifndef OHOS_CAMERA_METADATA_FILTER_H
#define OHOS_CAMERA_METADATA_FILTER_H

#include "cfilter.h"

namespace OHOS {
namespace CameraStandard {
class MetaDataFilter : public CFilter, public std::enable_shared_from_this<MetaDataFilter> {
public:
    explicit MetaDataFilter(std::string name, CFilterType type);
    ~MetaDataFilter() override;
    Status SetCodecFormat(const std::shared_ptr<Meta>& format);
    void Init(const std::shared_ptr<CEventReceiver>& receiver,
        const std::shared_ptr<CFilterCallback>& callback) override;
    Status Configure(const std::shared_ptr<Meta>& parameter);
    Status SetInputMetaSurface(sptr<Surface> surface);
    sptr<Surface> GetInputMetaSurface();
    Status DoPrepare() override;
    Status DoStart() override;
    Status DoPause() override;
    Status DoResume() override;
    Status DoStop() override;
    Status DoFlush() override;
    Status DoRelease() override;
    Status NotifyEos();
    void SetParameter(const std::shared_ptr<Meta>& parameter) override;
    void GetParameter(std::shared_ptr<Meta>& parameter) override;
    Status LinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    Status UpdateNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    Status UnLinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    CFilterType GetFilterType();
    void OnLinkedResult(const sptr<AVBufferQueueProducer>& outputBufferQueue, std::shared_ptr<Meta>& meta);
    void OnUpdatedResult(std::shared_ptr<Meta>& meta);
    void OnUnlinkedResult(std::shared_ptr<Meta>& meta);
    void OnBufferAvailable();
    void GetFirstFrameTimestamp(int64_t& timestamp);

protected:
    Status OnLinked(CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback) override;
    Status OnUpdated(CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback) override;
    Status OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback) override;

private:
    void UpdateBufferConfig(std::shared_ptr<AVBuffer> buffer, int64_t timestamp);
    void GetMuxerFirstFrameTimestamp(int64_t& timestamp);

    static constexpr uint32_t METASURFACE_USAGE =
        BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA;
    std::string name_;
    CFilterType filterType_ {CFilterType::TIMED_METADATA};
    std::shared_ptr<CEventReceiver> eventReceiver_ {nullptr};
    std::shared_ptr<CFilterCallback> filterCallback_ {nullptr};
    std::shared_ptr<CFilterLinkCallback> onLinkedResultCallback_ {nullptr};
    std::shared_ptr<Meta> configureParameter_ {nullptr};
    std::shared_ptr<CFilter> nextFilter_ {nullptr};
    sptr<AVBufferQueueProducer> outputBufferQueueProducer_ {nullptr};
    sptr<Surface> inputSurface_ {nullptr};
    sptr<Surface> producerSurface_ {nullptr};

    bool isStop_ {false};
    bool refreshTotalPauseTime_ {false};
    int64_t startBufferTime_ {-1};
    int64_t latestBufferTime_ {-1};
    int64_t latestPausedTime_ {-1};
    int64_t totalPausedTime_ {0};
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_METADATA_FILTER_H