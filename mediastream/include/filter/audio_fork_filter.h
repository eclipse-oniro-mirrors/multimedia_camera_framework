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
#ifndef OHOS_CAMERA_AUDIO_FORK_FILTER_H
#define OHOS_CAMERA_AUDIO_FORK_FILTER_H

#include "avbuffer_queue.h"
#include "cfilter.h"

namespace OHOS {
namespace CameraStandard {
class AudioForkFilter : public CFilter, public std::enable_shared_from_this<AudioForkFilter> {
public:
    explicit AudioForkFilter(std::string name, CFilterType type);
    ~AudioForkFilter() override;
    void Init(const std::shared_ptr<CEventReceiver>& receiver,
        const std::shared_ptr<CFilterCallback>& callback) override;
    Status DoPrepare() override;
    Status DoStart() override;
    Status DoPause() override;
    Status DoResume() override;
    Status DoStop() override;
    Status DoFlush() override;
    Status DoRelease() override;
    void SetParameter(const std::shared_ptr<Meta>& meta) override;
    void GetParameter(std::shared_ptr<Meta>& meta) override;
    Status LinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    Status UpdateNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    Status UnLinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    CFilterType GetFilterType();
    void OnLinkedResult(const sptr<AVBufferQueueProducer>& outputBufferQueue, std::shared_ptr<Meta>& meta);
    Status OnLinked(CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback) override;
    Status OnUpdated(CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback) override;
    Status OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback) override;
    void OnUnlinkedResult(const std::shared_ptr<Meta>& meta);
    void OnUpdatedResult(const std::shared_ptr<Meta>& meta);
    void ProcessAudioFork(std::shared_ptr<AVBuffer>& inputBuffer, const sptr<AVBufferQueueProducer>& inputBufferQueue);
    void OnBufferAvailable();
    Status CopyAVBuffer(std::shared_ptr<AVBuffer>& inputBuffer, std::shared_ptr<AVBuffer>& outputBuffer);

private:
    sptr<AVBufferQueueProducer> movieAudioProducer_ {nullptr};
    sptr<AVBufferQueueProducer> rawAudioProducer_ {nullptr};
    sptr<AVBufferQueueConsumer> consumer_ = nullptr;
    std::shared_ptr<AVBufferQueue> audioForkBufferQueue_ = nullptr;
    std::shared_ptr<CEventReceiver> receiver_ {nullptr};
    std::shared_ptr<CFilterCallback> filterCallback_ {nullptr};
    std::shared_ptr<CFilterLinkCallback> linkCallback_ {nullptr};
    std::shared_ptr<Meta> audioParameter_ {nullptr};
};

class AudioForkFilterLinkCallback : public CFilterLinkCallback {
public:
    explicit AudioForkFilterLinkCallback(const std::weak_ptr<AudioForkFilter>& audioForkFilter);
    ~AudioForkFilterLinkCallback() = default;

    void OnLinkedResult(const sptr<AVBufferQueueProducer>& queue, std::shared_ptr<Meta>& meta) override;
    void OnUnlinkedResult(std::shared_ptr<Meta> &meta) override;
    void OnUpdatedResult(std::shared_ptr<Meta> &meta) override;

private:
    std::weak_ptr<AudioForkFilter> audioForkFilter_;
};

class AudioForkBrokerListener : public IBrokerListener {
public:
    explicit AudioForkBrokerListener(const std::weak_ptr<AudioForkFilter>& muxerFilter,
        const sptr<AVBufferQueueProducer>& inputBufferQueue);

    sptr<IRemoteObject> AsObject() override;
    void OnBufferFilled(std::shared_ptr<AVBuffer>& avBuffer) override;

private:
    std::weak_ptr<AudioForkFilter> audioForkFilter_;
    wptr<AVBufferQueueProducer> inputBufferQueue_;
};

class AudioForkConsumerListener : public IConsumerListener {
public:
    explicit AudioForkConsumerListener(const std::weak_ptr<AudioForkFilter>& audioForkFilter);
    void OnBufferAvailable() override;

private:
    std::weak_ptr<AudioForkFilter> audioForkFilter_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_AUDIO_FORK_FILTER_H

