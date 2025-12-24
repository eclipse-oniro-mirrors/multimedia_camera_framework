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

#ifndef AUDIO_PROCESS_FILTER_H
#define AUDIO_PROCESS_FILTER_H

#include "audio_capturer_options.h"
#include "avbuffer_queue.h"
#include "cfilter.h"
#include "offline_audio_effect_manager.h"

namespace OHOS {
namespace CameraStandard {
class AudioProcessFilter : public CFilter, public std::enable_shared_from_this<AudioProcessFilter> {
public:
    explicit AudioProcessFilter(std::string name, CFilterType type);
    ~AudioProcessFilter() override;
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
    Status InitAudioProcessConfig();
    void OnUnlinkedResult(const std::shared_ptr<Meta>& meta);
    void OnUpdatedResult(const std::shared_ptr<Meta>& meta);
    void OnBufferAvailable();
    void SetAudioCaptureOptions(AudioStandard::AudioCapturerOptions& options);
    void GetOutputAudioStreamInfo(AudioStandard::AudioStreamInfo& outputStreamInfo);

private:
    Status CreateOfflineAudioEffectChain();
    void ProcessLoop();
    Status SendRawAudioToEncoder(std::shared_ptr<AVBuffer>& inputBuffer);
    Status SendPostEditAudioToEncoder(std::shared_ptr<AVBuffer>& inputBuffer);

    sptr<AVBufferQueueProducer> procAudEncProducer_ {nullptr};
    sptr<AVBufferQueueProducer> rawAudEncProducer_ {nullptr};
    sptr<AVBufferQueueConsumer> consumer_ {nullptr};

    std::shared_ptr<CFilter> nextFilter_ {nullptr};
    std::shared_ptr<AVBufferQueue> audioProcessBufferQueue_ {nullptr};
    std::shared_ptr<CEventReceiver> receiver_ {nullptr};
    std::shared_ptr<CFilterCallback> filterCallback_ {nullptr};
    std::shared_ptr<CFilterLinkCallback> linkCallback_ {nullptr};
    std::shared_ptr<Meta> audioParameter_ {nullptr};
    std::shared_ptr<Task> taskPtr_ {nullptr};
    std::shared_ptr<AVBuffer> cachedAudBuf_ {nullptr};

    std::unique_ptr<AudioStandard::OfflineAudioEffectManager> offlineAudioEffectManager_ {nullptr};
    std::unique_ptr<AudioStandard::OfflineAudioEffectChain> offlineEffectChain_ {nullptr};

    std::vector<std::shared_ptr<AVBuffer>> cachedAudBufList_;

    std::string selectedChain_ {""};
    uint32_t cachedAudioFrameCount_ {0};
    int32_t preFrameSize_ {0};
    int32_t preBatchSize_ {0};
    int32_t postFrameSize_ {0};
    int32_t postBatchSize_ {0};

    AudioStandard::AudioCapturerOptions inputOptions_;
    AudioStandard::AudioStreamInfo outputStreamInfo_;

    std::mutex dataMutex_;
};

class AudioProcessFilterLinkCallback : public CFilterLinkCallback {
public:
    explicit AudioProcessFilterLinkCallback(const std::weak_ptr<AudioProcessFilter>& audioProcessFilter);
    ~AudioProcessFilterLinkCallback() = default;

    void OnLinkedResult(const sptr<AVBufferQueueProducer>& queue, std::shared_ptr<Meta>& meta) override;
    void OnUnlinkedResult(std::shared_ptr<Meta> &meta) override;
    void OnUpdatedResult(std::shared_ptr<Meta> &meta) override;

private:
    std::weak_ptr<AudioProcessFilter> audioProcessFilter_;
};

class AudioProcessConsumerListener : public IConsumerListener {
public:
    explicit AudioProcessConsumerListener(const std::weak_ptr<AudioProcessFilter>& audioProcessFilter);
    void OnBufferAvailable() override;

private:
    std::weak_ptr<AudioProcessFilter> audioProcessFilter_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_AUDIO_PROCESS_FILTER_H
