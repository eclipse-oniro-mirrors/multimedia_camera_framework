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

#ifndef OHOS_CAMERA_MOVING_PHOTO_AUDIO_ENCODER_FILTER_H
#define OHOS_CAMERA_MOVING_PHOTO_AUDIO_ENCODER_FILTER_H

#include "cfilter.h"
#include "media_codec.h"
#include "engine_context_ext.h"
#include "audio_buffer_wrapper.h"
#include "avbuffer_context.h"

namespace OHOS {
namespace CameraStandard {
class MovingPhotoAudioEncoderFilter : public CFilter,
    public std::enable_shared_from_this<MovingPhotoAudioEncoderFilter>, public EngineContextExt  {
public:
    explicit MovingPhotoAudioEncoderFilter(std::string name, CFilterType type);
    ~MovingPhotoAudioEncoderFilter() override;
    Status SetCodecFormat(const std::shared_ptr<Meta>& format);
    void Init(const std::shared_ptr<CEventReceiver>& receiver,
        const std::shared_ptr<CFilterCallback>& callback) override;
    Status Configure(const std::shared_ptr<Meta>& parameter);
    sptr<Surface> GetInputSurface() override;
    Status DoPrepare() override;
    Status DoStart() override;
    Status DoPause() override;
    Status DoResume() override;
    Status DoStop() override;
    Status DoFlush() override;
    Status DoRelease() override;
    Status NotifyEos();
    Status SetTranscoderMode();
    void SetParameter(const std::shared_ptr<Meta>& parameter) override;
    void GetParameter(std::shared_ptr<Meta>& parameter) override;
    Status LinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    Status UpdateNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    Status UnLinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    CFilterType GetFilterType();
    void OnLinkedResult(const sptr<AVBufferQueueProducer>& outputBufferQueue, std::shared_ptr<Meta>& meta);
    void OnUpdatedResult(std::shared_ptr<Meta>& meta);
    void OnUnlinkedResult(std::shared_ptr<Meta>& meta);
    void SetFaultEvent(const std::string& errMsg);
    void SetFaultEvent(const std::string& errMsg, int32_t ret);
    void SetCallingInfo(int32_t appUid, int32_t appPid, const std::string& bundleName, uint64_t instanceId);

    sptr<AVBufferQueueProducer> GetInputBufferQueue();
    void SetOutputBufferQueue(const sptr<AVBufferQueueProducer> &outputBufferQueue);

    bool EncodeAudioRecord(std::vector<sptr<AudioBufferWrapper>>& audioRecords);
    bool EncodeAudioRecord(sptr<AudioBufferWrapper> audioRecord);
    bool EnqueueBuffer(sptr<AudioBufferWrapper> audioRecord);
    void OnBufferAvailable();

protected:
    Status OnLinked(CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback) override;
    Status OnUpdated(CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback) override;
    Status OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback) override;

private:
    std::shared_ptr<AVBufferQueue> bufferQ_;
    sptr<AVBufferQueueProducer> producer_;
    sptr<AVBufferQueueConsumer> consumer_;

    sptr<AVBufferContext> avbufferContext_ = new AVBufferContext();

    std::mutex serialMutex_;
    std::string name_;
    CFilterType filterType_ {CFilterType::MOVING_PHOTO_AUDIO_ENCODE};
    std::shared_ptr<CEventReceiver> eventReceiver_ {nullptr};
    std::shared_ptr<CFilterCallback> filterCallback_ {nullptr};
    std::shared_ptr<CFilterLinkCallback> onLinkedResultCallback_ {nullptr};
    std::shared_ptr<MediaCodec> mediaCodec_ {nullptr};
    std::string codecMimeType_;
    std::shared_ptr<Meta> configureParameter_ {nullptr};
    std::shared_ptr<CFilter> nextFilter_ {nullptr};
    std::string bundleName_;
    std::shared_ptr<Meta> transcoderMeta_ {nullptr};
    bool isTranscoderMode_ {false};
    uint64_t instanceId_ {0};
    int32_t appUid_ {0};
    int32_t appPid_ {0};
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_AUDIO_ENCODER_FILTER_H
