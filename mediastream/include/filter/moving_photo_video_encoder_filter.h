/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
 
#ifndef MOVING_PHOTO_VIDEO_ENCODER_FILTER_H
#define MOVING_PHOTO_VIDEO_ENCODER_FILTER_H
 
#include <cstring>
#include "surface.h"
#include "buffer/avbuffer.h"
#include "buffer/avallocator.h"
#include "buffer/avbuffer_queue.h"
#include "buffer/avbuffer_queue_producer.h"
#include "buffer/avbuffer_queue_consumer.h"
#include "avcodec_common.h"
#include "video_encoder_adapter.h"
#include "video_buffer_wrapper.h"
#include "avbuffer_context.h"
#include "engine_context_ext.h"
#include "cfilter.h"

namespace OHOS {
namespace CameraStandard {
using EncodeCallback = std::function<void(sptr<VideoBufferWrapper>, bool)>;
 
constexpr int32_t RECORDER_KEY_FRAME_INTERVAL = 10;
constexpr int64_t RECORDER_NANOSEC_RANGE = 1600000000LL;
 
class MovingPhotoVideoEncoderFilter : public CFilter,
    public std::enable_shared_from_this<MovingPhotoVideoEncoderFilter>, public EngineContextExt {
public:
    explicit MovingPhotoVideoEncoderFilter(std::string name, CFilterType type);
    ~MovingPhotoVideoEncoderFilter() override;
    Status SetCodecFormat(const std::shared_ptr<Meta> &format);
    void Init(const std::shared_ptr<CEventReceiver> &receiver,
        const std::shared_ptr<CFilterCallback> &callback) override;
    Status Configure(const std::shared_ptr<Meta> &parameter);
    Status SetWatermark(std::shared_ptr<AVBuffer> &waterMarkBuffer);
    Status SetStopTime();
    Status SetTransCoderMode();
    sptr<Surface> GetInputSurface() override;
    Status DoPrepare() override;
    Status DoStart() override;
    Status DoPause() override;
    Status DoResume() override;
    Status Reset();
    Status DoStop() override;
    Status DoFlush() override;
    Status DoRelease() override;
    Status NotifyEos(int64_t pts);
    void SetParameter(const std::shared_ptr<Meta> &parameter) override;
    void GetParameter(std::shared_ptr<Meta> &parameter) override;
    Status LinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType) override;
    Status UpdateNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType) override;
    Status UnLinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType) override;
    CFilterType GetFilterType();
    void OnLinkedResult(const sptr<AVBufferQueueProducer> &outputBufferQueue, std::shared_ptr<Meta> &meta);
    void OnUpdatedResult(std::shared_ptr<Meta> &meta);
    void OnUnlinkedResult(std::shared_ptr<Meta> &meta);
    void SetCallingInfo(int32_t appUid, int32_t appPid, const std::string &bundleName, uint64_t instanceId);
    void OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode);
    void OnReportKeyFramePts(std::string KeyFramePts);
 
    sptr<AVBufferContext> GetAVBufferContext();
    Status ReleaseOutputBuffer(uint32_t index);
    void EncodeVideoBuffer(sptr<VideoBufferWrapper> videoBufferWrapper, EncodeCallback encodeCallback);
    bool EncodeSurfaceBuffer(sptr<VideoBufferWrapper> videoBufferWrapper);
    void RequestIFrameIfNeed(sptr<VideoBufferWrapper> videoBufferWrapper);

    inline std::shared_ptr<Meta> GetConfigureParameter() {
        return configureParameter_;
    }
protected:
    Status OnLinked(CStreamType inType, const std::shared_ptr<Meta> &meta,
        const std::shared_ptr<CFilterLinkCallback> &callback) override;
    Status OnUpdated(CStreamType inType, const std::shared_ptr<Meta> &meta,
        const std::shared_ptr<CFilterLinkCallback> &callback) override;
    Status OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback) override;
 
private:
    std::shared_ptr<Task> taskPtr_{nullptr};
    sptr<AVBufferContext> avbufferContext_;
    std::string name_;
    CFilterType filterType_ = CFilterType::MOVING_PHOTO_VIDEO_ENCODE;
 
    std::shared_ptr<CEventReceiver> eventReceiver_;
    std::shared_ptr<CFilterCallback> filterCallback_;
 
    std::shared_ptr<CFilterLinkCallback> onLinkedResultCallback_;
 
    std::shared_ptr<VideoEncoderAdapter> mediaCodec_;
 
    std::string codecMimeType_;
    std::shared_ptr<Meta> configureParameter_;
 
    std::shared_ptr<CFilter> nextFilter_;
 
    std::atomic<bool> isUpdateCodecNeeded_ = false;
    sptr<Surface> surface_{nullptr};
    std::string bundleName_;
    bool isTranscoderMode_ {false};
    uint64_t instanceId_{0};
    int32_t appUid_ {0};
    int32_t appPid_ {0};
 
    inline void ResetKeyFrameCount() {
        keyFrameInterval_ = RECORDER_KEY_FRAME_INTERVAL;
    }
    int64_t preBufferTimestamp_ = 0;
    int32_t keyFrameInterval_ = RECORDER_KEY_FRAME_INTERVAL;
    bool successFrame_ = false;
    std::mutex encoderMutex_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // MOVING_PHOTO_VIDEO_ENCODER_FILTER_H