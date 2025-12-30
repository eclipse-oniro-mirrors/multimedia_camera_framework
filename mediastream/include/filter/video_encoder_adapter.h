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

#ifndef OHOS_CAMERA_VIDEO_ENCODER_ADAPTER_H
#define OHOS_CAMERA_VIDEO_ENCODER_ADAPTER_H

#include <deque>

#include "avbuffer_queue_producer.h"
#include "avcodec_video_encoder.h"
#include "osal/task/task.h"
#include "avbuffer_context.h"

namespace OHOS {
namespace CameraStandard {
using namespace Media;

enum class StateCode {
    PAUSE,
    RESUME,
};

enum class ProcessStateCode {
    IDLE,
    // operate start, resume
    RECORDING,
    // operate pause
    PAUSED,
    // operate stop
    STOPPED,
    ERROR,
};

class EncoderAdapterCallback {
public:
    virtual ~EncoderAdapterCallback() = default;
    virtual void OnError(MediaAVCodec::AVCodecErrorType type, int32_t errorCode) = 0;
    virtual void OnOutputFormatChanged(const std::shared_ptr<Meta>& format) = 0;
};

class EncoderAdapterKeyFramePtsCallback {
public:
    virtual ~EncoderAdapterKeyFramePtsCallback() = default;
    virtual void OnReportKeyFramePts(std::string KeyFramePts) = 0;
    virtual void OnFirstFrameArrival(std::string name, int64_t& startPts) = 0;
    virtual void OnReportFirstFramePts(int64_t firstFramePts) = 0;
};

class VideoEncoderAdapter : public std::enable_shared_from_this<VideoEncoderAdapter>  {
public:
    explicit VideoEncoderAdapter();
    explicit VideoEncoderAdapter(std::string name);
    ~VideoEncoderAdapter();

    Status Init(const std::string& mime, bool isEncoder);
    Status Configure(const std::shared_ptr<Meta>& meta);
    Status SetWatermark(std::shared_ptr<AVBuffer>& waterMarkBuffer);
    Status SetStopTime(int64_t stopTime = -1);
    Status SetOutputBufferQueue(const sptr<AVBufferQueueProducer>& bufferQueueProducer);
    Status SetEncoderAdapterCallback(const std::shared_ptr<EncoderAdapterCallback>& encoderAdapterCallback);
    Status SetEncoderAdapterKeyFramePtsCallback(
        const std::shared_ptr<EncoderAdapterKeyFramePtsCallback>& encoderAdapterKeyFramePtsCallback);
    Status SetTransCoderMode();
    sptr<Surface> GetInputSurface();
    Status Start();
    Status Stop();
    Status Pause();
    Status Resume();
    Status Flush();
    Status Reset();
    Status Release();
    Status NotifyEos(int64_t pts);
    Status SetParameter(const std::shared_ptr<Meta>& parameter);
    std::shared_ptr<Meta> GetOutputFormat();
    void TransCoderOnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer);
    void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer);
    void SetFaultEvent(const std::string& errMsg);
    void SetFaultEvent(const std::string& errMsg, int32_t ret);
    void SetCallingInfo(int32_t appUid, int32_t appPid, const std::string& bundleName, uint64_t instanceId);
    void OnInputParameterWithAttrAvailable(uint32_t index, std::shared_ptr<Format>& attribute,
        std::shared_ptr<Format>& parameter);
    bool GetIsTransCoderMode();

    std::shared_ptr<EncoderAdapterCallback> encoderAdapterCallback_ {nullptr};
    std::shared_ptr<EncoderAdapterKeyFramePtsCallback> encoderAdapterKeyFramePtsCallback_ {nullptr};

    void MovingPhotoOnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer);

    inline sptr<AVBufferContext> GetAVBufferContext()
    {
        return avbufferContext_;
    }
    Status ReleaseOutputBuffer(uint32_t index);
    inline void EnableMovingPhotoMode(bool isEnable) {
        isMovingPhotoMode_ = isEnable;
    }

    inline void EnableVirtualAperture(bool isVirtualApertureEnabled)
    {
        isVirtualApertureEnabled_ = isVirtualApertureEnabled;
    }

    inline void SetStreamStarted(bool isStreamStarted)
    {
        isStreamStarted_ = isStreamStarted;
    }

    inline int64_t GetStopTimestamp()
    {
        return stopTime_;
    }

private:
    bool isMovingPhotoMode_{false};
    bool isVirtualApertureEnabled_{true};
    bool isStreamStarted_{true};
    sptr<AVBufferContext> avbufferContext_ = new AVBufferContext();
    void ReleaseBuffer();
    void ConfigureGeneralFormat(MediaAVCodec::Format& format, const std::shared_ptr<Meta>& meta);
    void ConfigureAboutRGBA(MediaAVCodec::Format& format, const std::shared_ptr<Meta>& meta);
    void ConfigureEnableFormat(MediaAVCodec::Format& format, const std::shared_ptr<Meta>& meta);
    void ConfigureAboutEnableTemporalScale(MediaAVCodec::Format& format, const std::shared_ptr<Meta>& meta);
    void ConfigureAuxiliaryFormat(MediaAVCodec::Format& format, const std::shared_ptr<Meta>& meta);
    void ConfigureQualityFormat(MediaAVCodec::Format& format, const std::shared_ptr<Meta>& meta);
    void ConfigureBFrameFormat(MediaAVCodec::Format& format, const std::shared_ptr<Meta>& meta);
    bool CheckFrames(int64_t currentPts, int64_t& checkFramesPauseTime);
    void GetCurrentTime(int64_t& currentTime);
    void AddStartPts(int64_t currentPts);
    void AddStopPts();
    bool AddPauseResumePts(int64_t currentPts);
    void HandleWaitforStop();
    void UpdateStartBufferTime(int64_t currentPts);

    std::shared_ptr<MediaAVCodec::AVCodecVideoEncoder> codecServer_ {nullptr};
    sptr<AVBufferQueueProducer> outputBufferQueueProducer_ {nullptr};

    std::shared_ptr<Task> releaseBufferTask_ {nullptr};
    std::mutex releaseBufferMutex_;
    std::condition_variable releaseBufferCondition_;
    std::vector<uint32_t> indexs_;
    std::deque<std::pair<int64_t, StateCode>> pauseResumeQueue_ {};
    std::deque<int64_t> totalPauseTimeQueue_ {0};
    int64_t checkFramesPauseTime_ {0};
    std::atomic<bool> isThreadExit_ {true};
    bool isTransCoderMode_ {false};

    std::mutex mappingPtsMutex_;
    std::mutex checkFramesMutex_;
    std::mutex stopMutex_;
    std::condition_variable stopCondition_;
    int64_t stopTime_ {-1};
    int64_t pauseTime_ {-1};
    int64_t resumeTime_ {-1};
    std::atomic<int64_t> eosPts_{UINT32_MAX};
    std::atomic<int64_t> currentPts_ {-1};
    int64_t totalPauseTime_ {0};
    ProcessStateCode curState_ {ProcessStateCode::IDLE};

    int64_t startBufferTime_ {-1};
    int64_t lastBufferTime_ {-1};
    bool isStart_ {false};
    bool isResume_ {false};
    std::string codecMimeType_;
    std::string bundleName_;
    uint64_t instanceId_ {0};
    int32_t appUid_ {0};
    int32_t appPid_ {0};

    std::string keyFramePts_;
    bool isStartKeyFramePts_ {false};
    bool isStopKeyFramePts_ {false};
    int64_t currentKeyFramePts_ {-1};
    int64_t preKeyFramePts_ {-1};
    int32_t videoFrameRate_ {-1};
    std::deque<std::pair<int64_t, StateCode>> pauseResumePts_ {};
    bool hasReceivedEOS_ = false;
    std::string name_;
};

class VideoEncoderAdapterImplMediaCodecCallback : public MediaAVCodec::MediaCodecCallback {
public:
    explicit VideoEncoderAdapterImplMediaCodecCallback(std::shared_ptr<VideoEncoderAdapter> videoEncoderAdapter)
        : videoEncoderAdapter_(std::move(videoEncoderAdapter))
    {
    }

    void OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode) override
    {
        if (auto videoEncoderAdapter = videoEncoderAdapter_.lock()) {
            if (videoEncoderAdapter->GetIsTransCoderMode() && transCoderErrorCbOnce_) {
                return;
            }
            if (videoEncoderAdapter->GetIsTransCoderMode()) {
                transCoderErrorCbOnce_ = true;
            }
            videoEncoderAdapter->encoderAdapterCallback_->OnError(errorType, errorCode);
        }
    }

    void OnOutputFormatChanged(const MediaAVCodec::Format &format) override
    {
    }

    void OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) override
    {
    }

    void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) override
    {
        if (auto videoEncoderAdapter = videoEncoderAdapter_.lock()) {
            videoEncoderAdapter->OnOutputBufferAvailable(index, buffer);
        }
    }

private:
    std::weak_ptr<VideoEncoderAdapter> videoEncoderAdapter_;
    bool transCoderErrorCbOnce_ = false;
};

class DroppedFramesCallback : public MediaAVCodec::MediaCodecParameterWithAttrCallback {
public:
    explicit DroppedFramesCallback(std::shared_ptr<VideoEncoderAdapter> videoEncoderAdapter)
        : videoEncoderAdapter_(std::move(videoEncoderAdapter))
    {
    }

    void OnInputParameterWithAttrAvailable(uint32_t index, std::shared_ptr<Format> attribute,
        std::shared_ptr<Format> parameter) override
    {
        if (auto videoEncoderAdapter = videoEncoderAdapter_.lock()) {
            videoEncoderAdapter->OnInputParameterWithAttrAvailable(index, attribute, parameter);
        }
    }

private:
    std::weak_ptr<VideoEncoderAdapter> videoEncoderAdapter_;
};

} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_VIDEO_ENCODER_ADAPTER_H