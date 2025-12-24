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

#ifndef OHOS_CAMERA_MOVIE_FILE_VIDEO_ENCODED_BUFFER_PRODUCER_H
#define OHOS_CAMERA_MOVIE_FILE_VIDEO_ENCODED_BUFFER_PRODUCER_H

#include <memory>
#include <mutex>

#include "avcodec_video_encoder.h"
#include "camera_types.h"
#include "common/movie_file_video_encode_config.h"
#include "sp_holder.h"
#include "surface.h"
#include "unified_pipeline_data_producer.h"

namespace OHOS {
namespace CameraStandard {
class MovieFileVideoEncodedBufferProducer : public UnifiedPipelineDataProducer {
public:
    MovieFileVideoEncodedBufferProducer();

    ~MovieFileVideoEncodedBufferProducer() override;

    void OnCommandArrival(std::unique_ptr<UnifiedPipelineCommand> command) override;

    void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<MediaAVCodec::AVBuffer> buffer);

    void OnInputParameterWithAttrAvailable(uint32_t index, std::shared_ptr<OHOS::Media::Format> attribute,
        std::shared_ptr<OHOS::Media::Format> parameter);

    sptr<IBufferProducer> GetSurfaceProducer();

    void ConfigVideoEncoder(const VideoEncoderConfig& config);

    void ChangeCodecSettings(const std::string& mimeType, int32_t rotation, bool isBFrame, int32_t videoBitrate);

    void UpdateEncoderWarpConfig();

    void RequestIFrame();

    void FlushBuffer();

    void AddVideoFilter(const std::string& filterName, const std::string& filterParam);

    void RemoveVideoFilter(const std::string& filterName);

    void StartEncoder();

    void StopEncoder(int64_t timestamp);

    int32_t GetVideoBitrate();

private:
    static constexpr int64_t DEFAULT_BIT_RATE = 30000000; // default is 30M bitrate
    static constexpr int64_t DEFAULT_FRAME_RATE = 30;

    class VideoEncoderCallback : public MediaAVCodec::MediaCodecCallback {
    public:
        VideoEncoderCallback(MovieFileVideoEncodedBufferProducer* encodeNode);
        ~VideoEncoderCallback() override;
        void OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode) override;
        void OnOutputFormatChanged(const MediaAVCodec::Format& format) override;
        void OnInputBufferAvailable(uint32_t index, std::shared_ptr<MediaAVCodec::AVBuffer> buffer) override;
        void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<MediaAVCodec::AVBuffer> buffer) override;
        void Release();

    private:
        // MovieFileVideoEncodedBufferProducer
        // 析构的时候调用VideoEncoderCallback的Release方法，确保回调函数中不会踩内存。因此这个地方使用裸指针是安全的。
        std::mutex bufferProducerMutex_;
        MovieFileVideoEncodedBufferProducer* bufferProducer_ = nullptr;
    };

    class VideoEncoderParameterWithAttrCallback : public MediaAVCodec::MediaCodecParameterWithAttrCallback {
    public:
        VideoEncoderParameterWithAttrCallback(MovieFileVideoEncodedBufferProducer* encodeNode);
        ~VideoEncoderParameterWithAttrCallback() override;
        void OnInputParameterWithAttrAvailable(uint32_t index, std::shared_ptr<OHOS::Media::Format> attribute,
            std::shared_ptr<OHOS::Media::Format> parameter) override;
        void Release();
    private:
        std::mutex bufferParameterProducerMutex_;
        MovieFileVideoEncodedBufferProducer* bufferProducer_ = nullptr;
    };

    class EncoderWarp {
    public:
        enum class State : int32_t { STOPPED, STARTED };

    public:
        EncoderWarp(const VideoEncoderConfig& config, std::shared_ptr<MediaAVCodec::MediaCodecCallback> codecCallback,
            std::shared_ptr<MediaAVCodec::MediaCodecParameterWithAttrCallback> codecParameterCallback);
        ~EncoderWarp();
        void ReleaseOutputBuffer(uint32_t index);
        sptr<IBufferProducer> GetProducer();
        void RequestIFrame();
        void FlushBuffer();
        void NotifyEos();
        void SetWatermark(std::shared_ptr<MediaAVCodec::AVBuffer> waterMarkBuffer);
        void Start();
        void Stop();
        void Reset();
        void WaitState(State state);
        void CheckStoppedState();
        void UpdateConfig(const VideoEncoderConfig& config);
        int32_t GetEncodeBitrate();
        int32_t GetFrameRate();
        void QueueInputParameter(uint32_t index);

    private:
        sptr<Surface> codecSurface_;
        std::shared_ptr<MediaAVCodec::AVCodecVideoEncoder> encoder_;
        VideoEncoderConfig encodeConfig_ = {};

        SpHolder<std::shared_ptr<MediaAVCodec::AVBuffer>> waterMarkBuffer_;

        std::mutex stateMutex_; // Lock for stateCondition_ & state_
        std::condition_variable stateCondition_;
        State state_ = State::STOPPED;

    };

private:
    void SetSurfaceUsage(uint64_t usage);

    void SetSurfaceWidthAndHeight(int32_t width, int32_t height);

    void WaitOutbufferEnd();

    SpHolder<std::shared_ptr<EncoderWarp>> encoderWarp_;
    std::shared_ptr<VideoEncoderCallback> videoEncoderCallback_;
    std::shared_ptr<VideoEncoderParameterWithAttrCallback> videoEncoderParameterWithAttrCallback_;
    int64_t stopTime_ {-1};

    VideoEncoderConfig videoEncoderConfig_;

    std::mutex bufferEndCondMtx_; // Lock for bufferEndCondition_ & isReceivedBuffer_
    std::condition_variable bufferEndCondition_;
    bool isReceivedBuffer_ = false;
    std::atomic<bool> isWaitingBuffer_ = false;
};
} // namespace CameraStandard
} // namespace OHOS

#endif