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

#ifndef OHOS_CAMERA_MOVIE_FILE_CONSUMER_H
#define OHOS_CAMERA_MOVIE_FILE_CONSUMER_H

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>

#include "audio_info.h"
#include "avmuxer.h"
#include "unified_pipeline_audio_buffer.h"
#include "unified_pipeline_audio_encoded_buffer.h"
#include "unified_pipeline_data_consumer.h"
#include "unified_pipeline_surface_buffer.h"
#include "unified_pipeline_video_encoded_buffer.h"

namespace OHOS {
namespace CameraStandard {
class MovieFileConsumer : public UnifiedPipelineDataConsumer {
public:
    static constexpr int32_t INVALID_TRACKID = -1;
    static constexpr int64_t INVALID_TIMESTAMP = -1;
    static constexpr int64_t INVALID_FILE_DESCRIPTOR = -1;

    struct MovieFileConfig {
        int32_t fd = -1;
        int32_t rotation = 0;
        std::vector<float> location = {};
        float coverTime = 0; // Millisec
        int32_t videoWidth = 0;
        int32_t videoHeight = 0;
        std::string videoCodecMime = "";
        bool isVideoHdr = false;
        std::shared_ptr<AudioStandard::AudioStreamInfo> rawAudiostreamInfo = nullptr;
        std::shared_ptr<AudioStandard::AudioStreamInfo> audiostreamInfo = nullptr;
        int32_t frameRate = 30;
        bool isSetWaterMark = false;
        int64_t bitrate = 30000000;
        bool isBFrame = false;
        int32_t deviceFoldState = 0; // Value from OHOS::Rosen::FoldStatus
        std::string deviceModel = "";
        int32_t cameraPosition = -1; // -1 represents an uninitialized state.
    };

public:
    MovieFileConsumer();
    virtual ~MovieFileConsumer() override;

    // 创建 muxer 需要的fd 创建比较慢，因此需要延迟处理，先配上消费端。同时创建buffer缓存。
    void SetUp(MovieFileConfig config);

    void OnBufferArrival(std::unique_ptr<UnifiedPipelineBuffer> pipelineBuffer) override;
    void OnCommandArrival(std::unique_ptr<UnifiedPipelineCommand> command) override;

    bool WaitFirstFrame();

    void Start();

    void Pause();

    void Resume();

    void Stop();

    void SetDeferredVideoInfo(uint32_t flag, std::string videoId);

private:
    class ConsumerTimeKeeper {
    public:
    static constexpr int64_t COMBINE_TIME_GAP = 16000; // 分段录制的话，文件拼接间隔 16 ms ,避免前一段文件的最后一帧与下一段文件的第一帧重叠
        inline int64_t GetVideoDuration()
        {
            std::lock_guard<std::mutex> lock(timeMutex_);
            return videoDuration_;
        }

        inline void UpdateStartTime(int64_t startTimestamp)
        {
            std::lock_guard<std::mutex> lock(timeMutex_);
            if (lastVideoTimestamp_ != INVALID_TIMESTAMP && firstVideoTimestamp_ != INVALID_TIMESTAMP &&
                lastVideoTimestamp_ > firstVideoTimestamp_) {
                videoDuration_ += lastVideoTimestamp_ - firstVideoTimestamp_ + COMBINE_TIME_GAP;
            }
            startTimestamp_ = startTimestamp;
            firstVideoTimestamp_ = INVALID_TIMESTAMP;
            lastVideoTimestamp_ = INVALID_TIMESTAMP;
            firstMetadataTimestamp_ = INVALID_TIMESTAMP;
        }

        inline bool IsTimestampVaild(int64_t timestamp)
        {
            std::lock_guard<std::mutex> lock(timeMutex_);
            return timestamp >= firstVideoTimestamp_;
        }

        inline int64_t GetVideoRelativeTime(int64_t timestamp)
        {
            std::lock_guard<std::mutex> lock(timeMutex_);
            if (firstVideoTimestamp_ == INVALID_TIMESTAMP) {
                firstVideoTimestamp_ = timestamp;
                videoFrameCond_.notify_all();
            }
            if (timestamp > lastVideoTimestamp_) {
                lastVideoTimestamp_ = timestamp;
            }
            return videoDuration_ + timestamp - firstVideoTimestamp_;
        }

        inline int64_t GetRelativeTime(int64_t timestamp)
        {
            std::lock_guard<std::mutex> lock(timeMutex_);
            return videoDuration_ + timestamp - firstVideoTimestamp_;
        }

        inline int64_t GetMetadataRelativeTime(int64_t timestamp)
        {
            std::lock_guard<std::mutex> lock(timeMutex_);
            if (firstMetadataTimestamp_ == INVALID_TIMESTAMP) {
                firstMetadataTimestamp_ = timestamp;
            }
            return videoDuration_ + timestamp - firstMetadataTimestamp_;
        }

        inline bool IsVideoStarted()
        {
            std::lock_guard<std::mutex> lock(timeMutex_);
            return firstVideoTimestamp_ != INVALID_TIMESTAMP;
        }

        inline bool IsStarted()
        {
            return startTimestamp_ != INVALID_TIMESTAMP;
        }

        bool WaitFirstVideoFrame();


    private:
        std::mutex timeMutex_;
        int64_t videoDuration_ = 0;
        // 各个接口调用的时间，单位是微秒

        int64_t firstVideoTimestamp_ = INVALID_TIMESTAMP;
        int64_t lastVideoTimestamp_ = INVALID_TIMESTAMP;

        int64_t firstMetadataTimestamp_ = INVALID_TIMESTAMP;

        int64_t startTimestamp_ = INVALID_TIMESTAMP;

        std::condition_variable videoFrameCond_;
    };

    template<typename T>
    class BufferQueue {
    public:
        BufferQueue(size_t cacheSize) : bufferCacheSize_(cacheSize) {}

        void Push(std::unique_ptr<T> buffer)
        {
            std::lock_guard<std::mutex> lock(bufferQueueMutex_);
            bufferQueue_.push(std::move(buffer));
        }

        std::unique_ptr<T> Pop()
        {
            std::lock_guard<std::mutex> lock(bufferQueueMutex_);
            if (bufferQueue_.size() <= bufferCacheSize_) {
                return nullptr;
            }
            auto buffer = std::move(bufferQueue_.front());
            bufferQueue_.pop();
            return buffer;
        }

        std::queue<std::unique_ptr<T>> Flush()
        {
            std::queue<std::unique_ptr<T>> returnList;
            std::lock_guard<std::mutex> lock(bufferQueueMutex_);
            bufferQueue_.swap(returnList);
            return returnList;
        }

    private:
        std::mutex bufferQueueMutex_;
        std::queue<std::unique_ptr<T>> bufferQueue_;
        size_t bufferCacheSize_ = 0;
    };

private:
    static const size_t BUFFER_CACHE_SIZE = 0;
    void ConfigMuxerInfo(int32_t rotation, std::vector<float> location);
    void SetMovieFileConfigToMuxer(MovieFileConfig& config);

    void AddVideoTrack(int32_t width, int32_t height, bool isHdr, std::string mimeCodec, int32_t frameRate);
    void AddMetadataTrack();
    void AddAudioTrack(AudioStandard::AudioStreamInfo audioStreamInfo);
    void AddAudioRawTrack(AudioStandard::AudioStreamInfo audioStreamInfo);

    void OnAudioEncodedRawBufferArrival(std::unique_ptr<UnifiedPipelineAudioPackagedEncodedBuffer> audioEncodedBuffer);
    void WriteAudioEncodedRawBuffer(std::unique_ptr<UnifiedPipelineAudioPackagedEncodedBuffer> audioEncodedBuffer);

    void OnAudioEncodedBufferArrival(std::unique_ptr<UnifiedPipelineAudioPackagedEncodedBuffer> audioEncodedBuffer);
    void WriteAudioEncodedBuffer(std::unique_ptr<UnifiedPipelineAudioPackagedEncodedBuffer> audioEncodedBuffer);

    void OnVideoEncodedBufferArrival(std::unique_ptr<UnifiedPipelineVideoEncodedBuffer> videoEncodedBuffer);

    void OnMetaBufferArrival(std::unique_ptr<UnifiedPipelineSurfaceBuffer> metaBuffer);
    void WriteMetaBuffer(std::unique_ptr<UnifiedPipelineSurfaceBuffer> metaBuffer);

    void RecordTimeStamps(int64_t startTimeStamp, int64_t endTimeStamp);

    std::string GetTimeStamps();

    int64_t WaitBufferReceivedFinish();

    void FlushBufferQueueCache();

    std::vector<int64_t> recordTimeStamps_ = {};

    std::atomic<int64_t> videoStartPts_ = 0;
    std::atomic<int64_t> videoStopPts_ = 0;

    std::shared_ptr<MediaAVCodec::AVMuxer> muxer_ = nullptr;
    MovieFileConfig movieFileConfig_;

    int32_t videoTrackId_ = INVALID_TRACKID;
    int32_t audioTrackId_ = INVALID_TRACKID;
    int32_t audioRawTrackId_ = INVALID_TRACKID;
    int32_t metaTrackId_ = INVALID_TRACKID;

    ConsumerTimeKeeper timeKeeper_;
    BufferQueue<UnifiedPipelineAudioPackagedEncodedBuffer> audioEncodedBufferQueue_ { BUFFER_CACHE_SIZE };
    BufferQueue<UnifiedPipelineAudioPackagedEncodedBuffer> audioEncodedRawBufferQueue_ { BUFFER_CACHE_SIZE };

    std::mutex bufferEndCondMtx_; // Lock for bufferEndCondition_ & isReceivedBuffer_
    std::condition_variable bufferEndCondition_;
    bool isReceivedBuffer_ = false;
    std::atomic<bool> isWaitingBuffer_ = false;
};
} // namespace CameraStandard
} // namespace OHOS
#endif