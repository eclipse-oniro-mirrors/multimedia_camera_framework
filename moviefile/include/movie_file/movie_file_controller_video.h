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

#ifndef OHOS_CAMERA_MOVIE_FILE_CONTROLLER_VIDEO_H
#define OHOS_CAMERA_MOVIE_FILE_CONTROLLER_VIDEO_H

#include <memory>
#include <mutex>

#include "camera_server_photo_proxy.h"
#include "camera_simple_timer.h"
#include "istream_repeat_callback.h"
#include "movie_file_audio_buffer_producer.h"
#include "movie_file_consumer.h"
#include "movie_file_controller_base.h"
#include "movie_file_meta_buffer_producer.h"
#include "movie_file_video_buffer_producer.h"
#include "movie_file_video_encoded_buffer_producer.h"
#include "movie_file_video_encoder_plugin.h"
#include "photo_asset_interface.h"
#include "photo_asset_proxy.h"
#include "sp_holder.h"
#include "unified_pipeline_audio_capture_wrap.h"
#include "unified_pipeline_manager.h"

namespace OHOS {
namespace CameraStandard {
class MovieFileControllerVideo : public MovieFileControllerBase {
public:
    MovieFileControllerVideo(int32_t width, int32_t height, bool isHdr, int32_t frameRate, int32_t videoBitrate);
    ~MovieFileControllerVideo();

    int32_t MuxMovieFileStart(int64_t timestamp, MovieSettings movieSettings, int32_t cameraPosition) override;
    void MuxMovieFilePause(int64_t timestamp) override;
    void MuxMovieFileResume() override;
    std::string MuxMovieFileStop(int64_t timestamp) override;

    bool WaitFirstFrame() override;

    void ChangeCodecSettings(VideoCodecType codecType, int32_t rotation, bool isBFrame, int32_t videoBitrate) override;
    void AddVideoFilter(const std::string& filterName, const std::string& filterParam) override;
    void RemoveVideoFilter(const std::string& filterName) override;

    virtual sptr<IBufferProducer> GetVideoProducer() override;
    virtual sptr<IBufferProducer> GetRawVideoProducer() override;
    virtual sptr<IBufferProducer> GetMetaProducer() override;

    void ReleaseConsumer() override;

    sptr<IStreamRepeatCallback> GetVideoStreamCallback() override;

private:
    class VideoStreamCallback : public IStreamRepeatCallback {
    public:
        VideoStreamCallback(std::weak_ptr<MovieFileVideoEncodedBufferProducer> movieFileVideoEncodedBufferProducer);
        virtual ~VideoStreamCallback() override;

        ErrCode OnFrameStarted() override;

        ErrCode OnFrameEnded(int32_t frameCount) override;

        ErrCode OnFrameError(int32_t errorCode) override;

        ErrCode OnSketchStatusChanged(SketchStatus status) override;

        ErrCode OnDeferredVideoEnhancementInfo(const CaptureEndedInfoExt& captureEndedInfo) override;

        ErrCode OnFramePaused() override;

        ErrCode OnFrameResumed() override;

        sptr<IRemoteObject> AsObject() override;

        void WaitProcessEnd();

        inline void SetPhotoProxy(
            sptr<CameraServerPhotoProxy> photoProxy, std::shared_ptr<PhotoAssetProxy> photoAssetProxy)
        {
            std::lock_guard<std::mutex> lock(proxyMutex_);
            photoProxy_ = photoProxy;
            photoAssetProxy_ = photoAssetProxy;
        }

        inline void SetDeferredFlag(uint32_t flag)
        {
            deferredFlag_ = flag;
        }

        inline uint32_t GetDeferredFlag()
        {
            return deferredFlag_;
        }

        inline void SetVideoId(std::string videoId)
        {
            videoId_ = videoId;
        }

        inline std::string GetVideoId()
        {
            return videoId_;
        }

    private:
        std::mutex proxyMutex_;
        sptr<CameraServerPhotoProxy> photoProxy_;
        std::shared_ptr<PhotoAssetProxy> photoAssetProxy_;

        std::weak_ptr<MovieFileVideoEncodedBufferProducer> movieFileVideoEncodedBufferProducer_;

        std::mutex waitProcessMutex_;
        std::condition_variable processCondition_;
        bool isProcessDone_ = false;
        std::atomic<uint32_t> deferredFlag_ = 0;
        std::string videoId_;
    };

private:
    std::shared_ptr<PhotoAssetIntf> GetPhotoAsset();
    void StartConsumerAndProducer(std::shared_ptr<MovieFileConsumer> movieFileConsumer);
    void SetupPipeline(std::shared_ptr<MovieFileConsumer> movieFileConsumer);

    AudioStandard::AudioStreamInfo CreateAudioStreamInfo();
    void SelectTargetAudioInputDevice();
    void DeselectTargetAudioInputDevice();
    void ConfigAudioCapture();
    void ConfigAudioPipeline(const AudioStandard::AudioStreamInfo& streamInfo,
        std::shared_ptr<UnifiedPipelineAudioCaptureWrap> audioCaptureWrap);
    void ConfigRawAudioPipeline(const AudioStandard::AudioStreamInfo& streamInfo,
        std::shared_ptr<UnifiedPipelineAudioCaptureWrap> audioCaptureWrap);

    int32_t videoWidth_ = 0;
    int32_t videoHeight_ = 0;
    int32_t frameRate_ = 30;

    std::string waterFilter_;
    std::string waterFilterParam_;

    SpHolder<std::shared_ptr<MovieFileConsumer>> movieFileConsumer_;

    SpHolder<std::shared_ptr<UnifiedPipelineAudioCaptureWrap>> audioCaptureWrap_;

    std::shared_ptr<MovieFileVideoEncodedBufferProducer> movieFileVideoEncodedBufferProducer_;
    SpHolder<std::shared_ptr<MovieFileAudioBufferProducer>> movieFileAudioBufferProducer_;
    SpHolder<std::shared_ptr<MovieFileAudioBufferProducer>> movieFileAudioRawBufferProducer_;
    std::shared_ptr<MovieFileMetaBufferProducer> movieFileMetaBufferProducer_;

    std::shared_ptr<UnifiedPipelineManager> movieFilePipelineManager_ = std::make_shared<UnifiedPipelineManager>();

    std::string videoCodecMime_ = std::string(CodecMimeType::VIDEO_HEVC);

    SpHolder<std::shared_ptr<PhotoAssetIntf>> lastAsset_;

    std::shared_ptr<AudioStandard::AudioStreamInfo> sharedAudioCaptureStreamInfo_ = nullptr;
    std::shared_ptr<AudioStandard::AudioStreamInfo> sharedAudioEffectStreamInfo_ = nullptr;

    sptr<VideoStreamCallback> videoStreamCallback_;

    bool isEnableRawAudio_ = false;
};

} // namespace CameraStandard
} // namespace OHOS

#endif