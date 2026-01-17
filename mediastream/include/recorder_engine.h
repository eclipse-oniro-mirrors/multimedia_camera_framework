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

#ifndef OHOS_CAMERA_RECORDER_ENGINE_H
#define OHOS_CAMERA_RECORDER_ENGINE_H

#include "audio_capture_filter.h"
#include "audio_encoder_filter.h"
#include "audio_fork_filter.h"
#include "audio_process_filter.h"
#include "image_effect_filter.h"
#include "metadata_filter.h"
#include "cinematic_video_cache_filter.h"
#include "muxer_filter.h"
#include "refbase.h"
#include "video_encoder_filter.h"
#include "pipeline.h"
#include "i_recorder.h"
#include "avcodec_list.h"
#include "camera_sensor_plugin.h"
#include "camera_server_photo_proxy.h"
#include "photo_asset_proxy.h"
#include "pixel_map.h"
#include "surface.h"
#include "sp_holder.h"
#include "recorder_engine_interface.h"

namespace OHOS::CameraStandard {
class RecorderEngine : public RefBase {
public:
    RecorderEngine(wptr<RecorderIntf> recorder);
    virtual ~RecorderEngine();

    int32_t Prepare();
    Status StartRecording();
    Status PauseRecording();
    Status ResumeRecording();
    Status StopRecording();
    void SetRotation(int32_t rotation);
    int32_t SetOutputSettings(const EngineMovieSettings& movieSettings);
    int32_t GetSupportedVideoFilters(std::vector<std::string> &supportedVideoFilters);
    int32_t SetVideoFilter(const std::string& filter, const std::string& filterParam);
    int32_t SetUserMeta(const std::string& key, const std::string& val);
    int32_t SetUserMeta(const std::string& key, const std::vector<uint8_t>& val);
    int32_t UpdatePhotoProxy(const std::string& videoId, int32_t videoEnhancementType);
    int32_t EnableVirtualAperture(bool isVirtualApertureEnabled);
    int32_t GetFirstFrameTimestamp(int64_t& firstFrameTimeStamp);

    int32_t Init();
    void SetMovieFrameSize(int32_t width, int32_t height);
    void SetRawFrameSize(int32_t width, int32_t height);
    sptr<Surface> GetRawSurface();
    sptr<Surface> GetDepthSurface();
    sptr<Surface> GetPreySurface();
    sptr<Surface> GetMetaSurface();
    sptr<Surface> GetMovieDebugSurface();
    sptr<Surface> GetRawDebugSurface();
    sptr<Surface> GetImageEffectSurface();
    void SetIsWaitForMeta(bool isWait);
    void SetIsWaitForMuxerDone(bool isWait);
    void SetIsStreamStarted(bool isStarted);
    bool IsNeedWaitForMuxerDone();
    std::string GetMovieFileUri();
    void WaitForRawMuxerDone();
    bool IsNeedStopCallback();
    void SetIsNeedStopCallback(bool isNeed);
    void SetIsNeedWaitForRawMuxerDone(bool isNeed);

    // filter callback
    void OnEvent(const Event &event);
    Status OnCallback(std::shared_ptr<CFilter> filter, const CFilterCallBackCommand cmd, CStreamType outType);

private:
    void SetWatermarkMeta();
    void NotifyUserMetaSet();
    void WaitForUserMetaSet();
    void NotifyMuxerDone();
    void WaitForMuxerDoneThenUpdatePhotoProxy();

    Status InitCallerInfo();
    Status InitPipeline();

    Status PrepareAudioSource();
    Status PrepareMovieSource();
    Status PrepareRawSource();
    Status PreparePreySource();
    Status PrepareDepthSource();
    Status PrepareMetaSource();
    Status PrepareMovieDebugSource();
    Status PrepareRawDebugSource();

    Status AddResource();
    Status AddAudioSource();
    Status AddMovieSource();
    Status AddRawSource();
    Status AddPreySource();
    Status AddDepthSource();
    Status AddMetaSource();
    Status AddMovieDebugSource();
    Status AddRawDebugSource();

    Status RemoveResource();

    Status PrepareMovieMuxer();
    Status PrepareRawMuxer();
    Status PrepareSurface();
    Status PrepareAudioProcess();
    Status PrepareAudioEncoder();
    Status PrepareRawAudioEncoder();
    Status PrepareAudioFork();

    Status ConfigAudioCaptureFilter();
    Status ConfigImageEffectFilter();
    Status ConfigMovieEncoderFilter();
    Status ConfigRawEncoderFilter();
    Status ConfigPreyCacheFilter();
    Status ConfigPreyEncoderFilter();
    Status ConfigDepthCacheFilter();
    Status ConfigDepthEncoderFilter();
    Status ConfigMetaDataFilter();
    Status ConfigAudioProcessFilter();
    Status ConfigAudioEncoderFilter();
    Status ConfigRawAudioEncoderFilter();
    Status ConfigAudioForkFilter();
    Status ConfigMovieMuxerFilter();
    Status ConfigRawMuxerFilter();
    Status ConfigMovieDebugFilter();
    Status ConfigRawDebugFilter();


    Status SetWatermarkBuffer(std::string filter, std::string filterParam);
    Status CheckAudioPostEditAbility();
    Status HandleRawAudio(std::shared_ptr<CFilter> filter);
    Status HandleProcessedAudio(std::shared_ptr<CFilter> filter);
    Status HandleEncodedAudio(std::shared_ptr<CFilter> filter, int32_t clusterId);
    Status HandleLinkMuxer(int32_t clusterId, std::shared_ptr<CFilter> filter, CStreamType outType);

    Status CreateMovieFileMediaLibrary();

    void ConfigAudioCaptureFormat();
    void ConfigAudioEncFormat();
    void ConfigRawAudioEncFormat();
    void ConfigMovieEncFormat();
    void ConfigRawEncFormat();
    void ConfigPreyEncFormat();
    void ConfigDepthEncFormat();
    void ConfigMetaDataFormat();
    void ConfigMovieDebugFormat();
    void ConfigRawDebugFormat();
    void ConfigMovieMuxerFormat();
    void ConfigRawMuxerFormat();

    void SetMovieSurface();
    void SetRawSurface();
    void SetPreySurface();
    void SetDepthSurface();
    void SetMetaSurface();
    void SetMovieDebugSurface();
    void SetRawDebugSurface();
    void SetImageEffectSurface();

    void CloseMovieFd();
    void CloseRawFd();

    void SelectTargetAudioInputDevice();

    void OnStateChanged(StateId state);

    void SetEncParamMeta();

    bool IsWatermarkSupportedByAvCodec();

    int64_t GetCurrentTime();

    AudioChannel GetMicNum();

    int32_t appUid_{0};
    int32_t appPid_{0};
    uint32_t appTokenId_{0};
    uint64_t appFullTokenId_{0};

    uint32_t movieWidth_{0};
    uint32_t movieHeight_{0};
    uint32_t rawWidth_{0};
    uint32_t rawHeight_{0};

    bool isMovieHdr_{false};
    bool isImageEffectEnabled_{false};
    bool isAudioPostEditEnabled_ {false};
    bool isFirstPrepare_ { true };
    bool isVirtualApertureEnabled_ { true };
    bool needStopCallback_ {false};
    bool needWaitForRawMuxerDone_ {false};

    uint64_t instanceId_{0};

    std::string recorderId_{""};
    std::string bundleName_{""};

    int32_t rawVideoFd_{-1};
    int32_t movieVideoFd_{-1};
    std::string movieFileUri_{""};

    std::atomic<StateId> curState_;
    bool isAllSourceAdded_{false};
    bool needWaitForMeta_{false};
    bool needWaitForMuxerDone_{false};
    std::condition_variable userMetaCondition_;
    std::condition_variable muxerDoneCondition_;
    std::mutex userMetaMutex_;
    std::mutex muxerMutex_;

    std::shared_ptr<Pipeline> pipeline_;
    std::shared_ptr<CEventReceiver> recorderEventReceiver_;
    std::shared_ptr<CFilterCallback> recorderCallback_;
    std::shared_ptr<PhotoAssetProxy> movieFilePhotoAssetProxy_;
    
    std::shared_ptr<AudioCaptureFilter> audioCaptureFilter_;
    std::shared_ptr<AudioProcessFilter> audioProcessFilter_;
    std::shared_ptr<AudioEncoderFilter> audioEncoderFilter_;
    std::shared_ptr<AudioEncoderFilter> rawAudioEncoderFilter_;
    std::shared_ptr<AudioForkFilter> audioForkFilter_;
    std::shared_ptr<VideoEncoderFilter> movieEncoderFilter_;
    std::shared_ptr<VideoEncoderFilter> rawEncoderFilter_;
    std::shared_ptr<VideoEncoderFilter> depthEncoderFilter_;
    std::shared_ptr<VideoEncoderFilter> preyEncoderFilter_;
    std::shared_ptr<MetaDataFilter> metaDataFilter_;
    std::shared_ptr<MuxerFilter> movieMuxerFilter_;
    SpHolder<std::shared_ptr<MuxerFilter>> rawMuxerFilter_;
    std::shared_ptr<ImageEffectFilter> imageEffectFilter_;
    std::shared_ptr<MetaDataFilter> movieDebugFilter_;
    std::shared_ptr<MetaDataFilter> rawDebugFilter_;
    std::shared_ptr<CinematicVideoCacheFilter> preyCacheFilter_;
    std::shared_ptr<CinematicVideoCacheFilter> depthCacheFilter_;

    std::shared_ptr<Meta> audioCaptureFormat_ = std::make_shared<Meta>();
    std::shared_ptr<Meta> audioEncFormat_ = std::make_shared<Meta>();
    std::shared_ptr<Meta> rawAudioEncFormat_ = std::make_shared<Meta>();
    std::shared_ptr<Meta> movieEncFormat_ = std::make_shared<Meta>();
    std::shared_ptr<Meta> rawEncFormat_ = std::make_shared<Meta>();
    std::shared_ptr<Meta> preyEncFormat_ = std::make_shared<Meta>();
    std::shared_ptr<Meta> depthEncFormat_ = std::make_shared<Meta>();
    std::shared_ptr<Meta> metaDataFormat_ = std::make_shared<Meta>();
    std::shared_ptr<Meta> movieDebugFormat_ = std::make_shared<Meta>();
    std::shared_ptr<Meta> rawDebugFormat_ = std::make_shared<Meta>();
    std::shared_ptr<Meta> movieMuxerFormat_ = std::make_shared<Meta>();
    std::shared_ptr<Meta> rawMuxerFormat_ = std::make_shared<Meta>();
    
    Plugins::VideoRotation rotation_{Plugins::VideoRotation::VIDEO_ROTATION_0};

    sptr<Surface> movieSurface_{nullptr};
    sptr<Surface> rawSurface_{nullptr};
    sptr<Surface> metaSurface_{nullptr};
    sptr<Surface> preySurface_{nullptr};
    sptr<Surface> depthSurface_{nullptr};
    sptr<Surface> imageEffectSurface_{nullptr};
    sptr<Surface> movieDebugSurface_{nullptr};
    sptr<Surface> rawDebugSurface_{nullptr};

    sptr<CameraServerPhotoProxy> cameraPhotoProxy_;
    SpHolder<std::shared_ptr<AVBuffer>> waterMarkBuffer_;
    SpHolder<std::shared_ptr<MediaAVCodec::AVCodecList>> codecList_;
    
    EngineMovieSettings movieSettings_ {
        EngineVideoCodecType::VIDEO_ENCODE_TYPE_AVC, 0, false, {0.0, 0.0, 0.0}, false, 30000000};
    std::string waterMarkInfo_;
    wptr<RecorderIntf> recorder_;
};
} // namespace OHOS::CameraStandard
#endif // OHOS_CAMERA_RECORDER_ENGINE_H