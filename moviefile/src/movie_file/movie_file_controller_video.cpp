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

#include "movie_file_controller_video.h"

#include <parameters.h>

#include "audio_routing_manager.h"
#include "audio_session_manager.h"
#include "camera_log.h"
#include "camera_server_photo_proxy.h"
#include "display_lite.h"
#include "display_manager_lite.h"
#include "ipc_skeleton.h"
#include "movie_file_audio_effect_plugin.h"
#include "movie_file_audio_encoder_plugin.h"
#include "movie_file_audio_plugin.h"
#include "movie_file_audio_raw_plugin.h"
#include "movie_file_common_utils.h"
#include "movie_file_meta_plugin.h"
#include "movie_file_video_encoder_plugin.h"
#include "photo_asset_proxy.h"

namespace OHOS {
namespace CameraStandard {
namespace {
std::string GetMineTypeFromCodecType(VideoCodecType codecType)
{
    switch (codecType) {
        case VideoCodecType::VIDEO_ENCODE_TYPE_AVC:
            return std::string(CodecMimeType::VIDEO_AVC);
        case VideoCodecType::VIDEO_ENCODE_TYPE_HEVC:
            return std::string(CodecMimeType::VIDEO_HEVC);
        default:
            break;
    }
    return std::string(CodecMimeType::VIDEO_HEVC);
}
} // namespace

AudioStandard::AudioStreamInfo MovieFileControllerVideo::CreateAudioStreamInfo()
{
    AudioStandard::AudioStreamInfo audioCaptureStreamInfo = {};
    // 创建音频的生产端
    audioCaptureStreamInfo.samplingRate = UnifiedPipelineAudioCaptureWrap::AUDIO_PRODUCER_SAMPLING_RATE;
    audioCaptureStreamInfo.encoding = AudioStandard::AudioEncodingType::ENCODING_PCM;
    audioCaptureStreamInfo.format = AudioStandard::AudioSampleFormat::SAMPLE_S16LE;
    audioCaptureStreamInfo.channels =
        isEnableRawAudio_ ? UnifiedPipelineAudioCaptureWrap::GetMicNum() : AudioStandard::AudioChannel::STEREO;
    return audioCaptureStreamInfo;
}

void MovieFileControllerVideo::SelectTargetAudioInputDevice()
{
    CHECK_RETURN_ILOG(!isEnableRawAudio_,
                      "SelectTargetAudioInputDevice not enable audio edit, skip SelectTargetAudioInputDevice");
    auto audioRoutingManager = AudioStandard::AudioRoutingManager::GetInstance();
    CHECK_RETURN_WLOG(!audioRoutingManager, "SelectTargetAudioInputDevice audioRoutingManager is null");
    std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> descs;
    AudioStandard::RecommendInputDevices recommendDevice = audioRoutingManager->GetRecommendInputDevices(descs);
    MEDIA_INFO_LOG("GetRecommendInputDevices return recommendDevice: %{public}d.", recommendDevice);
    isEnableRawAudio_ = false;
    if (recommendDevice == AudioStandard::RecommendInputDevices::RECOMMEND_BUILT_IN_MIC) {
        CHECK_RETURN_ELOG(descs.size() != 1, "GetRecommendInputDevices return invalid data, descs size: %{public}zu",
                          descs.size());
        auto audioSessionManager = AudioStandard::AudioSessionManager::GetInstance();
        int32_t ret = audioSessionManager->SelectInputDevice(descs[0]);
        CHECK_RETURN_ELOG(ret != 0, "SelectInputDevice failed, ret: %{public}d", ret);
        MEDIA_INFO_LOG("Audio post audio is supported, and built in mic is selected.");
        isEnableRawAudio_ = true;
    }
}

void MovieFileControllerVideo::DeselectTargetAudioInputDevice()
{
    MEDIA_INFO_LOG("MovieFileControllerVideo::DeselectTargetAudioInputDevice");
    AudioStandard::AudioSessionManager::GetInstance()->ClearSelectedInputDevice();
}

void MovieFileControllerVideo::ConfigAudioCapture()
{
    static bool isEnableAudioEdit = system::GetBoolParameter("const.photo.audio_post_edit.enable", false);
    isEnableRawAudio_ = isEnableAudioEdit;
    MEDIA_INFO_LOG("MovieFileControllerVideo::ConfigAudioCapture isEnableAudioEdit is :%{public}d", isEnableAudioEdit);

    SelectTargetAudioInputDevice();
    sharedAudioCaptureStreamInfo_ = nullptr;
    sharedAudioEffectStreamInfo_ = nullptr;
    auto streamInfo = CreateAudioStreamInfo();
    AudioStandard::AudioCapturerOptions capturerOptions {};
    capturerOptions.streamInfo = streamInfo;
    capturerOptions.capturerInfo.sourceType = isEnableRawAudio_ ? AudioStandard::SourceType::SOURCE_TYPE_UNPROCESSED
                                                                : AudioStandard::SourceType::SOURCE_TYPE_CAMCORDER;
    MEDIA_INFO_LOG(
        "MovieFileControllerVideo::ConfigAudioCapture capturerInfo.sourceType is:%{public}d channels is :%{public}d",
        capturerOptions.capturerInfo.sourceType, streamInfo.channels);
    capturerOptions.capturerInfo.capturerFlags = 0;
    auto audioCaptureWrap = std::make_shared<UnifiedPipelineAudioCaptureWrap>(capturerOptions);
    audioCaptureWrap_.Set(audioCaptureWrap);
    audioCaptureWrap->InitThread();

    if (isEnableRawAudio_) {
        // Audio raw pipeline
        ConfigRawAudioPipeline(streamInfo, audioCaptureWrap);
    }
    // Audio pipeline
    ConfigAudioPipeline(streamInfo, audioCaptureWrap);
}

void MovieFileControllerVideo::ConfigAudioPipeline(
    const AudioStandard::AudioStreamInfo& streamInfo, std::shared_ptr<UnifiedPipelineAudioCaptureWrap> audioCaptureWrap)
{
    auto movieFileAudioBufferProducer = std::make_shared<MovieFileAudioBufferProducer>();
    movieFileAudioBufferProducer_.Set(movieFileAudioBufferProducer);
    movieFileAudioBufferProducer->InitBufferListener();
    audioCaptureWrap->AddBufferListener(movieFileAudioBufferProducer->GetAudioCaptureBufferListener());

    auto audioPipeline = movieFilePipelineManager_->GetPipelineWithProducer(movieFileAudioBufferProducer);
    if (isEnableRawAudio_) { // 使能先录后编，则走算法流程
        auto effectPlugin = std::make_shared<MovieFileAudioEffectPlugin>(streamInfo);
        auto audioEffectStreamInfo = effectPlugin->GetOutAudioStreamInfo();
        audioPipeline->AddPlugin(0, effectPlugin);
        MovieFileAudioEncoderEncodeNode::EncodeConfig audioEncodeConfig {
            .channelLayout = MovieFile::GetChannelLayoutByChannelCount(audioEffectStreamInfo.channels),
            .channelCount = audioEffectStreamInfo.channels,
            .sampleRate = audioEffectStreamInfo.samplingRate,
        };
        auto audioEncoderPlugin = std::make_shared<MovieFileAudioEncoderPlugin>(audioEncodeConfig);
        audioPipeline->AddPlugin(1, audioEncoderPlugin);
        sharedAudioEffectStreamInfo_ = std::make_shared<AudioStandard::AudioStreamInfo>(audioEffectStreamInfo);
    } else {
        auto audioPlugin = std::make_shared<MovieFileAudioPlugin>();
        audioPipeline->AddPlugin(0, audioPlugin);

        MovieFileAudioEncoderEncodeNode::EncodeConfig audioEncodeConfig {
            .channelLayout = MovieFile::GetChannelLayoutByChannelCount(streamInfo.channels),
            .channelCount = streamInfo.channels,
            .sampleRate = streamInfo.samplingRate,
        };
        auto audioEncoderPlugin = std::make_shared<MovieFileAudioEncoderPlugin>(audioEncodeConfig);
        audioPipeline->AddPlugin(1, audioEncoderPlugin);
        sharedAudioEffectStreamInfo_ = std::make_shared<AudioStandard::AudioStreamInfo>(streamInfo);
    }
}

void MovieFileControllerVideo::ConfigRawAudioPipeline(
    const AudioStandard::AudioStreamInfo& streamInfo, std::shared_ptr<UnifiedPipelineAudioCaptureWrap> audioCaptureWrap)
{
    auto movieFileAudioRawBufferProducer = std::make_shared<MovieFileAudioBufferProducer>();
    movieFileAudioRawBufferProducer_.Set(movieFileAudioRawBufferProducer);
    movieFileAudioRawBufferProducer->InitBufferListener();
    audioCaptureWrap->AddBufferListener(movieFileAudioRawBufferProducer->GetAudioCaptureBufferListener());

    auto audioRawPipeline = movieFilePipelineManager_->GetPipelineWithProducer(movieFileAudioRawBufferProducer);
    auto audioRawPlugin = std::make_shared<MovieFileAudioRawPlugin>();
    audioRawPipeline->AddPlugin(0, audioRawPlugin);
    MovieFileAudioEncoderEncodeNode::EncodeConfig audioEncodeConfig {
        .channelLayout = MovieFile::GetChannelLayoutByChannelCount(streamInfo.channels),
        .channelCount = streamInfo.channels,
        .sampleRate = streamInfo.samplingRate,
        .bitRate = MOVIE_FILE_AUDIO_HIGH_BITRATE,
    };
    auto audioEncoderPlugin = std::make_shared<MovieFileAudioEncoderPlugin>(audioEncodeConfig);
    audioRawPipeline->AddPlugin(1, audioEncoderPlugin);
    sharedAudioCaptureStreamInfo_ = std::make_shared<AudioStandard::AudioStreamInfo>(streamInfo);
}

MovieFileControllerVideo::MovieFileControllerVideo(
    int32_t width, int32_t height, bool isHdr, int32_t frameRate, int32_t videoBitrate)
    : videoWidth_(width), videoHeight_(height), frameRate_(frameRate)
{
    // 创建视频的生产端
    movieFileVideoEncodedBufferProducer_ = std::make_shared<MovieFileVideoEncodedBufferProducer>();
    // 编码阶段不处理旋转问题，muxer中处理一把旋转就好
    VideoEncoderConfig encoderNodeConfig {
        .width = width,
        .height = height,
        .rotation = 0,
        .isHdr = isHdr,
        .frameRate = frameRate,
        .videoBitrate = videoBitrate,
    };
    movieFileVideoEncodedBufferProducer_->ConfigVideoEncoder(encoderNodeConfig);
    videoStreamCallback_ = new VideoStreamCallback(movieFileVideoEncodedBufferProducer_);

    // 创建meta的生产端
    movieFileMetaBufferProducer_ = std::make_shared<MovieFileMetaBufferProducer>();
    movieFileMetaBufferProducer_->InitSurfaceWraper("movieMeta");

    // Meta pipeline
    auto metaPipeline = movieFilePipelineManager_->GetPipelineWithProducer(movieFileMetaBufferProducer_);
    metaPipeline->AddPlugin(0, std::make_shared<MovieFileMetaPlugin>());
}

MovieFileControllerVideo::~MovieFileControllerVideo()
{
    MEDIA_INFO_LOG("MovieFileControllerVideo::~MovieFileControllerVideo");
    auto captureWrap = audioCaptureWrap_.Get();
    if (captureWrap) {
        captureWrap->ReleaseCapture();
    }
    DeselectTargetAudioInputDevice();
}

void MovieFileControllerVideo::ChangeCodecSettings(
    VideoCodecType codecType, int32_t rotation, bool isBFrame, int32_t videoBitrate)
{
    videoCodecMime_ = GetMineTypeFromCodecType(codecType);
    movieFileVideoEncodedBufferProducer_->ChangeCodecSettings(videoCodecMime_, rotation, isBFrame, videoBitrate);
    if (!waterFilter_.empty() && !waterFilterParam_.empty()) {
        movieFileVideoEncodedBufferProducer_->AddVideoFilter(waterFilter_, waterFilterParam_);
    }
}

void MovieFileControllerVideo::AddVideoFilter(const std::string& filterName, const std::string& filterParam)
{
    waterFilter_ = filterName;
    waterFilterParam_ = filterParam;
    movieFileVideoEncodedBufferProducer_->AddVideoFilter(filterName, filterParam);
}

void MovieFileControllerVideo::RemoveVideoFilter(const std::string& filterName)
{
    waterFilter_ = "";
    waterFilterParam_ = "";
    movieFileVideoEncodedBufferProducer_->RemoveVideoFilter(filterName);
}

sptr<OHOS::IBufferProducer> MovieFileControllerVideo::GetVideoProducer()
{
    return movieFileVideoEncodedBufferProducer_->GetSurfaceProducer();
}

sptr<OHOS::IBufferProducer> MovieFileControllerVideo::GetRawVideoProducer()
{
    return nullptr;
}

sptr<OHOS::IBufferProducer> MovieFileControllerVideo::GetMetaProducer()
{
    return movieFileMetaBufferProducer_->GetSurfaceProducer();
}

void MovieFileControllerVideo::SetupPipeline(std::shared_ptr<MovieFileConsumer> movieFileConsumer)
{
    auto videoPipeline = movieFilePipelineManager_->GetPipelineWithProducer(movieFileVideoEncodedBufferProducer_);
    videoPipeline->SetDataConsumer(movieFileConsumer);

    auto movieFileAudioRawBufferProducer = movieFileAudioRawBufferProducer_.Get();
    if (movieFileAudioRawBufferProducer) {
        auto audioRawPipeline = movieFilePipelineManager_->GetPipelineWithProducer(movieFileAudioRawBufferProducer);
        audioRawPipeline->SetDataConsumer(movieFileConsumer);
    }

    auto movieFileAudioBufferProducer = movieFileAudioBufferProducer_.Get();
    if (movieFileAudioBufferProducer) {
        auto audioPipeline = movieFilePipelineManager_->GetPipelineWithProducer(movieFileAudioBufferProducer);
        audioPipeline->SetDataConsumer(movieFileConsumer);
    }

    auto metaPipeline = movieFilePipelineManager_->GetPipelineWithProducer(movieFileMetaBufferProducer_);
    metaPipeline->SetDataConsumer(movieFileConsumer);
}

int32_t MovieFileControllerVideo::MuxMovieFileStart(
    int64_t timestamp, MovieSettings movieSettings, int32_t cameraPosition)
{
    CAMERA_SYNC_TRACE;
    int32_t retCode = CamServiceError::CAMERA_UNKNOWN_ERROR;
    StatusTransfer(ControllerStatus::RUNNING, [&]() {
        MEDIA_INFO_LOG("MovieFileController MuxMovieFileFileStart");
        ConfigAudioCapture();
        // 创建数据消费端
        auto movieFileConsumer = std::make_shared<MovieFileConsumer>();
        SetupPipeline(movieFileConsumer);
        movieFileConsumer_.Set(movieFileConsumer);
        auto photoAssert = GetPhotoAsset();
        if (photoAssert == nullptr) {
            MEDIA_INFO_LOG("MovieFileController GetPhotoAsset fail ,release consumer");
            ReleaseConsumer();
            return;
        }
        lastAsset_.Set(photoAssert);

        std::vector<float> locationFloat {};
        CHECK_EXECUTE(movieSettings.isHasLocation, {
            locationFloat.emplace_back(movieSettings.location.latitude);
            locationFloat.emplace_back(movieSettings.location.longitude);
            locationFloat.emplace_back(movieSettings.location.altitude);
        });

        MEDIA_INFO_LOG("MovieFileController waterFilter_ is %{public}s waterFilterParam_ is %{public}s",
            waterFilter_.c_str(), waterFilterParam_.c_str());
        movieFileConsumer->SetUp(MovieFileConsumer::MovieFileConfig {
            .fd = photoAssert->GetVideoFd(VideoType::XT_ORIGIN_VIDEO),
            .rotation = movieSettings.rotation,
            .location = locationFloat,
            .coverTime = timestamp,
            .videoWidth = videoWidth_,
            .videoHeight = videoHeight_,
            .videoCodecMime = videoCodecMime_,
            .rawAudiostreamInfo = sharedAudioCaptureStreamInfo_,
            .audiostreamInfo = sharedAudioEffectStreamInfo_,
            .frameRate = frameRate_,
            .isSetWaterMark = !waterFilter_.empty() && !waterFilterParam_.empty(),
            // 消费端的的movieFileConfig_的videoBitrate用movieSettings传来的videoBitrate赋值
            .bitrate = movieFileVideoEncodedBufferProducer_->GetVideoBitrate(),
            .isBFrame = movieSettings.isBFrameEnabled,
            .deviceFoldState = static_cast<int32_t>(OHOS::Rosen::DisplayManagerLite::GetInstance().GetFoldStatus()),
            .deviceModel = system::GetParameter("persist.hiviewdfx.priv.sw.model", ""),
            .cameraPosition = cameraPosition });
        StartConsumerAndProducer(movieFileConsumer);
        retCode = CamServiceError::CAMERA_OK;
    });
    return retCode;
}

void MovieFileControllerVideo::StartConsumerAndProducer(std::shared_ptr<MovieFileConsumer> movieFileConsumer)
{
    movieFileConsumer->Start();
    movieFileVideoEncodedBufferProducer_->StartEncoder();
    movieFileVideoEncodedBufferProducer_->RequestIFrame();
    auto audioCaptureWrap = audioCaptureWrap_.Get();
    if (audioCaptureWrap) {
        audioCaptureWrap->StartCapture();
    }
}

void MovieFileControllerVideo::MuxMovieFilePause(int64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    StatusTransfer(ControllerStatus::PAUSED, [&]() {
        movieFileVideoEncodedBufferProducer_->StopEncoder(timestamp);
        auto audioCaptureWrap = audioCaptureWrap_.Get();
        if (audioCaptureWrap) {
            audioCaptureWrap->StopCapture();
        }
        auto movieFileConsumer = movieFileConsumer_.Get();
        if (movieFileConsumer) {
            movieFileConsumer->Pause();
        }
    });
}

void MovieFileControllerVideo::MuxMovieFileResume()
{
    CAMERA_SYNC_TRACE;
    StatusTransfer(ControllerStatus::RUNNING, [&]() {
        auto movieFileConsumer = movieFileConsumer_.Get();
        if (movieFileConsumer) {
            movieFileConsumer->Resume();
        }
        movieFileVideoEncodedBufferProducer_->StartEncoder();
        movieFileVideoEncodedBufferProducer_->RequestIFrame();
        auto audioCaptureWrap = audioCaptureWrap_.Get();
        if (audioCaptureWrap) {
            audioCaptureWrap->StartCapture();
        }
    });
}

std::string MovieFileControllerVideo::MuxMovieFileStop(int64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    std::string uri = "";
    StatusTransfer(ControllerStatus::STOPED, [&]() {
        MEDIA_INFO_LOG("MovieFileControllerVideo MuxMovieFileFileStop");
        movieFileVideoEncodedBufferProducer_->StopEncoder(timestamp);
        auto audioCaptureWrap = audioCaptureWrap_.Get();
        if (audioCaptureWrap) {
            audioCaptureWrap->StopCapture();
            audioCaptureWrap->ReleaseCapture();
        }
        ReleaseConsumer();
        auto lastAsset = lastAsset_.Get();
        if (lastAsset) {
            lastAsset->NotifyVideoSaveFinished(VideoType::ORIGIN_VIDEO);
            uri = lastAsset->GetPhotoAssetUri();
        }
        DeselectTargetAudioInputDevice();
    });
    return uri;
}

bool MovieFileControllerVideo::WaitFirstFrame()
{
    auto consumer = movieFileConsumer_.Get();
    if (consumer) {
        return consumer->WaitFirstFrame();
    }
    return false;
}

std::shared_ptr<PhotoAssetIntf> MovieFileControllerVideo::GetPhotoAsset()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("MovieFileRecorder::CreateMovieFileMediaLibrary is called");
    constexpr int32_t videoShotType = 1;
    auto photoAssetProxy = PhotoAssetProxy::GetPhotoAssetProxy(
        videoShotType, IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingTokenID());
    CHECK_RETURN_RET_ELOG(
        photoAssetProxy == nullptr, nullptr, "MovieFileRecorder::CreateMovieFileMediaLibrary get photoAssetProxy fail");
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->SetDisplayName(CreateVideoDisplayName());
    cameraPhotoProxy->SetIsVideo(true);
    cameraPhotoProxy->SetHighQuality(true);
    photoAssetProxy->AddPhotoProxy((sptr<PhotoProxy>&)cameraPhotoProxy);
    videoStreamCallback_->SetPhotoProxy(cameraPhotoProxy, photoAssetProxy);
    return photoAssetProxy;
}

void MovieFileControllerVideo::ReleaseConsumer()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("MovieFileControllerVideo ReleaseConsumer");
    auto consumer = movieFileConsumer_.Get();
    if (consumer) {
        consumer->Stop();
        videoStreamCallback_->WaitProcessEnd();
        consumer->SetDeferredVideoInfo(videoStreamCallback_->GetDeferredFlag(), videoStreamCallback_->GetVideoId());
        movieFileConsumer_.Set(nullptr);
        videoStreamCallback_->SetVideoId("");     // 重置videoId
        videoStreamCallback_->SetDeferredFlag(0); // 重置边播标记
    }
    MEDIA_INFO_LOG("MovieFileControllerVideo ReleaseConsumer done");
}

sptr<IStreamRepeatCallback> MovieFileControllerVideo::GetVideoStreamCallback()
{
    return videoStreamCallback_;
}

MovieFileControllerVideo::VideoStreamCallback::VideoStreamCallback(
    std::weak_ptr<MovieFileVideoEncodedBufferProducer> movieFileVideoEncodedBufferProducer)
    : movieFileVideoEncodedBufferProducer_(movieFileVideoEncodedBufferProducer)
{}

MovieFileControllerVideo::VideoStreamCallback::~VideoStreamCallback() {};

ErrCode MovieFileControllerVideo::VideoStreamCallback::OnFrameStarted()
{
    MEDIA_INFO_LOG("MovieFileControllerVideo::VideoStreamCallback::OnFrameStarted");
    {
        std::lock_guard<std::mutex> lock(waitProcessMutex_);
        isProcessDone_ = false;
    }
    auto movieFileVideoEncodedBufferProducer = movieFileVideoEncodedBufferProducer_.lock();
    if (movieFileVideoEncodedBufferProducer) {
        movieFileVideoEncodedBufferProducer->OnCommandArrival(
            std::make_unique<UnifiedPipelineCommand>(UnifiedPipelineCommandId::VIDEO_BUFFER_START, nullptr));
    }
    return ERR_OK;
}

ErrCode MovieFileControllerVideo::VideoStreamCallback::OnFrameEnded(int32_t frameCount)
{
    MEDIA_INFO_LOG("MovieFileControllerVideo::VideoStreamCallback::OnFrameEnded");
    return ERR_OK;
}

ErrCode MovieFileControllerVideo::VideoStreamCallback::OnFrameError(int32_t errorCode)
{
    return ERR_OK;
}

ErrCode MovieFileControllerVideo::VideoStreamCallback::OnSketchStatusChanged(SketchStatus status)
{
    return ERR_OK;
}

void MovieFileControllerVideo::VideoStreamCallback::WaitProcessEnd()
{
    constexpr int32_t WAIT_PROCESS_TIMEOUT = 5000; // 5000 ms
    std::unique_lock<std::mutex> lock(waitProcessMutex_);
    processCondition_.wait_for(lock, chrono::milliseconds(WAIT_PROCESS_TIMEOUT), [this]() { return isProcessDone_; });
}

ErrCode MovieFileControllerVideo::VideoStreamCallback::OnDeferredVideoEnhancementInfo(
    const CaptureEndedInfoExt& captureEndedInfo)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("VideoStreamCallback::OnDeferredVideoEnhancementInfo start");

    // Add muxer info for deferredVideoEnhanceFlag
    {
        std::lock_guard<std::mutex> lock(waitProcessMutex_);
        if (GetDeferredFlag() != 1) {
            SetDeferredFlag(captureEndedInfo.deferredVideoEnhanceFlag);
        }
        SetVideoId(captureEndedInfo.videoId);
        isProcessDone_ = true;
        processCondition_.notify_all();
    }

    {
        std::lock_guard<std::mutex> lock(proxyMutex_);
        CHECK_RETURN_RET_ELOG(
            photoProxy_ == nullptr, ERR_OK, "VideoStreamCallback::OnDeferredVideoEnhancementInfo photoProxy_ is null");
        CHECK_RETURN_RET_ELOG(photoAssetProxy_ == nullptr, ERR_OK,
            "VideoStreamCallback::OnDeferredVideoEnhancementInfo photoAssetProxy_ is null");

        photoProxy_->SetPhotoId(captureEndedInfo.videoId);
        photoProxy_->SetVideoEnhancementType(captureEndedInfo.isDeferredVideoEnhancementAvailable ? 1 : 0);
        photoProxy_->SetHighQuality(!captureEndedInfo.isDeferredVideoEnhancementAvailable);
        photoAssetProxy_->UpdatePhotoProxy(photoProxy_);
    }

    MEDIA_INFO_LOG("VideoStreamCallback::OnDeferredVideoEnhancementInfo end");
    return ERR_OK;
}

ErrCode MovieFileControllerVideo::VideoStreamCallback::OnFramePaused()
{
    return ERR_OK;
}

ErrCode MovieFileControllerVideo::VideoStreamCallback::OnFrameResumed()
{
    return ERR_OK;
}

sptr<IRemoteObject> MovieFileControllerVideo::VideoStreamCallback::AsObject()
{
    return nullptr;
};

} // namespace CameraStandard
} // namespace OHOS
