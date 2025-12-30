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

#include "recorder_engine.h"

#include <fcntl.h>
#include <memory>
#include <nlohmann/json.hpp>

#include "any.h"
#include "audio_session_manager.h"
#include "audio_source_type.h"
#include "audio_stream_info.h"
#include "audio_system_manager.h"
#include "camera_log.h"
#include "camera_util.h"
#include "camera_xml_parser.h"
#include "cfilter.h"
#include "image_effect_proxy.h"
#include "image_source.h"
#include "ipc_skeleton.h"
#include "osal/task/pipeline_threadpool.h"
#include "token_setproc.h"
#include "video_types.h"
#include "watermark_util.h"
#include <parameters.h>
#include "system_ability_definition.h"
#include "bundle_mgr_interface.h"
#include "iservice_registry.h"

namespace OHOS {
namespace CameraStandard {
namespace {
constexpr int32_t DEFAULT_ALL_CLUSTER_ID = -1;
// audio default settings
const std::string DEFAULT_AUDIO_MIME_TYPE = Plugins::MimeType::AUDIO_AAC;
constexpr int32_t DEFAULT_AUDIO_BIT_RATE = 192000;
constexpr int32_t DEFAULT_RAW_AUDIO_BIT_RATE = 384000;
constexpr int32_t DEFAULT_AUDIO_SAMPLE_RATE = SAMPLE_RATE_48000;
const std::string DEFAULT_AUDIO_TRACK_REFERENCE_TYPE = "auxl";
const std::string DEFAULT_AUDIO_TRACK_DESCRIPTION = "com.openharmony.audiomode.auxiliary";
constexpr Plugins::AudioAacProfile DEFAULT_AUDIO_AAC_PROFILE = Plugins::AudioAacProfile::LC;
constexpr Plugins::AudioSampleFormat DEFAULT_AUDIO_SAMPLE_FORMAT = Plugins::AudioSampleFormat::SAMPLE_S16LE;
// movie video stream default settings
constexpr int32_t DEFAULT_MOVIE_CLUSTER_ID = 0;
constexpr int32_t DEFAULT_MOVIE_FRAME_RATE = 30;
// raw video stream default settings
constexpr int32_t DEFAULT_RAW_CLUSTER_ID = 1;
constexpr int32_t DEFAULT_RAW_BIT_RATE = 30000000;
// meta stream default settings
constexpr int32_t DEFAULT_META_CLUSTER_ID = 1;
const std::string DEFAULT_META_MIME_TYPE = Plugins::MimeType::TIMED_METADATA;
const std::string DEFAULT_META_TIMED_KEY = "com.openharmony.timed_metadata.cinematic_video";
const std::string DEFAULT_META_SOURCE_TRACK_MIME = Plugins::MimeType::VIDEO_HEVC;
// debug stream default settings
const std::string DEFAULT_DEBUG_MIME_TYPE = Plugins::MimeType::TIMED_METADATA;
const std::string DEFAULT_DEBUG_TIMED_KEY = "com.openharmony.timed_metadata.vid_maker_info";
// prey stream default settings
constexpr int32_t DEFAULT_PREY_CLUSTER_ID = 1;
constexpr int32_t DEFAULT_PREY_FRAME_WIDTH = 960;
constexpr int32_t DEFAULT_PREY_FRAME_HEIGHT = 540;
const std::string DEFAULT_PREY_TRACK_REFERENCE_TYPE = "auxl";
const std::string DEFAULT_PREY_TRACK_DESCRIPTION = "com.openharmony.moviemode.prey";
constexpr int32_t DEFAULT_PREY_FRAME_QP_MAX = 15;
constexpr int32_t DEFAULT_PREY_FRAME_QP_MIN = 15;
// depth stream default settings
constexpr int32_t DEFAULT_DEPTH_CLUSTER_ID = 1;
constexpr int32_t DEFAULT_DEPTH_FRAME_WIDTH = 512;
constexpr int32_t DEFAULT_DEPTH_FRAME_HEIGHT = 288;
const std::string DEFAULT_DEPTH_TRACK_REFERENCE_TYPE = "vdep";
const std::string DEFAULT_DEPTH_TRACK_DESCRIPTION = "com.openharmony.moviemode.depth";
constexpr int32_t DEFAULT_DEPTH_FRAME_QP_MAX = 10;
constexpr int32_t DEFAULT_DEPTH_FRAME_QP_MIN = 10;
// meta settings
const string TIMED_META_TRACK_TAG = "use_timed_meta_track";
constexpr int32_t DEFAULT_USE_TIMED_META_TRACK = 1;
// muxer default settings
constexpr OutputFormatType DEFAULT_MUXER_OUTPUT_FORMAT = FORMAT_MPEG_4;
constexpr int32_t RAW_VIDEO_TYPE = 1;
constexpr int32_t MOVIE_VIDEO_TYPE = 2;
constexpr int32_t WAIT_MUXER_DONE_TIMEOUT_MS = 2000; // 2000ms
// time
constexpr int64_t SEC_TO_NS = 1000000000; // 1s = 1e9 ns
}

class RecorderEngineCEventReceiver : public CEventReceiver {
public:
    explicit RecorderEngineCEventReceiver(wptr<RecorderEngine> recorder)
    {
        recorder_ = recorder;
    }

    void OnEvent(const Event &event)
    {
        MEDIA_DEBUG_LOG("RecorderEngineCEventReceiver OnEvent is called");
        auto recorder = recorder_.promote();
        if (recorder) {
            recorder->OnEvent(event);
        } else {
            MEDIA_ERR_LOG("RecorderEngineCEventReceiver OnEvent error, recorder is null");
        }
    }

private:
    wptr<RecorderEngine> recorder_;
};

class RecorderEngineFilterCallback : public CFilterCallback {
public:
    explicit RecorderEngineFilterCallback(wptr<RecorderEngine> recorder)
    {
        recorder_ = recorder;
    }

    Status OnCallback(const std::shared_ptr<CFilter>& filter, CFilterCallBackCommand cmd, CStreamType outType)
    {
        auto recorder = recorder_.promote();
        if (recorder) {
            return recorder->OnCallback(filter, cmd, outType);
        }
        return Status::ERROR_UNKNOWN;
    }

private:
    wptr<RecorderEngine> recorder_;
};

std::string GetBundleName(int uid)
{
    std::string bundleName = "";
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_RET_ELOG(samgr == nullptr, bundleName, "GetClientBundle Get ability manager failed");

    sptr<IRemoteObject> object = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    CHECK_RETURN_RET_ELOG(object == nullptr, bundleName, "GetClientBundle object is NULL.");

    sptr<OHOS::AppExecFwk::IBundleMgr> bms = iface_cast<OHOS::AppExecFwk::IBundleMgr>(object);
    CHECK_RETURN_RET_ELOG(bms == nullptr, bundleName, "GetClientBundle bundle manager service is NULL.");

    auto result = bms->GetNameForUid(uid, bundleName);
    CHECK_RETURN_RET_DLOG(result != ERR_OK, "", "GetClientBundle GetBundleNameForUid fail");
    MEDIA_INFO_LOG("bundle name is %{public}s ", bundleName.c_str());

    return bundleName;
}

void RecorderEngine::SetIsWaitForMeta(bool isWait)
{
    needWaitForMeta_ = isWait;
}

void RecorderEngine::SetIsWaitForMuxerDone(bool isWait)
{
    needWaitForMuxerDone_ = isWait;
}

void RecorderEngine::SetIsStreamStarted(bool isStarted)
{
    CHECK_EXECUTE(pipeline_, pipeline_->SetStreamStarted(isStarted));
}

bool RecorderEngine::IsNeedWaitForMuxerDone()
{
    return needWaitForMuxerDone_;
}

std::string RecorderEngine::GetMovieFileUri()
{
    return movieFileUri_;
}

bool RecorderEngine::IsNeedStopCallback()
{
    return needStopCallback_;
}

void RecorderEngine::SetIsNeedStopCallback(bool isNeed)
{
    needStopCallback_ = isNeed;
}

void RecorderEngine::SetIsNeedWaitForRawMuxerDone(bool isNeed)
{
    needWaitForRawMuxerDone_ = isNeed;
}

RecorderEngine::RecorderEngine(wptr<RecorderIntf> recorder) : recorder_(recorder)
{
    MEDIA_DEBUG_LOG("RecorderEngine ctor is called");
}

RecorderEngine::~RecorderEngine()
{
    MEDIA_INFO_LOG("RecorderEngine dtor is called");
    PipeLineThreadPool::GetInstance().DestroyThread(recorderId_);
    ImageEffectProxy::FreeImageEffectDynamiclib();
}

int32_t RecorderEngine::Init()
{
    MEDIA_INFO_LOG("RecorderEngine::Init is called");
    Status ret = Status::OK;
    ret = InitCallerInfo();
    ret = InitPipeline();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, (int32_t)ret, "RecorderEngine::Init failed");
    return (int32_t)ret;
}

Status RecorderEngine::InitCallerInfo()
{
    MEDIA_INFO_LOG("RecorderEngine::InitCallerInfo is called");
    // set caller info
    appTokenId_ = IPCSkeleton::GetCallingTokenID();
    appFullTokenId_ = IPCSkeleton::GetCallingFullTokenID();
    appUid_ = UID_CAMERA;
    appPid_ = IPCSkeleton::GetCallingPid();
    // set first caller tokenId, the audio server will check it later when creating audio process
    SetFirstCallerTokenID(appTokenId_);
    bundleName_ = GetBundleName(appUid_);
    MEDIA_INFO_LOG("RecorderEngine::Init, appUid: %{public}d, appPid: %{public}d, bundleName_: %{public}s",
        appUid_, appPid_, bundleName_.c_str());
    return Status::OK;
}

Status RecorderEngine::InitPipeline()
{
    MEDIA_INFO_LOG("RecorderEngine::InitPipeline is called");
    recorderId_ = std::string("MOV_REC_") + std::to_string(Pipeline::GetNextPipelineId());
    recorderEventReceiver_ = std::make_shared<RecorderEngineCEventReceiver>(this);
    recorderCallback_ = std::make_shared<RecorderEngineFilterCallback>(this);
    // init pipeline
    pipeline_ = std::make_shared<Pipeline>();
    pipeline_->Init(recorderEventReceiver_, recorderCallback_, recorderId_);
    return Status::OK;
}

Status RecorderEngine::AddResource()
{
    MEDIA_INFO_LOG("RecorderEngine::AddResource is called");
    Status ret = Status::OK;
    CHECK_RETURN_RET(isAllSourceAdded_ == true, ret);
    ret = AddMovieSource();
    ret = AddRawSource();
    ret = AddAudioSource();
    ret = AddMovieDebugSource();
    ret = AddPreySource();
    ret = AddDepthSource();
    ret = AddMetaSource();
    ret = AddRawDebugSource();
    CHECK_EXECUTE(ret == Status::OK, isAllSourceAdded_ = true);
    return ret;
}

void RecorderEngine::NotifyMuxerDone()
{
    MEDIA_INFO_LOG("MuxerFilter::NotifyMuxerDone is called");
    std::unique_lock<std::mutex> lock(muxerMutex_);
    needWaitForRawMuxerDone_ = false;
    muxerDoneCondition_.notify_all();
}

void RecorderEngine::WaitForMuxerDoneThenUpdatePhotoProxy()
{
    MEDIA_INFO_LOG("RecorderEngine::WaitForMuxerDone is called");
    auto thisWptr = wptr<RecorderEngine>(this);
    std::thread asyncThread([thisWptr]() {
        MEDIA_DEBUG_LOG("RecorderEngine::WaitForMuxerDone thread is called");
        auto thisPtr = thisWptr.promote();
        if (thisPtr) {
            MEDIA_DEBUG_LOG("RecorderEngine::WaitForMuxerDone wait is called");
            std::unique_lock<std::mutex> lock(thisPtr->muxerMutex_);
            std::cv_status waitStatus = thisPtr->muxerDoneCondition_.wait_for(lock, std::chrono::milliseconds(2000));
            // Wait timeout when raw video is not muxed
            if (waitStatus == std::cv_status::timeout) {
                MEDIA_ERR_LOG("RecorderEngine::WaitForMuxerDone wait timeout");
            } else {
                MEDIA_DEBUG_LOG("RecorderEngine::WaitForMuxerDone notified");
            }
        }
        if (thisPtr && thisPtr->movieFilePhotoAssetProxy_ && thisPtr->cameraPhotoProxy_) {
            MEDIA_DEBUG_LOG("RecorderEngine::WaitForMuxerDone end, start UpdatePhotoProxy");
            thisPtr->movieFilePhotoAssetProxy_->UpdatePhotoProxy(thisPtr->cameraPhotoProxy_);
            thisPtr->needWaitForMuxerDone_ = false;
        }
    });
    asyncThread.detach();
}

void RecorderEngine::NotifyUserMetaSet()
{
    MEDIA_INFO_LOG("MuxerFilter::NotifyWaitForUserMeta is called");
    std::unique_lock<std::mutex> lock(userMetaMutex_);
    userMetaCondition_.notify_one();
}

void RecorderEngine::WaitForUserMetaSet()
{
    MEDIA_INFO_LOG("RecorderEngine::WaitForUserMetaSet is called");
    auto thisWptr = wptr<RecorderEngine>(this);
    std::thread asyncThread([thisWptr]() {
        MEDIA_DEBUG_LOG("RecorderEngine::WaitForUserMetaSet thread is called");
        auto thisPtr = thisWptr.promote();
        if (thisPtr) {
            MEDIA_DEBUG_LOG("RecorderEngine::WaitForUserMetaSet wait is called");
            std::unique_lock<std::mutex> lock(thisPtr->userMetaMutex_);
            std::cv_status waitStatus = thisPtr->userMetaCondition_.wait_for(lock, std::chrono::milliseconds(1000));
            // Waiting timeout with no video frame received
            CHECK_PRINT_ELOG(waitStatus == std::cv_status::timeout,
                "RecorderEngine::WaitForUserMetaSet wait timeout with no user meta received");
            MEDIA_DEBUG_LOG("RecorderEngine::WaitForUserMetaSet notified or timeout");
        }
        if (thisPtr) {
            MEDIA_DEBUG_LOG("RecorderEngine::WaitForUserMetaSet end, start release muxer");
            thisPtr->rawMuxerFilter_.Set(nullptr);
            thisPtr->needWaitForMeta_ = false;
        }
    });
    asyncThread.detach();
}

Status RecorderEngine::RemoveResource()
{
    MEDIA_INFO_LOG("RecorderEngine::RemoveResource is called");
    Status ret = Status::OK;
    movieMuxerFilter_ = nullptr;
    if (needWaitForMeta_) {
        MEDIA_INFO_LOG("RecorderEngine::RemoveResource start waiting for meta before release muxer");
        WaitForUserMetaSet();
    } else {
        MEDIA_DEBUG_LOG("RecorderEngine::RemoveResource no need wait for meta");
        rawMuxerFilter_.Set(nullptr);
    }
    CHECK_EXECUTE(audioCaptureFilter_, pipeline_->RemoveHeadFilter(audioCaptureFilter_));
#ifdef CAMERA_USE_IMAGE_EFFECT
    CHECK_EXECUTE(imageEffectFilter_, pipeline_->RemoveHeadFilter(imageEffectFilter_));
#else
    CHECK_EXECUTE(movieEncoderFilter_, pipeline_->RemoveHeadFilter(movieEncoderFilter_));
#endif
    CHECK_EXECUTE(movieDebugFilter_, pipeline_->RemoveHeadFilter(movieDebugFilter_));
    CHECK_EXECUTE(rawEncoderFilter_, pipeline_->RemoveHeadFilter(rawEncoderFilter_));
    CHECK_EXECUTE(depthCacheFilter_, pipeline_->RemoveHeadFilter(depthCacheFilter_));
    CHECK_EXECUTE(preyCacheFilter_, pipeline_->RemoveHeadFilter(preyCacheFilter_));
    CHECK_EXECUTE(metaDataFilter_, pipeline_->RemoveHeadFilter(metaDataFilter_));
    CHECK_EXECUTE(rawDebugFilter_, pipeline_->RemoveHeadFilter(rawDebugFilter_));
    CHECK_EXECUTE(ret == Status::OK, isAllSourceAdded_ = false);
    return ret;
}

int32_t RecorderEngine::Prepare()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("RecorderEngine::Prepare is called");
    Status ret = Status::OK;

    ret = RemoveResource();
    ret = AddResource();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, (int32_t)ret, "Add resource failed");

    auto recorder = recorder_.promote();
    CHECK_EXECUTE(recorder, SetRotation(recorder->GetMuxerRotation())); // update muxer rotation

    CheckAudioPostEditAbility();
    ret = InitCallerInfo();
    // prepare stream source
    ret = PrepareMovieSource();
    ret = PrepareAudioSource();
    ret = PrepareMovieDebugSource();
    ret = PrepareRawSource();
    ret = PreparePreySource();
    ret = PrepareDepthSource();
    ret = PrepareMetaSource();
    ret = PrepareRawDebugSource();
    // prepare pipeline
    ret = pipeline_->Prepare();
    CHECK_RETURN_RET_ELOG(
        ret != Status::OK, (int32_t)ret, "RecorderEngine::Prepare failed, pipeline prepare failed");
    // prepare surface
    ret = PrepareSurface();
    CHECK_EXECUTE(ret == Status::OK, OnStateChanged(StateId::READY));
    isFirstPrepare_ = false;
    return (int32_t)ret;
};

Status RecorderEngine::StartRecording()
{
    MEDIA_DEBUG_LOG("RecorderEngine::StartRecording is called.");
    Status ret = Status::OK;
    if (curState_ == StateId::PAUSE) {
        ret = pipeline_->Resume();
    } else {
        ret = pipeline_->Start();
    }
    // if start failed, stop and remove resource
    if (ret != Status::OK) {
        CHECK_EXECUTE(pipeline_, pipeline_->SetStreamStarted(false));
        StopRecording();
        MEDIA_ERR_LOG("RecorderEngine StartRecording failed");
        return ret;
    }
    std::string resolution = std::to_string(movieWidth_) + "," + std::to_string(movieHeight_);
    SetUserMeta("com.openharmony.targetVideoResolution", resolution);
    SetEncParamMeta();
    SetWatermarkMeta();
    auto recorder = recorder_.promote();
    CHECK_EXECUTE(recorder, recorder->EnableDetectedObjectLifecycleReport(true, -1));
    OnStateChanged(StateId::RECORDING);
    CAMERA_SYSEVENT_BEHAVIOR("Cinematic Start Recording");
    return Status::OK;
}

Status RecorderEngine::PauseRecording()
{
    MEDIA_INFO_LOG("RecorderEngine::PauseRecording is called");
    Status ret = Status::OK;
    if (curState_ != StateId::READY) {
        ret = pipeline_->Pause();
        CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "RecorderEngine Pause failed");
    }
    OnStateChanged(StateId::PAUSE);
    return ret;
}

Status RecorderEngine::ResumeRecording()
{
    MEDIA_INFO_LOG("RecorderEngine::ResumeRecording is called");
    Status ret = Status::OK;
    ret = pipeline_->Resume();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "RecorderEngine Resume failed");
    OnStateChanged(StateId::RECORDING);
    return ret;
}

Status RecorderEngine::StopRecording()
{
    MEDIA_INFO_LOG("RecorderEngine::StopRecording is called");
    Status ret = Status::OK;
    CHECK_RETURN_RET(curState_ == StateId::INIT, Status::OK);

    int64_t currentTime = GetCurrentTime();
    CHECK_EXECUTE(audioCaptureFilter_, audioCaptureFilter_->SendEos(currentTime));
    CHECK_EXECUTE(movieEncoderFilter_, movieEncoderFilter_->SetStopTime(currentTime));
    CHECK_EXECUTE(rawEncoderFilter_, rawEncoderFilter_->SetStopTime(currentTime));
    CHECK_EXECUTE(depthEncoderFilter_, depthEncoderFilter_->SetStopTime(currentTime));
    CHECK_EXECUTE(preyEncoderFilter_, preyEncoderFilter_->SetStopTime(currentTime));

    auto recorder = recorder_.promote();
    int64_t firstTimestamp;
    CHECK_EXECUTE(rawEncoderFilter_, rawEncoderFilter_->GetMuxerFirstFrameTimestamp(firstTimestamp));
    CHECK_EXECUTE(recorder, recorder->SetFirstFrameTimestamp(firstTimestamp));

    int64_t stopTimestamp = 0;
    CHECK_EXECUTE(rawEncoderFilter_, stopTimestamp = rawEncoderFilter_->GetStopTimestamp());
    CHECK_EXECUTE(recorder, recorder->EnableDetectedObjectLifecycleReport(false, stopTimestamp));

    ret = pipeline_->Stop();
    CHECK_EXECUTE(ret == Status::OK, OnStateChanged(StateId::INIT));

    ret = RemoveResource();

    CAMERA_SYSEVENT_BEHAVIOR("Cinematic Stop Recording");
    CHECK_RETURN_RET_ELOG(curState_ != StateId::INIT, Status::ERROR_INVALID_STATE, "StopRecording fail");
    return Status::OK;
}

Status RecorderEngine::PrepareAudioSource()
{
    MEDIA_INFO_LOG("RecorderEngine::PrepareAudioSource is called");

    Status ret = Status::OK;
    // cofig audio source
    ConfigAudioCaptureFormat();
    ret = ConfigAudioCaptureFilter();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "ConfigAudioCaptureFilter failed");
    if (movieEncoderFilter_) {
        audioCaptureFilter_->SetWithVideo(true);
    } else {
        audioCaptureFilter_->SetWithVideo(false);
    }
    MEDIA_INFO_LOG("PrepareAudioSource success.");
    OnStateChanged(StateId::RECORDING_SETTING);
    return ret;
}

Status RecorderEngine::AddAudioSource()
{
    MEDIA_INFO_LOG("RecorderEngine::AddAudioSource is called");
    Status ret = Status::OK;
    // create audio capture filter as audio source
    CHECK_EXECUTE(audioCaptureFilter_ == nullptr,
        audioCaptureFilter_ = std::make_shared<AudioCaptureFilter>("AudioCaptureFilter", CFilterType::AUDIO_CAPTURE));
    CHECK_RETURN_RET_ELOG(audioCaptureFilter_ == nullptr, Status::ERROR_NULL_POINTER,
        "RecorderEngine::create AudioCaptureFilter failed");
    // add audio source into pipeline
    ret = pipeline_->AddHeadFilters({audioCaptureFilter_});
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "AddFilters audioCapture to pipeline fail");
    return ret;
}

void RecorderEngine::ConfigAudioCaptureFormat()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigAudioCaptureFormat is called");
    CHECK_RETURN(!audioCaptureFilter_);
    int32_t audioChannelNum = isAudioPostEditEnabled_ ? GetMicNum() : AudioChannel::STEREO;
    // capture config
    audioCaptureFormat_->Set<Tag::AUDIO_SAMPLE_FORMAT>(DEFAULT_AUDIO_SAMPLE_FORMAT);
    audioCaptureFormat_->Set<Tag::AUDIO_SAMPLE_RATE>(DEFAULT_AUDIO_SAMPLE_RATE);
    audioCaptureFormat_->Set<Tag::AUDIO_CHANNEL_COUNT>(audioChannelNum);
    audioCaptureFormat_->Set<Tag::MEDIA_BITRATE>(DEFAULT_AUDIO_BIT_RATE);
    // caller info
    audioCaptureFormat_->Set<Tag::APP_TOKEN_ID>(appTokenId_);
    audioCaptureFormat_->Set<Tag::APP_UID>(appUid_);
    audioCaptureFormat_->Set<Tag::APP_PID>(appPid_);
    audioCaptureFormat_->Set<Tag::APP_FULL_TOKEN_ID>(appFullTokenId_);
}

Status RecorderEngine::ConfigAudioCaptureFilter()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigAudioCaptureFilter is called");
    CHECK_RETURN_RET(!audioCaptureFilter_, Status::OK);
    SourceType audioSourceType = isAudioPostEditEnabled_ ? SOURCE_TYPE_UNPROCESSED : SOURCE_TYPE_CAMCORDER;
    audioCaptureFilter_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
    audioCaptureFilter_->SetAudioSource(audioSourceType);
    audioCaptureFilter_->SetParameter(audioCaptureFormat_);
    audioCaptureFilter_->Init(recorderEventReceiver_, recorderCallback_);
    return Status::OK;
}

Status RecorderEngine::AddMovieSource()
{
    MEDIA_INFO_LOG("RecorderEngine::AddMovieSource is called");
    Status ret = Status::OK;
    // create video encoder filter as movie source
    CHECK_EXECUTE(movieEncoderFilter_ == nullptr,
        movieEncoderFilter_ = std::make_shared<VideoEncoderFilter>("MovieEncoderFilter", CFilterType::VIDEO_ENC));
    CHECK_RETURN_RET_ELOG(movieEncoderFilter_ == nullptr, Status::ERROR_NULL_POINTER,
        "RecorderEngine::create MovieEncoderFilter failed");

    // add movie source into pipeline
#ifdef CAMERA_USE_IMAGE_EFFECT
    // create image effect filter if image_effect system component is included
    CHECK_EXECUTE(imageEffectFilter_ == nullptr,
        imageEffectFilter_ = std::make_shared<ImageEffectFilter>("ImageEffectFilter", CFilterType::IMAGE_EFFECT));
    CHECK_RETURN_RET_ELOG(imageEffectFilter_ == nullptr, Status::ERROR_NULL_POINTER,
        "RecorderEngine::create ImageEffectFilter failed");
    MEDIA_INFO_LOG("Add ImageEffectFilter as head filter to pipeline");
    ret = pipeline_->AddHeadFilters({imageEffectFilter_});
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "Add ImageEffectFilter to pipeline failed");
#else
    MEDIA_INFO_LOG("Add MovieEncoderFilter as head filter to pipeline");
    ret = pipeline_->AddHeadFilters({movieEncoderFilter_});
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "Add MovieEncoderFilter to pipeline fail");
#endif
    return ret;
}

Status RecorderEngine::PrepareMovieSource()
{
    MEDIA_INFO_LOG("RecorderEngine::PrepareMovieSource is called");
    Status ret = Status::OK;

    // config image effect filter
#ifdef CAMERA_USE_IMAGE_EFFECT
    ConfigImageEffectFilter();
#endif

    // config movie source
    ConfigMovieEncFormat();
    ret = ConfigMovieEncoderFilter();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "ConfigMovieEncoderFilter failed");

    MEDIA_INFO_LOG("PrepareMovieSource success.");
    OnStateChanged(StateId::RECORDING_SETTING);
    return ret;
}

void RecorderEngine::ConfigMovieEncFormat()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigMovieEncFormat is called");
    CHECK_RETURN(!movieEncoderFilter_);
    // movie stream encode config
    movieEncFormat_->Set<Tag::VIDEO_WIDTH>(movieWidth_);
    movieEncFormat_->Set<Tag::VIDEO_HEIGHT>(movieHeight_);
    movieEncFormat_->Set<Tag::MEDIA_BITRATE>(movieSettings_.videoBitrate);
    movieEncFormat_->Set<Tag::VIDEO_FRAME_RATE>(DEFAULT_MOVIE_FRAME_RATE);
    MEDIA_INFO_LOG("RecorderEngine::ConfigMovieEncFormat:%{public}d*%{public}d bitrate:%{public}d",
        movieWidth_, movieHeight_, movieSettings_.videoBitrate);
    auto recorder = recorder_.promote();
    CHECK_EXECUTE(recorder, isMovieHdr_ = recorder->IsMovieStreamHdr());
    switch (movieSettings_.videoCodecType) {
        case EngineVideoCodecType::VIDEO_ENCODE_TYPE_AVC:
            movieEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::VIDEO_AVC);
            movieEncFormat_->Set<Tag::VIDEO_H264_PROFILE>(Plugins::VideoH264Profile::BASELINE);
            movieEncFormat_->Set<Tag::VIDEO_H264_LEVEL>(32); // 32: LEVEL 3.2
            break;
        case EngineVideoCodecType::VIDEO_ENCODE_TYPE_HEVC:
            movieEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::VIDEO_HEVC);
            CHECK_EXECUTE(isMovieHdr_,
                movieEncFormat_->Set<Tag::VIDEO_H265_PROFILE>(Plugins::HEVCProfile::HEVC_PROFILE_MAIN_10));
            break;
        default:
            break;
    }

    movieEncFormat_->Set<Tag::VIDEO_ENCODE_BITRATE_MODE>(Plugins::VideoEncodeBitrateMode::SQR);
    movieEncFormat_->SetData(Tag::VIDEO_ENCODER_ENABLE_B_FRAME, movieSettings_.isBFrameEnabled);
}

Status RecorderEngine::ConfigImageEffectFilter()
{
#ifdef CAMERA_USE_IMAGE_EFFECT
    MEDIA_INFO_LOG("RecorderEngine::ConfigImageEffectFilter is called");
    CHECK_RETURN_RET(!imageEffectFilter_, Status::OK);
    imageEffectFilter_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
    imageEffectFilter_->SetClusterId(DEFAULT_MOVIE_CLUSTER_ID);
    imageEffectFilter_->Init(recorderEventReceiver_, recorderCallback_);
#endif
    return Status::OK;
}

Status RecorderEngine::ConfigMovieEncoderFilter()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigMovieEncoderFilter is called");
    CHECK_RETURN_RET(!movieEncoderFilter_, Status::OK);
    movieEncoderFilter_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
    movieEncoderFilter_->SetClusterId(DEFAULT_MOVIE_CLUSTER_ID);
    movieEncoderFilter_->SetCodecFormat(movieEncFormat_);
    movieEncoderFilter_->Init(recorderEventReceiver_, recorderCallback_);
    Status ret = movieEncoderFilter_->Configure(movieEncFormat_);
    auto waterMarkBuffer = waterMarkBuffer_.Get();
    CHECK_EXECUTE(waterMarkBuffer, movieEncoderFilter_->SetWatermark(waterMarkBuffer));
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "movieEncoderFilter Configure fail");
    return ret;
}

Status RecorderEngine::AddRawSource()
{
    MEDIA_INFO_LOG("RecorderEngine::AddRawSource is called");
    Status ret = Status::OK;
    // create video encoder filter as raw video source
    CHECK_EXECUTE(rawEncoderFilter_ == nullptr,
        rawEncoderFilter_ = std::make_shared<VideoEncoderFilter>("RawEncoderFilter", CFilterType::VIDEO_ENC));
    CHECK_RETURN_RET_ELOG(
        rawEncoderFilter_ == nullptr, Status::ERROR_NULL_POINTER, "RecorderEngine::create RawEncoderFilter failed");
    // add audio source into pipeline
    ret = pipeline_->AddHeadFilters({rawEncoderFilter_});
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "Add RawEncoderFilter to pipeline fail");
    return ret;
}

Status RecorderEngine::PrepareRawSource()
{
    MEDIA_INFO_LOG("RecorderEngine::PrepareRawSource is called");
    Status ret = Status::OK;

    // config movie source
    ConfigRawEncFormat();
    ret = ConfigRawEncoderFilter();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "ConfigRawEncoderFilter failed");

    MEDIA_INFO_LOG("PrepareRawSource success.");
    OnStateChanged(StateId::RECORDING_SETTING);
    return ret;
}

void RecorderEngine::ConfigRawEncFormat()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigRawEncFormat is called");
    CHECK_RETURN(!rawEncoderFilter_);
    // movie stream encode config
    rawEncFormat_->Set<Tag::VIDEO_WIDTH>(rawWidth_);
    rawEncFormat_->Set<Tag::VIDEO_HEIGHT>(rawHeight_);
    rawEncFormat_->Set<Tag::MEDIA_BITRATE>(DEFAULT_RAW_BIT_RATE);
    rawEncFormat_->Set<Tag::VIDEO_FRAME_RATE>(DEFAULT_MOVIE_FRAME_RATE);
    rawEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::VIDEO_HEVC);
    CHECK_EXECUTE(isMovieHdr_, rawEncFormat_->Set<Tag::VIDEO_H265_PROFILE>(Plugins::HEVCProfile::HEVC_PROFILE_MAIN_10));
    MEDIA_INFO_LOG("RecorderEngine::ConfigRawEncFormat:%{public}d*%{public}d bitrate:%{public}d",
        rawWidth_, rawHeight_, movieSettings_.videoBitrate);
    rawEncFormat_->Set<Tag::VIDEO_ENCODE_BITRATE_MODE>(Plugins::VideoEncodeBitrateMode::SQR);
    rawEncFormat_->SetData(Tag::VIDEO_ENCODER_ENABLE_B_FRAME, movieSettings_.isBFrameEnabled);
}

Status RecorderEngine::ConfigRawEncoderFilter()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigRawEncoderFilter is called");
    CHECK_RETURN_RET(!rawEncoderFilter_, Status::OK);
    rawEncoderFilter_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
    rawEncoderFilter_->SetClusterId(DEFAULT_RAW_CLUSTER_ID);
    rawEncoderFilter_->SetCodecFormat(rawEncFormat_);
    rawEncoderFilter_->Init(recorderEventReceiver_, recorderCallback_);
    Status ret = rawEncoderFilter_->Configure(rawEncFormat_);
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "rawEncoderFilter Configure fail");
    return ret;
}

Status RecorderEngine::AddPreySource()
{
    MEDIA_INFO_LOG("RecorderEngine::AddPreySource is called");
    Status ret = Status::OK;
    // create prey cache filter
    CHECK_EXECUTE(preyCacheFilter_ == nullptr, preyCacheFilter_ = std::make_shared<CinematicVideoCacheFilter>(
        "PreyCacheFilter", CFilterType::CINEMATIC_VIDEO_CACHE));
    CHECK_RETURN_RET_ELOG(preyCacheFilter_ == nullptr, Status::ERROR_NULL_POINTER,
        "RecorderEngine::create PreyCacheFilter failed");
    // create prey encoder filter
    CHECK_EXECUTE(preyEncoderFilter_ == nullptr,
        preyEncoderFilter_ = std::make_shared<VideoEncoderFilter>("PreyEncoderFilter", CFilterType::VIDEO_ENC));
    CHECK_RETURN_RET_ELOG(preyEncoderFilter_ == nullptr, Status::ERROR_NULL_POINTER,
        "RecorderEngine::create PreyEncoderFilter failed");
    // add prey source into pipeline
    ret = pipeline_->AddHeadFilters({preyCacheFilter_});
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "Add PreyEncoderFilter to pipeline fail");
    return ret;
}

Status RecorderEngine::PreparePreySource()
{
    MEDIA_INFO_LOG("RecorderEngine::PreparePreySource is called");
    Status ret = Status::OK;

    // config prey encoder
    ConfigPreyEncFormat();
    ret = ConfigPreyEncoderFilter();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "ConfigPreyEncoderFilter failed");

    ret = ConfigPreyCacheFilter();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "ConfigPreyCacheFilter failed");

    MEDIA_INFO_LOG("PreparePreySource success.");
    OnStateChanged(StateId::RECORDING_SETTING);
    return ret;
}

void RecorderEngine::ConfigPreyEncFormat()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigPreyEncFormat is called");
    CHECK_RETURN(!preyEncoderFilter_);
    // prey stream encode config
    preyEncFormat_->Set<Tag::VIDEO_WIDTH>(DEFAULT_PREY_FRAME_WIDTH); // 960
    preyEncFormat_->Set<Tag::VIDEO_HEIGHT>(DEFAULT_PREY_FRAME_HEIGHT); // 540
    preyEncFormat_->Set<Tag::VIDEO_FRAME_RATE>(DEFAULT_MOVIE_FRAME_RATE); // 30

    preyEncFormat_->Set<Tag::MEDIA_TYPE>(Plugins::MediaType::AUXILIARY); // 6
    preyEncFormat_->Set<Tag::TRACK_REFERENCE_TYPE>(DEFAULT_PREY_TRACK_REFERENCE_TYPE); // auxl
    preyEncFormat_->Set<Tag::TRACK_DESCRIPTION>(DEFAULT_PREY_TRACK_DESCRIPTION); // com.openharmony.moviemode.prey

    // encode meta
    preyEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::VIDEO_HEVC); // video/hevc
    preyEncFormat_->Set<Tag::VIDEO_H265_PROFILE>(Plugins::HEVCProfile::HEVC_PROFILE_MAIN_10); // default is 10bit
    preyEncFormat_->Set<Tag::VIDEO_ENCODE_BITRATE_MODE>(Plugins::VideoEncodeBitrateMode::CQ); // 2

    preyEncFormat_->Set<Tag::VIDEO_ENCODER_QP_MIN>(DEFAULT_PREY_FRAME_QP_MIN);
    preyEncFormat_->Set<Tag::VIDEO_ENCODER_QP_MAX>(DEFAULT_PREY_FRAME_QP_MAX);
}

Status RecorderEngine::ConfigPreyEncoderFilter()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigPreyEncoderFilter is called");
    CHECK_RETURN_RET(!preyEncoderFilter_, Status::OK);
    preyEncoderFilter_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
    preyEncoderFilter_->SetClusterId(DEFAULT_PREY_CLUSTER_ID);
    preyEncoderFilter_->SetCodecFormat(preyEncFormat_);
    preyEncoderFilter_->Init(recorderEventReceiver_, recorderCallback_);
    Status ret = preyEncoderFilter_->Configure(preyEncFormat_);
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "preyEncoderFilter Configure fail");
    return ret;
}

Status RecorderEngine::ConfigPreyCacheFilter()
{
    MEDIA_INFO_LOG("called");
    CHECK_RETURN_RET(!preyCacheFilter_, Status::OK);
    preyCacheFilter_->SetClusterId(DEFAULT_PREY_CLUSTER_ID);
    preyCacheFilter_->Init(recorderEventReceiver_, recorderCallback_);
    preyCacheFilter_->Configure(preyEncFormat_);
    return Status::OK;
}

Status RecorderEngine::AddDepthSource()
{
    MEDIA_INFO_LOG("RecorderEngine::AddDepthSource is called");
    Status ret = Status::OK;
    // create depth cache filter
    CHECK_EXECUTE(depthCacheFilter_ == nullptr, depthCacheFilter_ = std::make_shared<CinematicVideoCacheFilter>(
        "DepthCacheFilter", CFilterType::CINEMATIC_VIDEO_CACHE));
    CHECK_RETURN_RET_ELOG(depthCacheFilter_ == nullptr, Status::ERROR_NULL_POINTER,
        "RecorderEngine::create DepthCacheFilter failed");

    // create depth encoder filter
    CHECK_EXECUTE(depthEncoderFilter_ == nullptr,
        depthEncoderFilter_ = std::make_shared<VideoEncoderFilter>("DepthEncoderFilter", CFilterType::VIDEO_ENC));
    CHECK_RETURN_RET_ELOG(depthEncoderFilter_ == nullptr, Status::ERROR_NULL_POINTER,
        "RecorderEngine::create DepthEncoderFilter failed");
    // add depth source into pipeline
    ret = pipeline_->AddHeadFilters({depthCacheFilter_});
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "Add DepthEncoderFilter to pipeline fail");
    return ret;
}

Status RecorderEngine::PrepareDepthSource()
{
    MEDIA_INFO_LOG("RecorderEngine::PrepareDepthSource is called");
    Status ret = Status::OK;
    // config movie source
    ConfigDepthEncFormat();
    ret = ConfigDepthEncoderFilter();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "ConfigDepthEncoderFilter failed");

    ret = ConfigDepthCacheFilter();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "ConfigDepthCacheFilter failed");

    MEDIA_INFO_LOG("PrepareDepthSource success.");
    OnStateChanged(StateId::RECORDING_SETTING);
    return ret;
}

void RecorderEngine::ConfigDepthEncFormat()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigDepthEncFormat is called");
    CHECK_RETURN(!depthEncoderFilter_);
    // movie stream encode config
    depthEncFormat_->Set<Tag::VIDEO_WIDTH>(DEFAULT_DEPTH_FRAME_WIDTH);
    depthEncFormat_->Set<Tag::VIDEO_HEIGHT>(DEFAULT_DEPTH_FRAME_HEIGHT);
    depthEncFormat_->Set<Tag::VIDEO_FRAME_RATE>(DEFAULT_MOVIE_FRAME_RATE);

    depthEncFormat_->Set<Tag::MEDIA_TYPE>(Plugins::MediaType::AUXILIARY);
    depthEncFormat_->Set<Tag::TRACK_REFERENCE_TYPE>(DEFAULT_DEPTH_TRACK_REFERENCE_TYPE);
    depthEncFormat_->Set<Tag::VIDEO_H265_PROFILE>(Plugins::HEVCProfile::HEVC_PROFILE_MAIN);
    depthEncFormat_->Set<Tag::TRACK_DESCRIPTION>(DEFAULT_DEPTH_TRACK_DESCRIPTION);

    depthEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::VIDEO_HEVC);
    depthEncFormat_->Set<Tag::VIDEO_ENCODE_BITRATE_MODE>(Plugins::VideoEncodeBitrateMode::CQ);
    depthEncFormat_->Set<Tag::VIDEO_ENCODER_QP_MIN>(DEFAULT_DEPTH_FRAME_QP_MIN);
    depthEncFormat_->Set<Tag::VIDEO_ENCODER_QP_MAX>(DEFAULT_DEPTH_FRAME_QP_MAX);
}

Status RecorderEngine::ConfigDepthEncoderFilter()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigDepthEncoderFilter is called");
    CHECK_RETURN_RET(!depthEncoderFilter_, Status::OK);
    depthEncoderFilter_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
    depthEncoderFilter_->SetClusterId(DEFAULT_DEPTH_CLUSTER_ID);
    depthEncoderFilter_->SetCodecFormat(depthEncFormat_);
    depthEncoderFilter_->EnableVirtualAperture(isVirtualApertureEnabled_);
    depthEncoderFilter_->Init(recorderEventReceiver_, recorderCallback_);
    Status ret = depthEncoderFilter_->Configure(depthEncFormat_);
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "depthEncoderFilter Configure fail");
    return ret;
}

Status RecorderEngine::ConfigDepthCacheFilter()
{
    MEDIA_INFO_LOG("called");
    CHECK_RETURN_RET(!depthCacheFilter_, Status::OK);
    depthCacheFilter_->SetClusterId(DEFAULT_DEPTH_CLUSTER_ID);
    depthCacheFilter_->Init(recorderEventReceiver_, recorderCallback_);
    depthCacheFilter_->Configure(depthEncFormat_);
    return Status::OK;
}

Status RecorderEngine::AddMetaSource()
{
    MEDIA_INFO_LOG("RecorderEngine::AddMetaSource is called");
    Status ret = Status::OK;
    // create video encoder filter as metadata source
    CHECK_EXECUTE(metaDataFilter_ == nullptr,
        metaDataFilter_ = std::make_shared<MetaDataFilter>("MetaDataFilter", CFilterType::TIMED_METADATA));
    CHECK_RETURN_RET_ELOG(
        metaDataFilter_ == nullptr, Status::ERROR_NULL_POINTER, "RecorderEngine::create MetaDataFilter failed");
    // add meta source into pipeline
    ret = pipeline_->AddHeadFilters({metaDataFilter_});
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "Add MetaEncoderFilter to pipeline fail");
    return ret;
}

Status RecorderEngine::PrepareMetaSource()
{
    MEDIA_INFO_LOG("RecorderEngine::PrepareMetaSource is called");
    Status ret = Status::OK;

    // config Metadata source
    ConfigMetaDataFormat();
    ret = ConfigMetaDataFilter();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "ConfigMetaDataFilter failed");

    MEDIA_INFO_LOG("PrepareMetaSource success.");
    OnStateChanged(StateId::RECORDING_SETTING);
    return ret;
}

void RecorderEngine::ConfigMetaDataFormat()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigMetaEncFormat is called");
    CHECK_RETURN(!metaDataFilter_);
    metaDataFormat_->Set<Tag::MIME_TYPE>(DEFAULT_META_MIME_TYPE);
    metaDataFormat_->Set<Tag::TIMED_METADATA_KEY>(DEFAULT_META_TIMED_KEY);
    metaDataFormat_->Set<Tag::TIMED_METADATA_SRC_TRACK_MIME>(DEFAULT_META_SOURCE_TRACK_MIME);
}

Status RecorderEngine::ConfigMetaDataFilter()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigMetaDataFilter is called");
    CHECK_RETURN_RET(!metaDataFilter_, Status::OK);
    metaDataFilter_->SetClusterId(DEFAULT_META_CLUSTER_ID);
    metaDataFilter_->SetCodecFormat(metaDataFormat_);
    metaDataFilter_->Init(recorderEventReceiver_, recorderCallback_);
    Status ret = metaDataFilter_->Configure(metaDataFormat_);
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "metaDataFilter Configure fail");
    return ret;
}

Status RecorderEngine::AddRawDebugSource()
{
    MEDIA_INFO_LOG("RecorderEngine::AddRawDebugSource is called");
    Status ret = Status::OK;
    // create metadata filter as raw debug source
    CHECK_EXECUTE(rawDebugFilter_ == nullptr,
        rawDebugFilter_ = std::make_shared<MetaDataFilter>("RawDebugFilter", CFilterType::TIMED_METADATA));
    CHECK_RETURN_RET_ELOG(
        rawDebugFilter_ == nullptr, Status::ERROR_NULL_POINTER, "RecorderEngine::create RawDebugFilter failed");
    // add meta source into pipeline
    ret = pipeline_->AddHeadFilters({rawDebugFilter_});
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "Add RawDebugFilter to pipeline fail");
    return ret;
}

Status RecorderEngine::PrepareRawDebugSource()
{
    MEDIA_INFO_LOG("RecorderEngine::PrepareRawDebugSource is called");
    Status ret = Status::OK;

    // config raw debug source
    ConfigRawDebugFormat();
    ret = ConfigRawDebugFilter();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "ConfigRawDebugFilter failed");

    MEDIA_INFO_LOG("PrepareRawDebugSource success.");
    OnStateChanged(StateId::RECORDING_SETTING);
    return ret;
}

void RecorderEngine::ConfigRawDebugFormat()
{
    MEDIA_INFO_LOG("called");
    CHECK_RETURN(!rawDebugFilter_);
    rawDebugFormat_->Set<Tag::MIME_TYPE>(DEFAULT_DEBUG_MIME_TYPE);
    rawDebugFormat_->Set<Tag::TIMED_METADATA_KEY>(DEFAULT_DEBUG_TIMED_KEY);
    rawDebugFormat_->Set<Tag::TIMED_METADATA_SRC_TRACK_MIME>(Plugins::MimeType::VIDEO_HEVC);
}

Status RecorderEngine::ConfigRawDebugFilter()
{
    MEDIA_INFO_LOG("called");
    CHECK_RETURN_RET(!rawDebugFilter_, Status::OK);
    rawDebugFilter_->SetClusterId(DEFAULT_RAW_CLUSTER_ID);
    rawDebugFilter_->SetCodecFormat(rawDebugFormat_);
    rawDebugFilter_->Init(recorderEventReceiver_, recorderCallback_);
    Status ret = rawDebugFilter_->Configure(rawDebugFormat_);
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "RawDebugFilter Configure fail");
    return ret;
}


Status RecorderEngine::AddMovieDebugSource()
{
    MEDIA_INFO_LOG("called");
    Status ret = Status::OK;
    // create metadata filter as movie debug source
    CHECK_EXECUTE(movieDebugFilter_ == nullptr,
        movieDebugFilter_ = std::make_shared<MetaDataFilter>("MovieDebugFilter", CFilterType::TIMED_METADATA));
    CHECK_RETURN_RET_ELOG(
        movieDebugFilter_ == nullptr, Status::ERROR_NULL_POINTER, "RecorderEngine::create MovieDebugFilter failed");
    // add meta source into pipeline
    ret = pipeline_->AddHeadFilters({movieDebugFilter_});
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "Add MovieDebugFilter to pipeline fail");
    return ret;
}

Status RecorderEngine::PrepareMovieDebugSource()
{
    MEDIA_INFO_LOG("RecorderEngine::PrepareMovieDebugSource is called");
    Status ret = Status::OK;

    // config movie debug source
    ConfigMovieDebugFormat();
    ret = ConfigMovieDebugFilter();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "ConfigMovieDebugFilter failed");

    MEDIA_INFO_LOG("PrepareMovieDebugSource success.");
    OnStateChanged(StateId::RECORDING_SETTING);
    return ret;
}

void RecorderEngine::ConfigMovieDebugFormat()
{
    MEDIA_INFO_LOG("called");
    CHECK_RETURN(!movieDebugFilter_);
    movieDebugFormat_->Set<Tag::MIME_TYPE>(DEFAULT_DEBUG_MIME_TYPE);
    movieDebugFormat_->Set<Tag::TIMED_METADATA_KEY>(DEFAULT_DEBUG_TIMED_KEY);
    switch (movieSettings_.videoCodecType) {
        case EngineVideoCodecType::VIDEO_ENCODE_TYPE_AVC:
            movieDebugFormat_->Set<Tag::TIMED_METADATA_SRC_TRACK_MIME>(Plugins::MimeType::VIDEO_AVC);
            break;
        case EngineVideoCodecType::VIDEO_ENCODE_TYPE_HEVC:
            movieDebugFormat_->Set<Tag::TIMED_METADATA_SRC_TRACK_MIME>(Plugins::MimeType::VIDEO_HEVC);
            break;
        default:
            break;
    }
}

Status RecorderEngine::ConfigMovieDebugFilter()
{
    MEDIA_INFO_LOG("called");
    CHECK_RETURN_RET(!movieDebugFilter_, Status::OK);
    movieDebugFilter_->SetClusterId(DEFAULT_MOVIE_CLUSTER_ID);
    movieDebugFilter_->SetCodecFormat(movieDebugFormat_);
    movieDebugFilter_->Init(recorderEventReceiver_, recorderCallback_);
    Status ret = movieDebugFilter_->Configure(movieDebugFormat_);
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "MovieDebugFilter Configure fail");
    return ret;
}


void RecorderEngine::OnStateChanged(StateId state)
{
    curState_ = state;
}

Status RecorderEngine::PrepareSurface()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("RecorderEngine::PrepareSurface is called");
    Status ret = Status::OK;
    SetMovieSurface();
    SetMovieDebugSurface();
    SetRawSurface();
    SetPreySurface();
    SetDepthSurface();
    SetMetaSurface();
    SetRawDebugSurface();
    SetImageEffectSurface();
    return ret;
}

void RecorderEngine::SetMovieSurface()
{
    MEDIA_INFO_LOG("SetMovieSurface is called.");
    CHECK_EXECUTE(movieEncoderFilter_, movieSurface_ = movieEncoderFilter_->GetInputSurface());
    CHECK_RETURN_ELOG(movieSurface_ == nullptr, "movieSurface_ is null!");
    MEDIA_INFO_LOG("movieSurface_ unique Id: %{public}" PRIu64, movieSurface_->GetUniqueId());
}

void RecorderEngine::SetRawSurface()
{
    MEDIA_INFO_LOG("SetRawSurface is called.");
    CHECK_EXECUTE(rawEncoderFilter_, rawSurface_ = rawEncoderFilter_->GetInputSurface());
    CHECK_RETURN_ELOG(rawSurface_ == nullptr, "rawSurface_ is null!");
    MEDIA_INFO_LOG("rawSurface_ unique Id: %{public}" PRIu64, rawSurface_->GetUniqueId());
}

void RecorderEngine::SetPreySurface()
{
    MEDIA_INFO_LOG("SetPreySurface is called.");
    CHECK_EXECUTE(preyCacheFilter_, preySurface_ = preyCacheFilter_->GetInputSurface());
    CHECK_RETURN_ELOG(preySurface_ == nullptr, "preySurface_ is null!");
    MEDIA_INFO_LOG("preySurface_ unique Id: %{public}" PRIu64, preySurface_->GetUniqueId());
}

void RecorderEngine::SetDepthSurface()
{
    MEDIA_INFO_LOG("SetDepthSurface is called.");
    CHECK_EXECUTE(depthCacheFilter_, depthSurface_ = depthCacheFilter_->GetInputSurface());
    CHECK_RETURN_ELOG(depthSurface_ == nullptr, "depthSurface_ is null!");
    MEDIA_INFO_LOG("depthSurface_ unique Id: %{public}" PRIu64, depthSurface_->GetUniqueId());
}

void RecorderEngine::SetMetaSurface()
{
    MEDIA_INFO_LOG("SetMetaSurface is called.");
    CHECK_EXECUTE(metaDataFilter_, metaSurface_ = metaDataFilter_->GetInputMetaSurface());
    CHECK_RETURN_ELOG(metaSurface_ == nullptr, "metaSurface_ is null!");
    MEDIA_INFO_LOG("metaSurface_ unique Id: %{public}" PRIu64, metaSurface_->GetUniqueId());
}

void RecorderEngine::SetMovieDebugSurface()
{
    MEDIA_INFO_LOG("called.");
    CHECK_EXECUTE(movieDebugFilter_, movieDebugSurface_ = movieDebugFilter_->GetInputMetaSurface());
    CHECK_RETURN_ELOG(movieDebugSurface_ == nullptr, "movieDebugSurface_ is null!");
    MEDIA_INFO_LOG("movieDebugSurface_ unique Id: %{public}" PRIu64, movieDebugSurface_->GetUniqueId());
}

void RecorderEngine::SetRawDebugSurface()
{
    MEDIA_INFO_LOG("called.");
    CHECK_EXECUTE(rawDebugFilter_, rawDebugSurface_ = rawDebugFilter_->GetInputMetaSurface());
    CHECK_RETURN_ELOG(rawDebugSurface_ == nullptr, "rawDebugSurface_ is null!");
    MEDIA_INFO_LOG("rawDebugSurface_ unique Id: %{public}" PRIu64, rawDebugSurface_->GetUniqueId());
}

void RecorderEngine::SetImageEffectSurface()
{
    MEDIA_INFO_LOG("SetImageEffectSurface is called.");
    CHECK_EXECUTE(imageEffectFilter_, imageEffectSurface_ = imageEffectFilter_->GetInputSurface());
    CHECK_RETURN_ELOG(imageEffectSurface_ == nullptr, "imageEffectSurface_ is null!");
    MEDIA_INFO_LOG("imageEffectSurface_ unique Id: %{public}" PRIu64, imageEffectSurface_->GetUniqueId());
}

Status RecorderEngine::PrepareMovieMuxer()
{
    MEDIA_INFO_LOG("RecorderEngine::PrepareMovieMuxer is called");
    Status ret = Status::OK;
    CHECK_RETURN_RET(movieMuxerFilter_ != nullptr, ret);
    movieMuxerFilter_ = std::make_shared<MuxerFilter>("MovieMuxerFilter", CFilterType::MUXER);
    CHECK_RETURN_RET_ELOG(
        movieMuxerFilter_ == nullptr, Status::ERROR_NULL_POINTER, "RecorderEngine::create MovieMuxerFilter failed");

    ConfigMovieMuxerFormat();
    ret = ConfigMovieMuxerFilter();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "ConfigMovieMuxerFilter failed");

    MEDIA_INFO_LOG("PrepareMovieMuxer success.");
    OnStateChanged(StateId::RECORDING_SETTING);
    return ret;
}

Status RecorderEngine::ConfigMovieMuxerFilter()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigMovieMuxerFilter is called");
    Status ret = Status::OK;
    CHECK_RETURN_RET(!movieMuxerFilter_, ret);
    ret = CreateMovieFileMediaLibrary();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "CreateMovieVideoMediaLibrary failed");
    movieMuxerFilter_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
    movieMuxerFilter_->SetClusterId(DEFAULT_MOVIE_CLUSTER_ID);
    MEDIA_INFO_LOG("RecorderEngine::ConfigRawMuxerFilter movieVideoFd_: %{public}d", movieVideoFd_);
    movieMuxerFilter_->SetOutputParameter(appUid_, appPid_, movieVideoFd_, DEFAULT_MUXER_OUTPUT_FORMAT);
    movieMuxerFilter_->SetParameter(movieMuxerFormat_);
    movieMuxerFilter_->Init(recorderEventReceiver_, recorderCallback_);
    CloseMovieFd();
    return ret;
}

Status RecorderEngine::PrepareRawMuxer()
{
    MEDIA_INFO_LOG("RecorderEngine::PrepareRawMuxer is called");
    Status ret = Status::OK;
    CHECK_RETURN_RET(rawMuxerFilter_.Get(), ret);
    rawMuxerFilter_.Set(std::make_shared<MuxerFilter>("RawMuxerFilter", CFilterType::MUXER));
    CHECK_RETURN_RET_ELOG(
        !rawMuxerFilter_.Get(), Status::ERROR_NULL_POINTER, "RecorderEngine::create RawMuxerFilter failed");

    ConfigRawMuxerFormat();
    ret = ConfigRawMuxerFilter();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "ConfigRawMuxerFilter failed");

    MEDIA_INFO_LOG("PrepareRawMuxer success.");
    OnStateChanged(StateId::RECORDING_SETTING);
    return ret;
}

Status RecorderEngine::ConfigRawMuxerFilter()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigRawMuxerFilter is called");
    auto rawMuxerFilter = rawMuxerFilter_.Get();
    CHECK_RETURN_RET(!rawMuxerFilter, Status::OK);
    rawMuxerFilter->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
    rawMuxerFilter->SetClusterId(DEFAULT_RAW_CLUSTER_ID);
    MEDIA_INFO_LOG("RecorderEngine::ConfigRawMuxerFilter rawVideoFd_: %{public}d", rawVideoFd_);
    rawMuxerFilter->SetOutputParameter(appUid_, appPid_, rawVideoFd_, DEFAULT_MUXER_OUTPUT_FORMAT);
    rawMuxerFilter->SetParameter(rawMuxerFormat_);
    rawMuxerFilter->Init(recorderEventReceiver_, recorderCallback_);
    CloseRawFd();
    return Status::OK;
}

void RecorderEngine::ConfigMovieMuxerFormat()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigMovieMuxerFormat is called");
    movieMuxerFormat_->Set<Tag::MEDIA_CREATION_TIME>("now");
    movieMuxerFormat_->Set<Tag::VIDEO_ROTATION>(rotation_);
    movieMuxerFormat_->SetData(TIMED_META_TRACK_TAG, DEFAULT_USE_TIMED_META_TRACK);
    if (movieSettings_.isHasLocation) {
        MEDIA_DEBUG_LOG("set location info");
        movieMuxerFormat_->Set<Tag::MEDIA_LATITUDE>(movieSettings_.location.latitude);
        movieMuxerFormat_->Set<Tag::MEDIA_LONGITUDE>(movieSettings_.location.longitude);
    }
}

Status RecorderEngine::CreateMovieFileMediaLibrary()
{
    MEDIA_INFO_LOG("RecorderEngine::CreateMovieFileMediaLibrary is called");
    constexpr int32_t movieFileShotType = 4;
    auto photoAssetProxy = PhotoAssetProxy::GetPhotoAssetProxy(
        movieFileShotType, IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingTokenID(), 2);
    CHECK_RETURN_RET_ELOG(photoAssetProxy == nullptr, Status::ERROR_UNKNOWN,
        "RecorderEngine::CreateMovieFileMediaLibrary get photoAssetProxy fail");
    sptr<CameraServerPhotoProxy> cameraPhotoProxy = new CameraServerPhotoProxy();
    cameraPhotoProxy->SetDisplayName(CreateVideoDisplayName());
    cameraPhotoProxy->SetIsVideo(true);
    photoAssetProxy->AddPhotoProxy((sptr<PhotoProxy>&)cameraPhotoProxy);
    cameraPhotoProxy_ = cameraPhotoProxy;
    movieFilePhotoAssetProxy_ = photoAssetProxy;
    movieFileUri_ = photoAssetProxy->GetPhotoAssetUri();
    rawVideoFd_ = photoAssetProxy->GetVideoFd(static_cast<VideoType>(RAW_VIDEO_TYPE));
    movieVideoFd_ = photoAssetProxy->GetVideoFd(static_cast<VideoType>(MOVIE_VIDEO_TYPE));
    MEDIA_INFO_LOG("RecorderEngine::CreateMovieVideoMediaLibrary, movieFileShotType: %{public}d, movieFileUri_: "
                   "%{public}s, rawVideoFd_: %{public}d, movieFileFd_: %{public}d",
                   movieFileShotType, movieFileUri_.c_str(), rawVideoFd_, movieVideoFd_);
    CHECK_RETURN_RET_ELOG(movieVideoFd_ == -1 || rawVideoFd_ == -1, Status::ERROR_INVALID_DATA,
                          "GetVideoFd failed, fd is invalid");
    return Status::OK;
}

void RecorderEngine::ConfigRawMuxerFormat()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigRawMuxerFormat is called");
    rawMuxerFormat_->Set<Tag::MEDIA_CREATION_TIME>("now");
    rawMuxerFormat_->Set<Tag::VIDEO_ROTATION>(rotation_);
    rawMuxerFormat_->SetData(TIMED_META_TRACK_TAG, DEFAULT_USE_TIMED_META_TRACK);
    if (movieSettings_.isHasLocation) {
        MEDIA_DEBUG_LOG("set location info");
        rawMuxerFormat_->Set<Tag::MEDIA_LATITUDE>(movieSettings_.location.latitude);
        rawMuxerFormat_->Set<Tag::MEDIA_LONGITUDE>(movieSettings_.location.longitude);
    }
}

Status RecorderEngine::PrepareAudioProcess()
{
    MEDIA_INFO_LOG("RecorderEngine::PrepareAudioProcess is called");
    Status ret = Status::OK;
    // create audio process filter, always create a new one to free the old one
    audioProcessFilter_ = std::make_shared<AudioProcessFilter>("AudioProcessFilter", CFilterType::AUDIO_PROCESS);
    CHECK_RETURN_RET_ELOG(audioProcessFilter_ == nullptr, Status::ERROR_NULL_POINTER,
        "RecorderEngine::create AudioProcessFilter failed");

    ret = ConfigAudioProcessFilter();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "ConfigAudioProcessFilter failed");

    MEDIA_INFO_LOG("PrepareAudioProcess success.");
    OnStateChanged(StateId::RECORDING_SETTING);
    return ret;
}

Status RecorderEngine::ConfigAudioProcessFilter()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigAudioProcessFilter is called");
    CHECK_RETURN_RET(!audioProcessFilter_, Status::OK);
    AudioCapturerOptions inputOptions;
    CHECK_EXECUTE(audioCaptureFilter_, audioCaptureFilter_->GetAudioCaptureOptions(inputOptions));
    audioProcessFilter_->SetClusterId(DEFAULT_ALL_CLUSTER_ID);
    audioProcessFilter_->SetParameter(audioCaptureFormat_);
    audioProcessFilter_->SetAudioCaptureOptions(inputOptions);
    audioProcessFilter_->Init(recorderEventReceiver_, recorderCallback_);
    Status ret = audioProcessFilter_->InitAudioProcessConfig();
    if (ret != Status::OK) {
        MEDIA_ERR_LOG("InitAudioProcessConfig failed, ret:%{public}d", ret);
        audioProcessFilter_ = nullptr;
        return ret;
    }
    return ret;
}

Status RecorderEngine::PrepareAudioEncoder()
{
    MEDIA_INFO_LOG("RecorderEngine::PrepareAudioEncoder is called");
    Status ret = Status::OK;
    // create audio encoder filter, always create a new one to free the old one
    audioEncoderFilter_ = std::make_shared<AudioEncoderFilter>("AudioEncoderFilter", CFilterType::AUDIO_ENC);
    CHECK_RETURN_RET_ELOG(audioEncoderFilter_ == nullptr, Status::ERROR_NULL_POINTER,
        "RecorderEngine::create AudioEncoderFilter failed");

    ConfigAudioEncFormat();
    // config movie source
    ret = ConfigAudioEncoderFilter();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "ConfigAudioEncoderFilter failed");

    MEDIA_INFO_LOG("PrepareAudioEncoder success.");
    OnStateChanged(StateId::RECORDING_SETTING);
    return ret;
}

void RecorderEngine::ConfigAudioEncFormat()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigAudioEncFormat is called");
    CHECK_RETURN(!audioEncoderFilter_);
    int32_t audioChannelNum = AudioChannel::STEREO;
    if (isAudioPostEditEnabled_ && audioProcessFilter_) {
        AudioStreamInfo streamInfo;
        audioProcessFilter_->GetOutputAudioStreamInfo(streamInfo);
        audioChannelNum = streamInfo.channels > 0 ? streamInfo.channels : AudioChannel::STEREO;
    }
    MEDIA_INFO_LOG("ConfigAudioEncFormat audioChannelNum:%{public}d", audioChannelNum);
    // encode config, deafult mime type is Advanced Audio Coding Low Complexity (AAC-LC)
    audioEncFormat_->Set<Tag::MIME_TYPE>(DEFAULT_AUDIO_MIME_TYPE);
    audioEncFormat_->Set<Tag::AUDIO_AAC_PROFILE>(DEFAULT_AUDIO_AAC_PROFILE);
    audioEncFormat_->Set<Tag::AUDIO_SAMPLE_FORMAT>(DEFAULT_AUDIO_SAMPLE_FORMAT);
    audioEncFormat_->Set<Tag::AUDIO_SAMPLE_RATE>(DEFAULT_AUDIO_SAMPLE_RATE);
    audioEncFormat_->Set<Tag::AUDIO_CHANNEL_COUNT>(audioChannelNum);
    audioEncFormat_->Set<Tag::MEDIA_BITRATE>(DEFAULT_AUDIO_BIT_RATE);
    // caller info
    audioEncFormat_->Set<Tag::APP_TOKEN_ID>(appTokenId_);
    audioEncFormat_->Set<Tag::APP_UID>(appUid_);
    audioEncFormat_->Set<Tag::APP_PID>(appPid_);
    audioEncFormat_->Set<Tag::APP_FULL_TOKEN_ID>(appFullTokenId_);
}

Status RecorderEngine::ConfigAudioEncoderFilter()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigAudioEncoderFilter is called");
    CHECK_RETURN_RET(!audioEncoderFilter_, Status::OK);
    audioEncoderFilter_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
    audioEncoderFilter_->SetCodecFormat(audioEncFormat_);
    audioEncoderFilter_->SetClusterId(DEFAULT_ALL_CLUSTER_ID);
    audioEncoderFilter_->Init(recorderEventReceiver_, recorderCallback_);
    Status ret = audioEncoderFilter_->Configure(audioEncFormat_);
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "audioEncoderFilter Configure fail");
    return ret;
}

Status RecorderEngine::PrepareRawAudioEncoder()
{
    MEDIA_INFO_LOG("RecorderEngine::PrepareRawAudioEncoder is called");
    Status ret = Status::OK;
    // create raw audio encoder filter, always create a new one to free the old one
    rawAudioEncoderFilter_ = std::make_shared<AudioEncoderFilter>("RawAudioEncoderFilter", CFilterType::AUDIO_ENC);
    CHECK_RETURN_RET_ELOG(rawAudioEncoderFilter_ == nullptr, Status::ERROR_NULL_POINTER,
        "RecorderEngine::create RawAudioEncoderFilter failed");

    ConfigRawAudioEncFormat();
    // config raw audio encoder filter
    ret = ConfigRawAudioEncoderFilter();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "ConfigRawAudioEncoderFilter failed");

    MEDIA_INFO_LOG("PrepareRawAudioEncoder success.");
    OnStateChanged(StateId::RECORDING_SETTING);
    return ret;
}

void RecorderEngine::ConfigRawAudioEncFormat()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigRawAudioEncFormat is called");
    CHECK_RETURN(!rawAudioEncoderFilter_);
    int32_t audioChannelNum = isAudioPostEditEnabled_ ? GetMicNum() : AudioChannel::STEREO;
    MEDIA_INFO_LOG("ConfigRawAudioEncFormat audioChannelNum:%{public}d", audioChannelNum);
    // aux audio track meta
    rawAudioEncFormat_->Set<Tag::MEDIA_TYPE>(Plugins::MediaType::AUXILIARY); // 6
    rawAudioEncFormat_->Set<Tag::TRACK_REFERENCE_TYPE>(DEFAULT_AUDIO_TRACK_REFERENCE_TYPE);
    rawAudioEncFormat_->Set<Tag::TRACK_DESCRIPTION>(DEFAULT_AUDIO_TRACK_DESCRIPTION);
    // encode config, deafult mime type is Advanced Audio Coding Low Complexity (AAC-LC)
    rawAudioEncFormat_->Set<Tag::MIME_TYPE>(DEFAULT_AUDIO_MIME_TYPE);
    rawAudioEncFormat_->Set<Tag::AUDIO_AAC_PROFILE>(DEFAULT_AUDIO_AAC_PROFILE);
    rawAudioEncFormat_->Set<Tag::AUDIO_SAMPLE_FORMAT>(DEFAULT_AUDIO_SAMPLE_FORMAT);
    rawAudioEncFormat_->Set<Tag::AUDIO_SAMPLE_RATE>(DEFAULT_AUDIO_SAMPLE_RATE);
    rawAudioEncFormat_->Set<Tag::AUDIO_CHANNEL_COUNT>(audioChannelNum);
    rawAudioEncFormat_->Set<Tag::MEDIA_BITRATE>(DEFAULT_RAW_AUDIO_BIT_RATE);
    // caller info
    rawAudioEncFormat_->Set<Tag::APP_TOKEN_ID>(appTokenId_);
    rawAudioEncFormat_->Set<Tag::APP_UID>(appUid_);
    rawAudioEncFormat_->Set<Tag::APP_PID>(appPid_);
    rawAudioEncFormat_->Set<Tag::APP_FULL_TOKEN_ID>(appFullTokenId_);
}

Status RecorderEngine::ConfigRawAudioEncoderFilter()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigRawAudioEncoderFilter is called");
    CHECK_RETURN_RET(!rawAudioEncoderFilter_, Status::OK);
    rawAudioEncoderFilter_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
    rawAudioEncoderFilter_->SetCodecFormat(rawAudioEncFormat_);
    rawAudioEncoderFilter_->SetClusterId(DEFAULT_RAW_CLUSTER_ID);
    rawAudioEncoderFilter_->Init(recorderEventReceiver_, recorderCallback_);
    Status ret = rawAudioEncoderFilter_->Configure(rawAudioEncFormat_);
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "RawAudioEncFormat Configure fail");
    return ret;
}

Status RecorderEngine::PrepareAudioFork()
{
    MEDIA_INFO_LOG("RecorderEngine::PrepareAudioFork is called");
    Status ret = Status::OK;
    // create audio fork filter, always create a new one to free the old one
    audioForkFilter_ = std::make_shared<AudioForkFilter>("AudioForkFilter", CFilterType::AUDIO_FORK);
    CHECK_RETURN_RET_ELOG(audioForkFilter_ == nullptr, Status::ERROR_NULL_POINTER,
        "RecorderEngine::create AudioForkFilter failed");

    ret = ConfigAudioForkFilter();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "ConfigAudioForkFilter failed");

    MEDIA_INFO_LOG("PrepareAudioFork success.");
    OnStateChanged(StateId::RECORDING_SETTING);
    return ret;
}

Status RecorderEngine::ConfigAudioForkFilter()
{
    MEDIA_INFO_LOG("RecorderEngine::ConfigAudioForkFilter is called");
    CHECK_RETURN_RET(!audioForkFilter_, Status::OK);
    audioForkFilter_->SetClusterId(DEFAULT_ALL_CLUSTER_ID);
    audioForkFilter_->Init(recorderEventReceiver_, recorderCallback_);
    return Status::OK;
}

void RecorderEngine::CloseMovieFd()
{
    MEDIA_DEBUG_LOG("RecorderEngine::CloseMovieFd is called, fd is %{public}d", movieVideoFd_);
    if (movieVideoFd_ >= 0) {
        (void)::close(movieVideoFd_);
        movieVideoFd_ = -1;
    }
}

void RecorderEngine::CloseRawFd()
{
    MEDIA_DEBUG_LOG("RecorderEngine::CloseRawFd is called, fd is %{public}d", rawVideoFd_);
    if (rawVideoFd_ >= 0) {
        (void)::close(rawVideoFd_);
        rawVideoFd_ = -1;
    }
}

Status RecorderEngine::OnCallback(std::shared_ptr<CFilter> filter, const CFilterCallBackCommand cmd,
    CStreamType outType)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("RecorderEngine::OnCallback is called.");
    Status ret = Status::OK;
    CHECK_RETURN_RET(cmd != CFilterCallBackCommand::NEXT_FILTER_NEEDED, ret);
    CHECK_RETURN_RET(filter == nullptr, ret);
    int32_t clusterId;
    filter->GetClusterId(clusterId);

    switch (outType) {
        case CStreamType::RAW_AUDIO:
            ret = HandleRawAudio(filter);
            break;
        case CStreamType::PROCESSED_AUDIO:
            ret = HandleProcessedAudio(filter);
            break;
        case CStreamType::RAW_VIDEO:
            ret = pipeline_->LinkFilters(filter, {movieEncoderFilter_}, outType);
            break;
        case CStreamType::CACHED_VIDEO:
            if (filter->GetName() == "PreyCacheFilter") {
                ret = pipeline_->LinkFilters(filter, {preyEncoderFilter_}, outType);
            } else if (filter->GetName() == "DepthCacheFilter") {
                ret = pipeline_->LinkFilters(filter, {depthEncoderFilter_}, outType);
            }
            break;
        case CStreamType::ENCODED_AUDIO:
            ret = HandleEncodedAudio(filter, clusterId);
            break;
        case CStreamType::ENCODED_VIDEO:
        case CStreamType::FORK_AUDIO:
            if (isFirstPrepare_) {
                MEDIA_INFO_LOG("RecorderEngine::OnCallback prepare muxer exit for first time.");
                break;
            }
            ret = HandleLinkMuxer(clusterId, filter, outType);
            break;
        default:
            break;
    }
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "pipeline_->LinkFilters failed. ret: %{public}d", ret);
    return Status::OK;
}

Status RecorderEngine::HandleRawAudio(std::shared_ptr<CFilter> filter)
{
    Status ret = Status::OK;
    if (isAudioPostEditEnabled_) {
        ret = PrepareAudioProcess();
        if (ret == Status::OK) {
            CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "PrepareAudioProcess failed");
            ret = pipeline_->LinkFilters(filter, {audioProcessFilter_}, CStreamType::RAW_AUDIO);
            CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "Link AudioProcessFilter failed");
        } else {
            // if create audio process failed, change source
            MEDIA_ERR_LOG("PrepareAudioProcess failed");
            isAudioPostEditEnabled_ = false;
            CHECK_EXECUTE(audioCaptureFilter_, audioCaptureFilter_->DoRelease());
            ret = PrepareAudioSource();
            CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "PrepareAudioSource failed");
            ret = PrepareAudioEncoder();
            CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "PrepareAudioEncoder failed");
            ret = pipeline_->LinkFilters(filter, {audioEncoderFilter_}, CStreamType::RAW_AUDIO);
            CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "Link AudioEncoderFilter failed");
        }
    } else {
        ret = PrepareAudioEncoder();
        CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "PrepareAudioEncoder failed");
        ret = pipeline_->LinkFilters(filter, {audioEncoderFilter_}, CStreamType::RAW_AUDIO);
        CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "Link AudioEncoderFilter failed");
    }
    return ret;
}

Status RecorderEngine::HandleProcessedAudio(std::shared_ptr<CFilter> filter)
{
    Status ret = Status::OK;
    ret = PrepareAudioEncoder();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "PrepareAudioEncoder failed");
    ret = pipeline_->LinkFilters(filter, {audioEncoderFilter_}, CStreamType::PROCESSED_AUDIO);
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "Link AudioEncoderFilter failed");
    ret = PrepareRawAudioEncoder();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "PrepareRawAudioEncoder failed");
    ret = pipeline_->LinkFilters(filter, {rawAudioEncoderFilter_}, CStreamType::PROCESSED_AUDIO);
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "Link RawAudioEncoderFilter failed");
    return ret;
}

Status RecorderEngine::HandleEncodedAudio(std::shared_ptr<CFilter> filter, int32_t clusterId)
{
    Status ret = Status::OK;
    switch (clusterId) {
        case DEFAULT_RAW_CLUSTER_ID:
            if (isFirstPrepare_) {
                MEDIA_INFO_LOG("RecorderEngine::OnCallback prepare muxer exit for first time.");
                break;
            }
            ret = HandleLinkMuxer(clusterId, filter, CStreamType::ENCODED_AUDIO);
            break;
        case DEFAULT_ALL_CLUSTER_ID:
            ret = PrepareAudioFork();
            CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "PrepareAudioFork failed");
            ret = pipeline_->LinkFilters(filter, {audioForkFilter_}, CStreamType::ENCODED_AUDIO);
            break;
        default:
            break;
    }
    return ret;
}

Status RecorderEngine::HandleLinkMuxer(int32_t clusterId, std::shared_ptr<CFilter> filter, CStreamType outType)
{
    Status ret = Status::OK;
    switch (clusterId) {
        case DEFAULT_MOVIE_CLUSTER_ID:
            ret = PrepareMovieMuxer();
            CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "PrepareMovieMuxer failed");
            pipeline_->LinkFilters(filter, {movieMuxerFilter_}, outType);
            break;
        case DEFAULT_RAW_CLUSTER_ID:
            ret = PrepareRawMuxer();
            CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "PrepareRawMuxer failed");
            pipeline_->LinkFilters(filter, {rawMuxerFilter_.Get()}, outType);
            break;
        case DEFAULT_ALL_CLUSTER_ID:
            ret = PrepareMovieMuxer();
            CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "PrepareMovieMuxer failed");
            pipeline_->LinkFilters(filter, {movieMuxerFilter_}, outType);
            ret = PrepareRawMuxer();
            CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "PrepareRawMuxer failed");
            pipeline_->LinkFilters(filter, {rawMuxerFilter_.Get()}, outType);
            break;
        default:
            break;
    }
    CHECK_RETURN_RET_ELOG(ret != Status::OK, ret, "pipeline_->LinkFilters failed.");
    return Status::OK;
}

void RecorderEngine::OnEvent(const Event &event)
{
    MEDIA_DEBUG_LOG("RecorderEngine::OnEvent is called.");
    switch (event.type) {
        case FilterEventType::EVENT_ERROR: {
            MEDIA_INFO_LOG("EVENT_ERROR.");
            if (event.srcFilter == "audio_capture_filter") {
                MEDIA_ERR_LOG("RecorderEngine::OnEvent EVENT_ERROR, audio capture filter init failed");
                CHECK_EXECUTE(audioCaptureFilter_ && pipeline_, pipeline_->RemoveHeadFilter(audioCaptureFilter_));
            }
            break;
        }
        case FilterEventType::EVENT_READY: {
            MEDIA_INFO_LOG("EVENT_READY.");
            OnStateChanged(StateId::READY);
            break;
        }
        case FilterEventType::EVENT_COMPLETE: {
            MEDIA_INFO_LOG("EVENT_COMPLETE., filter: %{public}s", event.srcFilter.c_str());
            CHECK_RETURN_ELOG(movieFilePhotoAssetProxy_ == nullptr, "movieFilePhotoAssetProxy_ is null");
            // notify video save finished when muxer is stopped
            if (event.srcFilter == "movie_muxer_filter") {
                MEDIA_INFO_LOG("EVENT_COMPLETE, notify movie video save finished");
                movieFilePhotoAssetProxy_->NotifyVideoSaveFinished(static_cast<VideoType>(MOVIE_VIDEO_TYPE));
            } else if (event.srcFilter == "raw_muxer_filter") {
                MEDIA_INFO_LOG("EVENT_COMPLETE, notify raw video save finished");
                movieFilePhotoAssetProxy_->NotifyVideoSaveFinished(static_cast<VideoType>(RAW_VIDEO_TYPE));
                needWaitForMuxerDone_ = false;
                NotifyMuxerDone();
            }
            break;
        }
        case FilterEventType::EVENT_VIDEO_FIRST_FRAME: {
            if (audioCaptureFilter_) {
                int64_t firstFramePts = Media::AnyCast<int64_t>(event.param);
                audioCaptureFilter_->SetVideoFirstFramePts(firstFramePts);
            }
            break;
        }
        default:
            break;
    }
}

sptr<Surface> RecorderEngine::GetRawSurface()
{
    return rawSurface_;
}

sptr<Surface> RecorderEngine::GetMetaSurface()
{
    return metaSurface_;
}

sptr<Surface> RecorderEngine::GetMovieDebugSurface()
{
    return movieDebugSurface_;
}

sptr<Surface> RecorderEngine::GetRawDebugSurface()
{
    return rawDebugSurface_;
}

sptr<Surface> RecorderEngine::GetDepthSurface()
{
    return depthSurface_;
}

sptr<Surface> RecorderEngine::GetPreySurface()
{
    return preySurface_;
}

sptr<Surface> RecorderEngine::GetImageEffectSurface()
{
#ifdef CAMERA_USE_IMAGE_EFFECT
    return imageEffectSurface_;
#else
    return movieSurface_;
#endif
}

void RecorderEngine::SetMovieFrameSize(int32_t width, int32_t height)
{
    movieWidth_ = static_cast<uint32_t>(width);
    movieHeight_ = static_cast<uint32_t>(height);
}

void RecorderEngine::SetRawFrameSize(int32_t width, int32_t height)
{
    rawWidth_ = static_cast<uint32_t>(width);
    rawHeight_ = static_cast<uint32_t>(height);
}

void RecorderEngine::SetWatermarkMeta()
{
    CHECK_RETURN(waterMarkInfo_.empty());
    std::shared_ptr<Meta> watermark = std::make_shared<Meta>();
    watermark->SetData(WATER_MARK_INFO_KEY, waterMarkInfo_);
    CHECK_EXECUTE(movieMuxerFilter_, movieMuxerFilter_->SetUserMeta(watermark));
    auto rawMuxerFilter = rawMuxerFilter_.Get();
    CHECK_EXECUTE(rawMuxerFilter, rawMuxerFilter->SetUserMeta(watermark));
}

void RecorderEngine::SetEncParamMeta()
{
    std::string encParam = "video_encode_bitrate_mode=SQR:bitrate=" + std::to_string(movieSettings_.videoBitrate);
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    userMeta->SetData("com.openharmony.encParam", encParam);
    CHECK_EXECUTE(movieMuxerFilter_, movieMuxerFilter_->SetUserMeta(userMeta));
    auto rawMuxerFilter = rawMuxerFilter_.Get();
    CHECK_EXECUTE(rawMuxerFilter, rawMuxerFilter->SetUserMeta(userMeta));
}

void RecorderEngine::SetRotation(int32_t rotation)
{
    MEDIA_INFO_LOG("RecorderEngine::SetRecorderCallback, rotation: %{public}d", rotation);
    switch (rotation) {
        case Plugins::VideoRotation::VIDEO_ROTATION_0:
            rotation_ = Plugins::VideoRotation::VIDEO_ROTATION_0;
            break;
        case Plugins::VideoRotation::VIDEO_ROTATION_90:
            rotation_ = Plugins::VideoRotation::VIDEO_ROTATION_90;
            break;
        case Plugins::VideoRotation::VIDEO_ROTATION_180:
            rotation_ = Plugins::VideoRotation::VIDEO_ROTATION_180;
            break;
        case Plugins::VideoRotation::VIDEO_ROTATION_270:
            rotation_ = Plugins::VideoRotation::VIDEO_ROTATION_270;
            break;
        default:
            break;
    }
}

int32_t RecorderEngine::SetOutputSettings(const EngineMovieSettings& movieSettings)
{
    // 首次打开电影模式时调用
    movieSettings_ = movieSettings;
    MEDIA_INFO_LOG("RecorderEngine::SetOutputSettings called, videobitRate %{public}d", movieSettings_.videoBitrate);
    return CAMERA_OK;
}

int32_t RecorderEngine::GetSupportedVideoFilters(std::vector<std::string> &supportedVideoFilters)
{
#ifdef CAMERA_USE_IMAGE_EFFECT
    auto imageEffectProxy = ImageEffectProxy::CreateImageEffectProxy();
    CHECK_EXECUTE(imageEffectProxy, imageEffectProxy->GetSupportedFilters(supportedVideoFilters));
#endif
    return CAMERA_OK;
}

int32_t RecorderEngine::SetVideoFilter(const std::string& filter, const std::string& filterParam)
{
    Status ret = Status::OK;
    ret = SetWatermarkBuffer(filter, filterParam);
    CHECK_RETURN_RET_ILOG(IsWatermarkSupportedByAvCodec(), (int32_t)ret, "Set watermark by AvCodec");
#ifdef CAMERA_USE_IMAGE_EFFECT
    if (!imageEffectFilter_) {
        imageEffectFilter_ = std::make_shared<ImageEffectFilter>("ImageEffectFilter", CFilterType::IMAGE_EFFECT);
    }
    CHECK_RETURN_RET_ELOG(imageEffectFilter_ == nullptr, CAMERA_UNKNOWN_ERROR, "ImageEffectFilter is null");
    imageEffectFilter_->SetImageEffect(filter, filterParam);
    isImageEffectEnabled_ = true;
#else
    isImageEffectEnabled_ = false;
#endif
    return CAMERA_OK;
}

int32_t RecorderEngine::SetUserMeta(const std::string& key, const std::string& val)
{
    MEDIA_DEBUG_LOG("RecorderEngine::SetUserMeta is called, string type");
    int32_t ret = CAMERA_INVALID_STATE;
    auto rawMuxerFilter = rawMuxerFilter_.Get();
    CHECK_RETURN_RET_ELOG(!rawMuxerFilter, ret, "rawMuxerFilter is null");
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    userMeta->SetData(key, val);
    rawMuxerFilter->SetUserMeta(userMeta);
    if (key == "com.openharmony.videoId") {
        rawMuxerFilter->SetUserMetaAllSet(true);
        rawMuxerFilter->NotifyWaitForUserMeta();
        NotifyUserMetaSet();
    }

    MEDIA_DEBUG_LOG("RecorderEngine::SetUserMeta key: %{public}s, val: %{public}s", key.c_str(), val.c_str());
    return CAMERA_OK;
}

int32_t RecorderEngine::SetUserMeta(const std::string& key, const std::vector<uint8_t>& val)
{
    MEDIA_DEBUG_LOG("RecorderEngine::SetUserMeta is called, buffer type");
    int32_t ret = CAMERA_INVALID_STATE;
    auto rawMuxerFilter = rawMuxerFilter_.Get();
    CHECK_RETURN_RET_ELOG(!rawMuxerFilter, ret, "rawMuxerFilter is null");
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    userMeta->SetData(key, val);
    rawMuxerFilter->SetUserMeta(userMeta);
    MEDIA_DEBUG_LOG("RecorderEngine::SetUserMeta key: %{public}s, buffer size: %{public}zu", key.c_str(),
                    val.size());
    return CAMERA_OK;
}

int32_t RecorderEngine::UpdatePhotoProxy(const std::string& videoId, int32_t videoEnhancementType)
{
    MEDIA_DEBUG_LOG("RecorderEngine::UpdatePhotoProxy is called");
    CHECK_RETURN_RET_ELOG(cameraPhotoProxy_ == nullptr, CAMERA_INVALID_STATE, "cameraPhotoProxy_ is nullptr");
    cameraPhotoProxy_->SetPhotoId(videoId);
    cameraPhotoProxy_->SetVideoEnhancementType(videoEnhancementType);
    if (needWaitForMuxerDone_) {
        WaitForMuxerDoneThenUpdatePhotoProxy();
    } else {
        CHECK_RETURN_RET_ELOG(
            movieFilePhotoAssetProxy_ == nullptr, CAMERA_INVALID_STATE, "movieFilePhotoAssetProxy_ is nullptr");
        movieFilePhotoAssetProxy_->UpdatePhotoProxy(cameraPhotoProxy_);
    };
    return CAMERA_OK;
}

int32_t RecorderEngine::EnableVirtualAperture(bool isVirtualApertureEnabled)
{
    MEDIA_DEBUG_LOG("RecorderEngine::EnableVirtualAperture is called, isVirtualApertureEnabled: %{public}d",
        isVirtualApertureEnabled);
    isVirtualApertureEnabled_ = isVirtualApertureEnabled;
    return CAMERA_OK;
}

Status RecorderEngine::SetWatermarkBuffer(std::string filter, std::string filterParam)
{
    // set empty buffer if filter name is not Inplace Sticker or filterParam is empty
    if (filter != INPLACE_STICKER_NAME || filterParam.empty()) {
        MEDIA_INFO_LOG("[WMDB] SetWatermarkBuffer set empty watermark buffer");
        waterMarkBuffer_.Set(nullptr);
        waterMarkInfo_.clear();
        return Status::OK;
    }
    // parse json info from app
    WatermarkEncodeConfig config;
    ParseWatermarkConfigFromJson(config, filterParam);
    // create pixel map
    std::shared_ptr<PixelMap> pixelMap;
    CreatePixelMapFromPath(pixelMap, config.imagePath);
    // scale pixel map
    ScalePixelMap(pixelMap, config, movieWidth_, movieHeight_);
    // rotate pixel map
    RotatePixelMap(pixelMap, config);
    // get av buffer config
    std::shared_ptr<Meta> meta = GetAvBufferMeta(config, movieWidth_, movieHeight_);
    CHECK_RETURN_RET(meta == nullptr, Status::ERROR_INVALID_PARAMETER);
    waterMarkInfo_ = CoverWatermarkConfigToJson(config);
    CHECK_RETURN_RET_ILOG(!IsWatermarkSupportedByAvCodec(), Status::OK, "[WMDB] Watermark is not supported by AvCodec");
    // create watermark buffer
    waterMarkBuffer_.Set(CreateWatermarkBuffer(pixelMap, meta));
    return Status::OK;
}

bool RecorderEngine::IsWatermarkSupportedByAvCodec()
{
    std::string mimeType;
    switch (movieSettings_.videoCodecType) {
        case EngineVideoCodecType::VIDEO_ENCODE_TYPE_AVC:
            mimeType = Plugins::MimeType::VIDEO_AVC;
            break;
        case EngineVideoCodecType::VIDEO_ENCODE_TYPE_HEVC:
            mimeType = Plugins::MimeType::VIDEO_HEVC;
            break;
        default:
            mimeType = Plugins::MimeType::VIDEO_AVC;
    }
    CHECK_EXECUTE(!codecList_.Get(), codecList_.Set(MediaAVCodec::AVCodecListFactory::CreateAVCodecList()));
    auto codecList = codecList_.Get();
    CHECK_RETURN_RET_ELOG(!codecList, CAMERA_UNKNOWN_ERROR, "codecList is null");
    MediaAVCodec::CapabilityData *capabilityData = codecList->GetCapability(mimeType,
        true, MediaAVCodec::AVCodecCategory::AVCODEC_HARDWARE);
    if (capabilityData != nullptr) {
        if (capabilityData->featuresMap.count(
            static_cast<int32_t>(MediaAVCodec::AVCapabilityFeature::VIDEO_WATERMARK))) {
            return true;
        } else {
            return false;
        }
    }
    CHECK_RETURN_RET_ELOG(!codecList, CAMERA_UNKNOWN_ERROR, "codecList is null");
    capabilityData = codecList->GetCapability(mimeType, true,
        MediaAVCodec::AVCodecCategory::AVCODEC_SOFTWARE);
    if (capabilityData != nullptr) {
        if (capabilityData->featuresMap.count(
            static_cast<int32_t>(MediaAVCodec::AVCapabilityFeature::VIDEO_WATERMARK))) {
            return true;
        } else {
            return false;
        }
    }
    return false;
}

int32_t RecorderEngine::GetFirstFrameTimestamp(int64_t& firstFrameTimestamp)
{
    CHECK_EXECUTE(rawEncoderFilter_, rawEncoderFilter_->GetMuxerFirstFrameTimestamp(firstFrameTimestamp));
    return CAMERA_OK;
}

Status RecorderEngine::CheckAudioPostEditAbility()
{
    isAudioPostEditEnabled_ = system::GetBoolParameter("const.photo.audio_post_edit.enable", false);
    CheckExternalMicrophone();
    SelectTargetAudioInputDevice();
    MEDIA_INFO_LOG("isAudioPostEditEnabled_:%{public}d", isAudioPostEditEnabled_);
    return Status::OK;
}

AudioChannel RecorderEngine::GetMicNum()
{
    MEDIA_INFO_LOG("called");
    std::string mainKey = "device_status";
    std::vector<std::string> subKeys = { "hardware_info#mic_num" };
    std::vector<std::pair<std::string, std::string>> result = {};
    AudioSystemManager* audioSystemMgr = AudioSystemManager::GetInstance();
    CHECK_RETURN_RET_WLOG(audioSystemMgr == nullptr, AudioChannel::STEREO, "GetAudioSystemManagerInstance failed");
    int32_t ret = audioSystemMgr->GetExtraParameters(mainKey, subKeys, result);
    CHECK_RETURN_RET_WLOG(ret != 0, AudioChannel::STEREO, "GetExtraParameters failed");
    CHECK_RETURN_RET_WLOG(result.empty() || result[0].second.empty() || result[0].first.empty(), AudioChannel::STEREO,
                          "GetMicNum result is empty");
    for (auto i : result[0].second) {
        CHECK_RETURN_RET_WLOG(!std::isdigit(i), AudioChannel::STEREO, "GetMicNum result is invalid");
    }
    int32_t micNum = 0;
    CHECK_RETURN_RET_WLOG(!StrToInt(result[0].second, micNum), AudioChannel::STEREO, "Convert micNum failed");
    int32_t oddFlag = micNum % 2;
    MEDIA_INFO_LOG("GetMicNum %{public}d + %{public}d", micNum, oddFlag);
    // odd channel should + 1
    return static_cast<AudioChannel>(micNum + oddFlag);
}

void RecorderEngine::CheckExternalMicrophone()
{
    CHECK_RETURN_ILOG(!isAudioPostEditEnabled_,
                      "CheckExternalMicrophone not enable audio edit, skip CheckExternalMicrophone");
    auto audioRoutingManager = AudioStandard::AudioRoutingManager::GetInstance();
    CHECK_RETURN_WLOG(!audioRoutingManager, "CheckExternalMicrophone audioRoutingManager is null");
    AudioStandard::AudioCapturerInfo captureInfo;
    captureInfo.sourceType = AudioStandard::SOURCE_TYPE_CAMCORDER;
    std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> descs;
    audioRoutingManager->GetPreferredInputDeviceForCapturerInfo(captureInfo, descs);
    for (auto& desc : descs) {
        CHECK_CONTINUE(!desc);
        auto type = desc->getType();
        auto typeStr = desc->GetDeviceTypeString();
        MEDIA_DEBUG_LOG("CheckExternalMicrophone device type:%{public}d--%{public}s", type,
            typeStr.c_str());
        CHECK_RETURN_ILOG(desc->getType() == AudioStandard::DEVICE_TYPE_MIC,
                          "CheckExternalMicrophone enable raw audio capture");
    }
    isAudioPostEditEnabled_ = false;
}

void RecorderEngine::SelectTargetAudioInputDevice()
{
    CHECK_RETURN_ILOG(!isAudioPostEditEnabled_,
                      "SelectTargetAudioInputDevice not enable audio edit, skip SelectTargetAudioInputDevice");
    auto audioSessionManager = AudioStandard::AudioSessionManager::GetInstance();
    auto devices = audioSessionManager->GetAvailableDevices(AudioStandard::AudioDeviceUsage::MEDIA_INPUT_DEVICES);
    std::shared_ptr<AudioStandard::AudioDeviceDescriptor> targetDevice = nullptr;
    for (auto& device : devices) {
        CHECK_CONTINUE(!device);
        MEDIA_DEBUG_LOG("SelectTargetAudioInputDevice find device %{public}s type:%{public}d "
                        "typeStr:%{public}s",
            device->deviceName_.c_str(), device->getType(), device->GetDeviceTypeString().c_str());
        CHECK_EXECUTE(device->getType() == AudioStandard::DEVICE_TYPE_MIC, targetDevice = device);
    }
    if (targetDevice) {
        MEDIA_INFO_LOG("SelectTargetAudioInputDevice type:%{public}d "
                       "typeStr:%{public}s ",
            targetDevice->getType(), targetDevice->GetDeviceTypeString().c_str());
        audioSessionManager->SelectInputDevice(targetDevice);
    }
}

void RecorderEngine::WaitForRawMuxerDone()
{
    CHECK_RETURN_ILOG(!needWaitForRawMuxerDone_, "no need WaitForRawMuxerDone");
    MEDIA_INFO_LOG("RecorderEngine::WaitForRawMuxerDone start");
    std::unique_lock<std::mutex> lock(muxerMutex_);
    std::cv_status waitStatus = muxerDoneCondition_.wait_for(
        lock, std::chrono::milliseconds(WAIT_MUXER_DONE_TIMEOUT_MS));
    CHECK_PRINT_ELOG(waitStatus == std::cv_status::timeout, "RecorderEngine::WaitForRawMuxerDone wait timeout");
    MEDIA_INFO_LOG("RecorderEngine::WaitForRawMuxerDone notified");
    needWaitForRawMuxerDone_ = false;
}

int64_t RecorderEngine::GetCurrentTime()
{
    struct timespec timestamp = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &timestamp);
    return static_cast<int64_t>(timestamp.tv_sec) * SEC_TO_NS + static_cast<int64_t>(timestamp.tv_nsec);
}
}
}