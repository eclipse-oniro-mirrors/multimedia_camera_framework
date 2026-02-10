/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <unistd.h>
#include "audio_video_muxer.h"
#include "sample_info.h"
#include "utils/camera_log.h"
#include "native_mfmagic.h"
#include "camera_dynamic_loader.h"

namespace OHOS {
namespace CameraStandard {

AudioVideoMuxer::AudioVideoMuxer()
{
}

AudioVideoMuxer::~AudioVideoMuxer()
{
    MEDIA_INFO_LOG("~AudioVideoMuxer enter");
}

int32_t AudioVideoMuxer::Create(OH_AVOutputFormat format, shared_ptr<PhotoAssetIntf> photoAssetProxy,
    VideoType videoType)
{
    photoAssetProxy_ = photoAssetProxy;
    if (photoAssetProxy_) {
        // LCOV_EXCL_START
        fd_ = photoAssetProxy_->GetVideoFd(videoType);
        // LCOV_EXCL_STOP
    } else {
        MEDIA_ERR_LOG("AudioVideoMuxer::Create photoAssetProxy_ is nullptr!");
    }
    MEDIA_INFO_LOG("CreateAVMuxer with videoFd: %{public}d", fd_);
    muxer_ = AVMuxerFactory::CreateAVMuxer(fd_, static_cast<Plugins::OutputFormat>(format));
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, 1, "create muxer failed!");
    return 0;
}

int32_t AudioVideoMuxer::Start()
{
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, 1, "muxer_ is null");
    int32_t ret = muxer_->Start();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Start failed, ret: %{public}d", ret);
    return 0;
    // LCOV_EXCL_STOP
}

int32_t AudioVideoMuxer::SetRotation(int32_t rotation)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("SetRotation rotation : %{public}d", rotation);
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, 1, "muxer_ is null");
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    param->Set<Tag::VIDEO_ROTATION>(static_cast<Plugins::VideoRotation>(rotation));
    int32_t ret = muxer_->SetParameter(param);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "SetRotation failed, ret: %{public}d", ret);
    return 0;
    // LCOV_EXCL_STOP
}

int32_t AudioVideoMuxer::SetCoverTime(float timems)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("SetCoverTime coverTime : %{public}f", timems);
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, 1, "muxer_ is null");
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    userMeta->SetData("com.openharmony.covertime", timems);
    int32_t ret = muxer_->SetUserMeta(userMeta);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "SetCoverTime failed, ret: %{public}d", ret);
    return 0;
    // LCOV_EXCL_STOP
}

int32_t AudioVideoMuxer::SetDeferredVideoEnhanceFlag(uint32_t flag)
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("SetDeferredVideoEnhanceFlag : %{public}u", flag);
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, 1, "muxer_ is null");
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    userMeta->SetData("com.openharmony.deferredVideoEnhanceFlag", std::to_string(flag));
    int32_t ret = muxer_->SetUserMeta(userMeta);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "SetDeferredVideoEnhanceFlag failed, ret: %{public}d", ret);
    return 0;
    // LCOV_EXCL_STOP
}

int32_t AudioVideoMuxer::SetVideoId(std::string videoId)
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("SetVideoId : %{public}s", videoId.c_str());
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, 1, "muxer_ is null");
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    userMeta->SetData("com.openharmony.videoId", videoId);
    int32_t ret = muxer_->SetUserMeta(userMeta);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "SetVideoId failed, ret: %{public}d", ret);
    return 0;
    // LCOV_EXCL_STOP
}

int32_t AudioVideoMuxer::SetStartTime(float timems)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("SetStartTime StartTime: %{public}f", timems);
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, 1, "muxer_ is null");
    constexpr int64_t SEC_TO_MSEC = 1e3;
    constexpr int64_t MSEC_TO_NSEC = 1e6;
    struct timespec realTime;
    struct timespec monotonic;
    clock_gettime(CLOCK_REALTIME, &realTime);
    clock_gettime(CLOCK_MONOTONIC, &monotonic);
    int64_t realTimeStamp = realTime.tv_sec * SEC_TO_MSEC + realTime.tv_nsec / MSEC_TO_NSEC;
    int64_t monotonicTimeStamp = monotonic.tv_sec * SEC_TO_MSEC + monotonic.tv_nsec / MSEC_TO_NSEC;
    int64_t firstFrameTime = realTimeStamp - monotonicTimeStamp + int64_t(timems);
    std::string firstFrameTimeStr = std::to_string(firstFrameTime);
    MEDIA_INFO_LOG("SetStartTime StartTime end: %{public}s", firstFrameTimeStr.c_str());
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    userMeta->SetData("com.openharmony.starttime", firstFrameTimeStr);
    int32_t ret = muxer_->SetUserMeta(userMeta);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "SetStartTime Failed, ret: %{public}d", ret);
    return 0;
    // LCOV_EXCL_STOP
}

int32_t AudioVideoMuxer::SetSqr(int32_t bitrate, bool isBframeEnable)
{
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr || bitrate <= 0, 1, "AudioVideoMuxer::SetSqr failed");
    std::string bitrateStr = STAGE_VIDEO_ENCODER_PARAM_VALUE + std::to_string(bitrate);
    std::string BframeStr = STAGE_VIDEO_ENCODER_BFRAME_VALUE + std::to_string(isBframeEnable);
    std::string BframeModeStr = STAGE_VIDEO_ENCODER_BFRAME_MODE_VALUE;
    uint32_t sqrFactor = isBframeEnable ? SQR_FACTOR_28 : SQR_FACTOR_27;
    std::string sqrFactorStr = STAGE_VIDEO_ENCODER_SQR_FACTOR_VALUE + std::to_string(sqrFactor);
    std::string InfoStr = bitrateStr + BframeStr + BframeModeStr + sqrFactorStr;
    MEDIA_DEBUG_LOG("InfoStr:%{public}s",InfoStr.c_str());
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    userMeta->SetData(STAGE_ENCODER_PARAM_KEY, InfoStr);
    int32_t ret = muxer_->SetUserMeta(userMeta);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "SetSqr failed, ret: %{public}d", ret);
    return 0;
}

int32_t AudioVideoMuxer::SetTimedMetadata()
{
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, 1, "muxer_ is null");
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    param->SetData("use_timed_meta_track", 1);
    return muxer_->SetParameter(param);
    // LCOV_EXCL_STOP
}

int32_t AudioVideoMuxer::WriteSampleBuffer(std::shared_ptr<OHOS::Media::AVBuffer> sample, TrackType type)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, 1, "muxer_ is nullptr!");
    CHECK_RETURN_RET_ELOG(sample == nullptr, AV_ERR_INVALID_VAL, "input sample is nullptr!");
    int32_t ret = AV_ERR_OK;
    int trackId = -1;
    switch (type) {
        case TrackType::AUDIO_TRACK:
            trackId = audioTrackId_;
            break;
        case TrackType::VIDEO_TRACK:
            trackId = videoTrackId_;
            break;
        case TrackType::META_TRACK:
            trackId = metaTrackId_;
            break;
        default:
            MEDIA_ERR_LOG("TrackType type = %{public}d not supported", type);
    }
    ret = muxer_->WriteSample(trackId, sample);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "WriteSampleBuffer failed, ret: %{public}d", ret);
    return 0;
}

int32_t AudioVideoMuxer::GetVideoFd()
{
    // LCOV_EXCL_START
    return fd_;
    // LCOV_EXCL_STOP
}

shared_ptr<PhotoAssetIntf> AudioVideoMuxer::GetPhotoAssetProxy()
{
    // LCOV_EXCL_START
    return photoAssetProxy_;
    // LCOV_EXCL_STOP
}


int32_t AudioVideoMuxer::AddTrack(int &trackId, std::shared_ptr<Format> format, TrackType type)
{
    CHECK_RETURN_RET_ELOG(format == nullptr, AV_ERR_INVALID_VAL, "input track format is nullptr!");
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, 1, "muxer_ is nullptr!");
    int32_t ret = muxer_->AddTrack(trackId, format->GetMeta());
    switch (type) {
        case TrackType::AUDIO_TRACK:
            audioTrackId_ = trackId;
            break;
        case TrackType::VIDEO_TRACK:
            videoTrackId_ = trackId;
            break;
        case TrackType::META_TRACK:
            metaTrackId_ = trackId;
            break;
        default:
            MEDIA_ERR_LOG("TrackType type = %{public}d not supported", type);
    }
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK && trackId >= 0, 1, "AddTrack failed, ret: %{public}d", ret);
    return 0;
}

int32_t AudioVideoMuxer::Stop()
{
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, 1, "muxer_ is nullptr!");
    int32_t ret = muxer_->Stop();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Stop failed, ret: %{public}d", ret);
    return 0;
    // LCOV_EXCL_STOP
}

int32_t AudioVideoMuxer::Release()
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("AudioVideoMuxer::Release enter");
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, 0, "muxer_ is nullptr!");
    muxer_ = nullptr;
    close(fd_);
    return 0;
    // LCOV_EXCL_STOP
}
} // CameraStandard
} // OHOS