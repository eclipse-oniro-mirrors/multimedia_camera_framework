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
#include "utils/camera_log.h"
#include "av_codec_proxy.h"

namespace OHOS {
namespace CameraStandard {

AudioVideoMuxer::AudioVideoMuxer()
{
}

AudioVideoMuxer::~AudioVideoMuxer()
{
    MEDIA_INFO_LOG("~AudioVideoMuxer enter");
    CHECK_EXECUTE(photoAssetProxy_ != nullptr, photoAssetProxy_ = nullptr);
    CHECK_EXECUTE(avCodecProxy_ != nullptr, avCodecProxy_ = nullptr);
}

int32_t AudioVideoMuxer::Create(OH_AVOutputFormat format, std::shared_ptr<PhotoAssetIntf> photoAssetProxy)
{
    photoAssetProxy_ = photoAssetProxy;
    if (photoAssetProxy_) {
        fd_ = photoAssetProxy_->GetVideoFd();
    } else {
        MEDIA_ERR_LOG("AudioVideoMuxer::Create photoAssetProxy_ is nullptr!");
    }
    MEDIA_INFO_LOG("CreateAVMuxer with videoFd: %{public}d", fd_);
    avCodecProxy_ = AVCodecProxy::CreateAVCodecProxy();
    CHECK_ERROR_RETURN_RET_LOG(avCodecProxy_ == nullptr, 1, "AVCodecProxy CreateAVCodecProxy failed!");
    int32_t ret = avCodecProxy_->CreateAVMuxer(fd_, static_cast<Plugins::OutputFormat>(format));
    CHECK_ERROR_RETURN_RET_LOG(ret != AV_ERR_OK, 1, "CreateAVMuxer failed, ret: %{public}d", ret);
    return 0;
}

int32_t AudioVideoMuxer::Start()
{
    CHECK_ERROR_RETURN_RET_LOG(avCodecProxy_ == nullptr, 1, "avCodecProxy_ is nullptr!");
    int32_t ret = avCodecProxy_->AVMuxerStart();
    CHECK_ERROR_RETURN_RET_LOG(ret != AV_ERR_OK, 1, "Start failed, ret: %{public}d", ret);
    return 0;
}

int32_t AudioVideoMuxer::SetRotation(int32_t rotation)
{
    MEDIA_INFO_LOG("SetRotation rotation : %{public}d", rotation);
    CHECK_ERROR_RETURN_RET_LOG(avCodecProxy_ == nullptr, 1, "avCodecProxy_ is nullptr!");
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    param->Set<Tag::VIDEO_ROTATION>(static_cast<Plugins::VideoRotation>(rotation));
    int32_t ret = avCodecProxy_->AVMuxerSetParameter(param);
    CHECK_ERROR_RETURN_RET_LOG(ret != AV_ERR_OK, 1, "SetRotation failed, ret: %{public}d", ret);
    return 0;
}

int32_t AudioVideoMuxer::SetCoverTime(float timems)
{
    MEDIA_INFO_LOG("SetCoverTime coverTime : %{public}f", timems);
    CHECK_ERROR_RETURN_RET_LOG(avCodecProxy_ == nullptr, 1, "avCodecProxy_ is nullptr!");
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    userMeta->SetData("com.openharmony.covertime", timems);
    int32_t ret = avCodecProxy_->AVMuxerSetUserMeta(userMeta);
    CHECK_ERROR_RETURN_RET_LOG(ret != AV_ERR_OK, 1, "SetCoverTime failed, ret: %{public}d", ret);
    return 0;
}

int32_t AudioVideoMuxer::SetStartTime(float timems)
{
    MEDIA_INFO_LOG("SetStartTime StartTime: %{public}f", timems);
    CHECK_ERROR_RETURN_RET_LOG(avCodecProxy_ == nullptr, 1, "avCodecProxy_ is nullptr!");
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
    int32_t ret = avCodecProxy_->AVMuxerSetUserMeta(userMeta);
    CHECK_ERROR_RETURN_RET_LOG(ret != AV_ERR_OK, 1, "SetStartTime Failed, ret: %{public}d", ret);
    return 0;
}

int32_t AudioVideoMuxer::SetTimedMetadata()
{
    CHECK_ERROR_RETURN_RET_LOG(avCodecProxy_ == nullptr, 1, "avCodecProxy_ is nullptr!");
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    param->SetData("use_timed_meta_track", 1);
    return avCodecProxy_->AVMuxerSetParameter(param);
}

int32_t AudioVideoMuxer::WriteSampleBuffer(std::shared_ptr<OHOS::Media::AVBuffer> sample, TrackType type)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(avCodecProxy_ == nullptr, 1, "avCodecProxy_ is nullptr!");
    CHECK_ERROR_RETURN_RET_LOG(sample == nullptr, AV_ERR_INVALID_VAL, "input sample is nullptr!");
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
    ret = avCodecProxy_->AVMuxerWriteSample(trackId, sample);
    CHECK_ERROR_RETURN_RET_LOG(ret != AV_ERR_OK, 1, "WriteSampleBuffer failed, ret: %{public}d", ret);
    return 0;
}

int32_t AudioVideoMuxer::GetVideoFd()
{
    return fd_;
}

std::shared_ptr<PhotoAssetIntf> AudioVideoMuxer::GetPhotoAssetProxy()
{
    return photoAssetProxy_;
}


int32_t AudioVideoMuxer::AddTrack(int &trackId, std::shared_ptr<Format> format, TrackType type)
{
    CHECK_ERROR_RETURN_RET_LOG(format == nullptr, AV_ERR_INVALID_VAL, "input track format is nullptr!");
    CHECK_ERROR_RETURN_RET_LOG(avCodecProxy_ == nullptr, 1, "avCodecProxy_ is nullptr!");
    int32_t ret = avCodecProxy_->AVMuxerAddTrack(trackId, format->GetMeta());
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
    CHECK_ERROR_RETURN_RET_LOG(ret != AV_ERR_OK && trackId >= 0, 1, "AddTrack failed, ret: %{public}d", ret);
    return 0;
}

int32_t AudioVideoMuxer::Stop()
{
    CHECK_ERROR_RETURN_RET_LOG(avCodecProxy_ == nullptr, 1, "avCodecProxy_ is nullptr!");
    int32_t ret = avCodecProxy_->AVMuxerStop();
    CHECK_ERROR_RETURN_RET_LOG(ret != AV_ERR_OK, 1, "Stop failed, ret: %{public}d", ret);
    return 0;
}

int32_t AudioVideoMuxer::Release()
{
    MEDIA_INFO_LOG("AudioVideoMuxer::Release enter");
    CHECK_ERROR_RETURN_RET_LOG(avCodecProxy_ == nullptr, 0, "avCodecProxy_ is nullptr!");
    AVCodecProxy::Release();
    avCodecProxy_ = nullptr;
    close(fd_);
    return 0;
}
} // CameraStandard
} // OHOS