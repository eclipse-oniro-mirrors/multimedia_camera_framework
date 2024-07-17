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
#include "camera_log.h"
#include "native_mfmagic.h"

namespace OHOS {
namespace CameraStandard {

AudioVideoMuxer::AudioVideoMuxer()
{
}

AudioVideoMuxer::~AudioVideoMuxer()
{
    MEDIA_INFO_LOG("~AudioVideoMuxer enter");
}

int32_t AudioVideoMuxer::Create(OH_AVOutputFormat format, std::shared_ptr<Media::PhotoAssetProxy> photoAssetProxy)
{
    photoAssetProxy_ = photoAssetProxy;
    fd_ = photoAssetProxy_->GetVideoFd();
    MEDIA_INFO_LOG("CreateAVMuxer with videoFd: %{public}d", fd_);
    muxer_ = AVMuxerFactory::CreateAVMuxer(fd_, static_cast<Plugins::OutputFormat>(format));
    CHECK_AND_RETURN_RET_LOG(muxer_ != nullptr, 1, "create muxer failed!");
    return 0;
}

int32_t AudioVideoMuxer::Start()
{
    CHECK_AND_RETURN_RET_LOG(muxer_ != nullptr, 1, "muxer_ is null");
    int32_t ret = muxer_->Start();
    CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, 1, "Start failed, ret: %{public}d", ret);
    return 0;
}

int32_t AudioVideoMuxer::SetRotation(int32_t rotation)
{
    MEDIA_INFO_LOG("SetRotation rotation : %{public}d", rotation);
    CHECK_AND_RETURN_RET_LOG(muxer_ != nullptr, 1, "muxer_ is null");
    std::shared_ptr<Meta> param = std::make_shared<Meta>();
    param->Set<Tag::VIDEO_ROTATION>(static_cast<Plugins::VideoRotation>(rotation));
    int32_t ret = muxer_->SetParameter(param);
    CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, 1, "SetRotation failed, ret: %{public}d", ret);
    return 0;
}

int32_t AudioVideoMuxer::SetCoverTime(float timems)
{
    MEDIA_INFO_LOG("SetCoverTime coverTime : %{public}f", timems);
    CHECK_AND_RETURN_RET_LOG(muxer_ != nullptr, 1, "muxer_ is null");
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    userMeta->SetData("com.openharmony.covertime", timems);
    int32_t ret = muxer_->SetUserMeta(userMeta);
    CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, 1, "SetCoverTime failed, ret: %{public}d", ret);
    return 0;
}

int32_t AudioVideoMuxer::WriteSampleBuffer(OH_AVBuffer *sample, TrackType type)
{
    CHECK_AND_RETURN_RET_LOG(muxer_ != nullptr, 1, "muxer_ is null");
    CHECK_AND_RETURN_RET_LOG(sample != nullptr, AV_ERR_INVALID_VAL, "input sample is nullptr!");
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
    ret = muxer_->WriteSample(trackId, sample->buffer_);
    CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, 1, "WriteSampleBuffer failed, ret: %{public}d", ret);
    return 0;
}

int32_t AudioVideoMuxer::GetVideoFd()
{
    return fd_;
}

std::shared_ptr<Media::PhotoAssetProxy> AudioVideoMuxer::GetPhotoAssetProxy()
{
    return photoAssetProxy_;
}


int32_t AudioVideoMuxer::AddTrack(int &trackId, OH_AVFormat *format, TrackType type)
{
    CHECK_AND_RETURN_RET_LOG(muxer_ != nullptr, 1, "muxer_ is null");
    CHECK_AND_RETURN_RET_LOG(format != nullptr, AV_ERR_INVALID_VAL, "input track format is nullptr!");
    int32_t ret = muxer_->AddTrack(trackId, format->format_.GetMeta());
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
    OH_AVFormat_Destroy(format);
    CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK || trackId < 0, 1, "AddTrack failed, ret: %{public}d", ret);
    return 0;
}

int32_t AudioVideoMuxer::Stop()
{
    CHECK_AND_RETURN_RET_LOG(muxer_ != nullptr, 1, "muxer_ is null");
    int32_t ret = muxer_->Stop();
    CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, 1, "Stop failed, ret: %{public}d", ret);
    return 0;
}

int32_t AudioVideoMuxer::Release()
{
    MEDIA_INFO_LOG("AudioVideoMuxer::Release enter");
    if (muxer_ != nullptr) {
        muxer_ = nullptr;
        close(fd_);
    }
    return 0;
}

} // CameraStandard
} // OHOS