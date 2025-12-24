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
#include "moving_photo_avmuxer.h"
#include "camera_log.h"
#include "native_mfmagic.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {

MovingPhotoAVMuxer::MovingPhotoAVMuxer()
{
}

MovingPhotoAVMuxer::~MovingPhotoAVMuxer()
{
    MEDIA_INFO_LOG("~MovingPhotoAVMuxer enter");
}

int32_t MovingPhotoAVMuxer::Create(Plugins::OutputFormat format, int32_t fd)
{
    fd_ = fd;
    MEDIA_INFO_LOG("CreateAVMuxer with videoFd: %{public}d", fd_);
    muxer_ = AVMuxerFactory::CreateAVMuxer(fd_, format);
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, 1, "create muxer failed!");
    return MEDIA_OK;
}

int32_t MovingPhotoAVMuxer::Start()
{
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, 1, "muxer_ is null");
    int32_t ret = muxer_->Start();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Start failed, ret: %{public}d", ret);
    return MEDIA_OK;
}

int32_t MovingPhotoAVMuxer::SetParameter(const std::shared_ptr<Meta> &param)
{
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, 1, "muxer_ is null");
    int32_t ret = muxer_->SetParameter(param);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "SetParameter failed, ret: %{public}d", ret);
    return MEDIA_OK;
}

int32_t MovingPhotoAVMuxer::SetUserMeta(MuxerConfig& config)
{
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, 1, "muxer_ is null");
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    MEDIA_INFO_LOG("SetUserMeta coverTime : %{public}f", config.covertime);
    userMeta->SetData(MOVING_PHOTO_COVER_TIME, config.covertime);
    MEDIA_INFO_LOG("SetUserMeta starttime: %{public}s", config.starttime.c_str());
    userMeta->SetData(MOVING_PHOTO_START_TIME, config.starttime);
    if (config.hasEnhanceFlag) {
        MEDIA_DEBUG_LOG("SetUserMeta videoEnhanceFlag : %{public}u", config.videoEnhanceFlag);
        userMeta->SetData(MOVING_PHOTO_DEFERRED_VIDEO_ENHANCE_FLAG, std::to_string(config.videoEnhanceFlag));
    }
    if (config.hasVideoId) {
        MEDIA_INFO_LOG("SetUserMeta videoId : %{public}s", config.videoId.c_str());
        userMeta->SetData(MOVING_PHOTO_VIDEO_ID, config.videoId);
    }
    if (config.hasBitrateString) {
        userMeta->SetData(MOVING_PHOTO_ENCODER_PARAM, config.bitrateString);
    }
    int32_t ret = muxer_->SetUserMeta(userMeta);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "SetUserMeta failed, ret: %{public}d", ret);
    return MEDIA_OK;
}

int32_t MovingPhotoAVMuxer::WriteSampleBuffer(int32_t trackId, std::shared_ptr<OHOS::Media::AVBuffer> sample)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(trackId == -1, MEDIA_INVALID_PARAM, "muxer_ is null");
    CHECK_RETURN_RET_ELOG(sample == nullptr, MEDIA_INVALID_PARAM, "input sample is nullptr!");
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, MEDIA_ERR, "muxer_ is null");
    int32_t ret = muxer_->WriteSample(trackId, sample);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, MEDIA_ERR, "WriteSampleBuffer failed, ret:%{public}d", ret);
    return MEDIA_OK;
}

int32_t MovingPhotoAVMuxer::GetVideoFd()
{
    return fd_;
}

int32_t MovingPhotoAVMuxer::AddTrack(int32_t &trackId, std::shared_ptr<Meta> meta)
{
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, 1, "muxer_ is null");
    CHECK_RETURN_RET_ELOG(meta == nullptr, MEDIA_INVALID_PARAM, "input track meta is nullptr!");
    int32_t ret = muxer_->AddTrack(trackId, meta);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, MEDIA_ERR, "AddTrack failed, ret: %{public}d", ret);
    std::string mimeType;
    meta->Get<Tag::MIME_TYPE>(mimeType);
    if (mimeType.find("audio/") == 0) {
        audioTrackId_ = trackId;
    } else if (mimeType.find("video/") == 0) {
        videoTrackId_ = trackId;
    } else if (mimeType.find("meta/") == 0) {
        metaTrackId_ = trackId;
    } else {
        MEDIA_ERR_LOG("mimeType: %{public}s not supported", mimeType.c_str());
        return MEDIA_ERR;
    }
    MEDIA_INFO_LOG("mimeType: %{public}s add success", mimeType.c_str());
    return MEDIA_OK;
}

int32_t MovingPhotoAVMuxer::Stop()
{
    MEDIA_INFO_LOG("MovingPhotoAVMuxer::Stop E");
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, 1, "muxer_ is null");
    int32_t ret = muxer_->Stop();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Stop failed, ret: %{public}d", ret);
    return MEDIA_OK;
}

int32_t MovingPhotoAVMuxer::Release()
{
    MEDIA_INFO_LOG("MovingPhotoAVMuxer::Release enter");
    if (muxer_ != nullptr) {
        muxer_ = nullptr;
        close(fd_);
    }
    return MEDIA_OK;
}
} // CameraStandard
} // OHOS
// LCOV_EXCL_STOP