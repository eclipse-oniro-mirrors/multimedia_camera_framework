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
// LCOV_EXCL_START
#include "reader.h"

#include <cstring>

#include "dp_utils.h"
#include "track_factory.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr double DEFAULT_DOUBLE_VAL = 0.0;
    constexpr int32_t FPS_30 = 30;
    constexpr int32_t FPS_60 = 60;
    constexpr double FACTOR = 1.1;
}

Reader::~Reader()
{
    tracks_.clear();
}

MediaManagerError Reader::Create(int32_t inputFd)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(inputFd == INVALID_FD, ERROR_FAIL, "inputFd is invalid: %{public}d.", inputFd);

    auto off = lseek(inputFd, DEFAULT_OFFSET, SEEK_END);
    DP_CHECK_ERROR_RETURN_RET_LOG(off == static_cast<off_t>(ERROR_FAIL), ERROR_FAIL, "Reader lseek failed.");
    source_ = MediaAVCodec::AVSourceFactory::CreateWithFD(inputFd, DEFAULT_OFFSET, off);
    DP_CHECK_ERROR_RETURN_RET_LOG(source_ == nullptr, ERROR_FAIL, "Create avsource failed.");

    auto ret = GetSourceFormat();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Get avsource format failed.");

    ret = GetUserMeta();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Get user format failed.");

    ret = InitTracksAndDemuxer();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Init tracks and demuxer failed.");
    return OK;
}

MediaManagerError Reader::GetSourceFormat()
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(source_ == nullptr, ERROR_FAIL, "AVSource is nullptr.");

    Format sourceFormat;
    auto ret = source_->GetSourceFormat(sourceFormat);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "Get avsource format failed.");
    sourceFormat_ = std::make_shared<Format>(sourceFormat);
    DP_INFO_LOG("GetSource data: %{public}s", sourceFormat_->Stringify().c_str());
    return OK;
}

MediaManagerError Reader::GetUserMeta()
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(source_ == nullptr, ERROR_FAIL, "AVSource is nullptr.");

    Format userFormat;
    auto ret = source_->GetUserMeta(userFormat);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "Get user format failed.");
    userFormat_ = std::make_shared<Format>(userFormat);
    return OK;
}

MediaManagerError Reader::InitTracksAndDemuxer()
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(!sourceFormat_->GetIntValue(Tag::MEDIA_TRACK_COUNT, trackCount_), ERROR_FAIL,
        "Get track count failed.");

    for (int32_t index = 0; index < trackCount_; ++index) {
        auto track = TrackFactory::GetInstance().CreateTrack(source_, index);
        DP_LOOP_CONTINUE_LOG(track == nullptr, "Track index: %{public}d is nullptr.", index);
        tracks_.emplace(std::pair(track->GetType(), track));
    }
    DP_DEBUG_LOG("TrackCount num: %{public}d, trackMap size: %{public}d",
        trackCount_, static_cast<int32_t>(tracks_.size()));
    inputDemuxer_ = std::make_shared<Demuxer>();
    auto ret = inputDemuxer_->Create(source_, tracks_);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Demuxer init failed.");
    return OK;
}

MediaManagerError Reader::Read(Media::Plugins::MediaType trackType, std::shared_ptr<AVBuffer>& sample)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(inputDemuxer_ == nullptr, ERROR_FAIL, "Demuxer is nullptr.");
    auto ret = inputDemuxer_->ReadStream(trackType, sample);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL,
        "Read sample failed, track type: %{public}d", trackType);
    DP_CHECK_RETURN_RET_LOG(ret == EOS, EOS, "Reading finished.");
    return ret;
}

MediaManagerError Reader::GetMediaInfo(std::shared_ptr<MediaInfo>& mediaInfo)
{
    mediaInfo->streamCount = trackCount_;
    GetSourceMediaInfo(mediaInfo);
    GetUserMediaInfo(mediaInfo);
    auto it = tracks_.find(Media::Plugins::MediaType::VIDEO);
    DP_CHECK_ERROR_RETURN_RET_LOG(it == tracks_.end(), ERROR_FAIL, "Not find video track.");
    
    auto videoMeta = it->second->GetMeta();
    GetTrackMediaInfo(videoMeta, mediaInfo);
    return OK;
}

MediaManagerError Reader::Reset(int64_t resetPts)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(resetPts < 0, ERROR_FAIL, "Invalid reset pts.");
    DP_CHECK_ERROR_RETURN_RET_LOG(inputDemuxer_ == nullptr, ERROR_FAIL, "Demuxer is null.");

    auto ret = inputDemuxer_->SeekToTime(resetPts);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Reset pts failed.");
    return OK;
}

void Reader::GetSourceMediaInfo(std::shared_ptr<MediaInfo>& mediaInfo) const
{
    DP_CHECK_RETURN(sourceFormat_ == nullptr);
    auto sourceMeta = sourceFormat_->GetMeta();
    DP_CHECK_ERROR_RETURN_LOG(sourceMeta == nullptr, "SourceMeta is nullptr.");
    DP_INFO_LOG("SourceMediaInfo: %{public}s", sourceFormat_->Stringify().c_str());
    sourceMeta->Get<Tag::MEDIA_CREATION_TIME>(mediaInfo->creationTime);
    sourceMeta->Get<Tag::MEDIA_DURATION>(mediaInfo->codecInfo.duration);
    sourceMeta->Get<Tag::MEDIA_LATITUDE>(mediaInfo->latitude);
    sourceMeta->Get<Tag::MEDIA_LONGITUDE>(mediaInfo->longitude);
}

void Reader::GetUserMediaInfo(std::shared_ptr<MediaInfo>& mediaInfo) const
{
    DP_CHECK_RETURN(userFormat_ == nullptr);
    auto userMeta = userFormat_->GetMeta();
    DP_CHECK_ERROR_RETURN_LOG(userMeta == nullptr, "UserMeta is nullptr.");
    DP_INFO_LOG("UserMediaInfo: %{public}s", userFormat_->Stringify().c_str());
    userMeta->GetData(IS_WATER_MARK_KEY, mediaInfo->isWaterMark);
    userMeta->GetData(WATER_MARK_INFO_KEY, mediaInfo->waterMarkInfo);
    std::string encParam;
    userMeta->GetData(ENC_PARAM_KEY, encParam);
    auto result = ParseKeyValue(encParam);
    for (const auto& [tag, value] : result) {
        if (strcmp(tag.c_str(), Tag::VIDEO_ENCODE_BITRATE_MODE) == 0) {
            mediaInfo->codecInfo.bitMode = MapVideoBitrateMode(value);
        } else if (strcmp(tag.c_str(), Tag::MEDIA_BITRATE) == 0) {
            int64_t bitRate;
            DP_CHECK_EXECUTE(StrToI64(value, bitRate), mediaInfo->codecInfo.bitRate = bitRate);
        } else if (strcmp(tag.c_str(), Tag::VIDEO_ENCODER_ENABLE_B_FRAME) == 0) {
            int64_t isBFrame;
            DP_CHECK_EXECUTE(StrToI64(value, isBFrame), mediaInfo->codecInfo.isBFrame = static_cast<bool>(isBFrame));
        } else if (strcmp(tag.c_str(), Tag::VIDEO_ENCODE_B_FRAME_GOP_MODE) == 0) {
            mediaInfo->codecInfo.bFrameGopMode = MapVideoBFrameGopMode(value);
        } else if (strcmp(tag.c_str(), Tag::VIDEO_ENCODER_SQR_FACTOR) == 0) {
            uint32_t srqFactor;
            DP_CHECK_EXECUTE(StrToU32(value, srqFactor), mediaInfo->codecInfo.srqFactor = srqFactor);
        }
    }
    userMeta->GetData(LIVE_PHOTO_COVERTIME, mediaInfo->livePhotoCovertime);
    userMeta->GetData(DEVICE_FOLD_STATE_KEY, mediaInfo->deviceFoldState);
    userMeta->GetData(DEVICE_MODEL_KEY, mediaInfo->deviceModel);
    userMeta->GetData(CAMERA_POSITION_KEY, mediaInfo->cameraPosition);
}

void Reader::GetTrackMediaInfo(const std::shared_ptr<Media::Meta>& trackMeta,
    std::shared_ptr<MediaInfo>& mediaInfo) const
{
    DP_CHECK_ERROR_RETURN_LOG(trackMeta == nullptr, "Track is nullptr.");
    trackMeta->Get<Tag::MIME_TYPE>(mediaInfo->codecInfo.mimeType);
    trackMeta->Get<Tag::MEDIA_PROFILE>(mediaInfo->codecInfo.profile);
    trackMeta->Get<Tag::MEDIA_LEVEL>(mediaInfo->codecInfo.level);
    trackMeta->Get<Tag::VIDEO_WIDTH>(mediaInfo->codecInfo.width);
    trackMeta->Get<Tag::VIDEO_HEIGHT>(mediaInfo->codecInfo.height);
    trackMeta->Get<Tag::VIDEO_ROTATION>(mediaInfo->codecInfo.rotation);
    trackMeta->Get<Tag::VIDEO_PIXEL_FORMAT>(mediaInfo->codecInfo.pixelFormat);
    trackMeta->Get<Tag::VIDEO_COLOR_PRIMARIES>(mediaInfo->codecInfo.colorPrimary);
    trackMeta->Get<Tag::VIDEO_COLOR_TRC>(mediaInfo->codecInfo.colorTransferCharacter);
    trackMeta->Get<Tag::VIDEO_IS_HDR_VIVID>(mediaInfo->codecInfo.isHdrvivid);
    trackMeta->Get<Tag::VIDEO_COLOR_RANGE>(mediaInfo->codecInfo.colorRange);
    double doubleVal {DEFAULT_DOUBLE_VAL};
    DP_CHECK_EXECUTE(trackMeta->Get<Tag::VIDEO_FRAME_RATE>(doubleVal),
        mediaInfo->codecInfo.fps = FixFPS(doubleVal));
    DP_CHECK_EXECUTE(mediaInfo->codecInfo.bitRate == -1,
        trackMeta->Get<Tag::MEDIA_BITRATE>(mediaInfo->codecInfo.bitRate));
    DP_INFO_LOG("TrackMediaInfo colorRange: %{public}d, pixelFormat: %{public}d, colorPrimary: %{public}d, "
        "transfer: %{public}d, profile: %{public}d, level: %{public}d, bitRate: %{public}" PRId64 ", "
        "fps: %{public}d, rotation: %{public}d, mime: %{public}s, isHdrvivid: %{public}d, bitMode: %{public}d",
        mediaInfo->codecInfo.colorRange, mediaInfo->codecInfo.pixelFormat, mediaInfo->codecInfo.colorPrimary,
        mediaInfo->codecInfo.colorTransferCharacter, mediaInfo->codecInfo.profile, mediaInfo->codecInfo.level,
        mediaInfo->codecInfo.bitRate, mediaInfo->codecInfo.fps, mediaInfo->codecInfo.rotation,
        mediaInfo->codecInfo.mimeType.c_str(), mediaInfo->codecInfo.isHdrvivid, mediaInfo->codecInfo.bitMode);
}

int32_t Reader::FixFPS(const double fps) const
{
    return fps < static_cast<double>(FPS_30) * FACTOR ? FPS_30 : FPS_60;
}

Media::Plugins::VideoEncodeBitrateMode Reader::MapVideoBitrateMode(const std::string& modeName) const
{
    static const std::unordered_map<std::string, Media::Plugins::VideoEncodeBitrateMode> modeMap = {
        {"CBR", Media::Plugins::VideoEncodeBitrateMode::CBR},
        {"VBR", Media::Plugins::VideoEncodeBitrateMode::VBR},
        {"CQ", Media::Plugins::VideoEncodeBitrateMode::CQ},
        {"CRF", Media::Plugins::VideoEncodeBitrateMode::CRF},
        {"SQR", Media::Plugins::VideoEncodeBitrateMode::SQR},
        {"CBR_VIDEOCALL", Media::Plugins::VideoEncodeBitrateMode::CBR_VIDEOCALL}
    };
    auto it = modeMap.find(modeName);
    DP_CHECK_RETURN_RET(it == modeMap.end(), Media::Plugins::VideoEncodeBitrateMode::CBR);
    return it->second;
}

Media::Plugins::VideoEncodeBFrameGopMode Reader::MapVideoBFrameGopMode(const std::string& gopModeName) const
{
    static const std::unordered_map<std::string, Media::Plugins::VideoEncodeBFrameGopMode> gopModeMap = {
        {"ADAPTIVE", Media::Plugins::VideoEncodeBFrameGopMode::VIDEO_ENCODE_GOP_ADAPTIVE_B_MODE},
        {"H3B", Media::Plugins::VideoEncodeBFrameGopMode::VIDEO_ENCODE_GOP_H3B_MODE},
    };
    auto it = gopModeMap.find(gopModeName);
    DP_CHECK_RETURN_RET(it == gopModeMap.end(),
        Media::Plugins::VideoEncodeBFrameGopMode::VIDEO_ENCODE_GOP_ADAPTIVE_B_MODE);
    return it->second;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP