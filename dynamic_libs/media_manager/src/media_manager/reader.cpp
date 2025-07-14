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

#include "reader.h"

#include "dp_utils.h"
#include "track_factory.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr int32_t DEFAULT_INT_VAL = 0;
    constexpr double DEFAULT_DOUBLE_VAL = 0.0;
    constexpr int32_t FPS_30 = 30;
    constexpr int32_t FPS_60 = 60;
    constexpr double FACTOR = 1.1;
}

Reader::~Reader()
{
    source_ = nullptr;
    sourceFormat_ = nullptr;
    inputDemuxer_ = nullptr;
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
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "Audio demuxer init failed.");
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
    GetSourceMediaInfo(mediaInfo);
    mediaInfo->streamCount = trackCount_;

    auto it = tracks_.find(Media::Plugins::MediaType::VIDEO);
    DP_CHECK_ERROR_RETURN_RET_LOG(it == tracks_.end(), ERROR_FAIL, "Not find video track.");
    
    auto videoFormat = it->second->GetFormat();
    GetTrackMediaInfo(videoFormat, mediaInfo);
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
    CheckAndGetValue(sourceFormat_, Tag::MEDIA_CREATION_TIME, mediaInfo->creationTime);
    CheckAndGetValue(sourceFormat_, Tag::MEDIA_DURATION, mediaInfo->codecInfo.duration);
    CheckAndGetValue(sourceFormat_, Tag::MEDIA_LATITUDE, mediaInfo->latitude);
    CheckAndGetValue(sourceFormat_, Tag::MEDIA_LONGITUDE, mediaInfo->longitude);
    CheckAndGetValue(userFormat_, LIVE_PHOTO_COVERTIME, mediaInfo->livePhotoCovertime);
    std::string encParam;
    CheckAndGetValue(userFormat_, STAGE_ENC_PARAM_KEY, encParam);
    auto result = ParseKeyValue(encParam);
    for (const auto& [tag, value] : result) {
        if (tag == Tag::VIDEO_ENCODE_BITRATE_MODE) {
            mediaInfo->codecInfo.bitMode = MapVideoBitrateMode(value);
        } else if (tag == Tag::MEDIA_BITRATE) {
            int64_t bitRate;
            DP_CHECK_EXECUTE(StrToI64(value, bitRate), mediaInfo->codecInfo.bitRate = bitRate);
        }
    }
    DP_INFO_LOG("MediaInfo creationTime: %{public}s, duration: %{public}" PRId64 ", livePhotoCovertime: %{public}f, "
        "bitMode: %{public}d, bitRate: %{public}" PRId64,
        mediaInfo->creationTime.c_str(), mediaInfo->codecInfo.duration, mediaInfo->livePhotoCovertime,
        mediaInfo->codecInfo.bitMode, mediaInfo->codecInfo.bitRate);
}

MediaManagerError Reader::GetTrackMediaInfo(const TrackFormat& trackFormat,
    std::shared_ptr<MediaInfo>& mediaInfo) const
{
    auto& format = trackFormat.format;
    CheckAndGetValue(format, Tag::MIME_TYPE, mediaInfo->codecInfo.mimeType);
    CheckAndGetValue(format, Tag::MEDIA_PROFILE, mediaInfo->codecInfo.profile);
    CheckAndGetValue(format, Tag::MEDIA_LEVEL, mediaInfo->codecInfo.level);
    CheckAndGetValue(format, Tag::VIDEO_WIDTH, mediaInfo->codecInfo.width);
    CheckAndGetValue(format, Tag::VIDEO_HEIGHT, mediaInfo->codecInfo.height);
    CheckAndGetValue(format, Tag::VIDEO_ROTATION, mediaInfo->codecInfo.rotation);
    DP_CHECK_EXECUTE(mediaInfo->codecInfo.bitRate == 0,
        CheckAndGetValue(format, Tag::MEDIA_BITRATE, mediaInfo->codecInfo.bitRate));

    int32_t intVal {DEFAULT_INT_VAL};
    if (CheckAndGetValue(format, Tag::VIDEO_COLOR_RANGE, intVal)) {
        mediaInfo->codecInfo.colorRange = static_cast<ColorRange>(intVal);
    }
    if (CheckAndGetValue(format, Tag::VIDEO_PIXEL_FORMAT, intVal)) {
        mediaInfo->codecInfo.pixelFormat = static_cast<Media::Plugins::VideoPixelFormat>(intVal);
    }
    if (CheckAndGetValue(format, Tag::VIDEO_COLOR_PRIMARIES, intVal)) {
        mediaInfo->codecInfo.colorPrimary = static_cast<Media::Plugins::ColorPrimary>(intVal);
    }
    if (CheckAndGetValue(format, Tag::VIDEO_COLOR_TRC, intVal)) {
        mediaInfo->codecInfo.colorTransferCharacter = static_cast<Media::Plugins::TransferCharacteristic>(intVal);
    }
    if (CheckAndGetValue(format, Tag::VIDEO_IS_HDR_VIVID, intVal)) {
        mediaInfo->codecInfo.isHdrvivid = static_cast<bool>(intVal);
    }

    double doubleVal {DEFAULT_DOUBLE_VAL};
    if (CheckAndGetValue(format, Tag::VIDEO_FRAME_RATE, doubleVal)) {
        mediaInfo->codecInfo.fps = FixFPS(doubleVal);
    }

    DP_INFO_LOG("TrackMediaInfo colorRange: %{public}d, pixelFormat: %{public}d, colorPrimary: %{public}d, "
        "transfer: %{public}d, profile: %{public}d, level: %{public}d, bitRate: %{public}" PRId64 ", "
        "fps: %{public}d, rotation: %{public}d, mime: %{public}s, isHdrvivid: %{public}d",
        mediaInfo->codecInfo.colorRange, mediaInfo->codecInfo.pixelFormat, mediaInfo->codecInfo.colorPrimary,
        mediaInfo->codecInfo.colorTransferCharacter, mediaInfo->codecInfo.profile, mediaInfo->codecInfo.level,
        mediaInfo->codecInfo.bitRate, mediaInfo->codecInfo.fps, mediaInfo->codecInfo.rotation,
        mediaInfo->codecInfo.mimeType.c_str(), mediaInfo->codecInfo.isHdrvivid);
    return OK;
}

inline int32_t Reader::FixFPS(const double fps)
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
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
