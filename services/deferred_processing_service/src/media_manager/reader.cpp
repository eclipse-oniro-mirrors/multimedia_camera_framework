/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "dp_log.h"
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
    userFormat_ = nullptr;
    inputDemuxer_ = nullptr;
    tracks_.clear();
}

MediaManagerError Reader::Create(int32_t inputFd)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(inputFd == INVALID_FD, ERROR_FAIL, "inputFd is invalid: %{public}d.", inputFd);

    auto off = lseek(inputFd, DEFAULT_OFFSET, SEEK_END);
    DP_CHECK_ERROR_RETURN_RET_LOG(off == static_cast<off_t>(ERROR_FAIL), ERROR_FAIL, "reader lseek failed.");
    source_ = MediaAVCodec::AVSourceFactory::CreateWithFD(inputFd, DEFAULT_OFFSET, off);
    DP_CHECK_ERROR_RETURN_RET_LOG(source_ == nullptr, ERROR_FAIL, "create avsource failed.");

    auto ret = GetSourceFormat();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "get avsource format failed.");

    ret = InitTracksAndDemuxer();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "init tracks and demuxer failed.");
    return OK;
}

MediaManagerError Reader::GetSourceFormat()
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(source_ == nullptr, ERROR_FAIL, "avsource is nullptr.");

    Format sourceFormat;
    auto ret = source_->GetSourceFormat(sourceFormat);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "get avsource format failed.");
    sourceFormat_ = std::make_shared<Format>(sourceFormat);

    Format userMeta;
    ret = source_->GetUserMeta(userMeta);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "get avsource user meta failed.");
    userFormat_ = std::make_shared<Format>(userMeta);
    return OK;
}

MediaManagerError Reader::InitTracksAndDemuxer()
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(!sourceFormat_->GetIntValue(Tag::MEDIA_TRACK_COUNT, trackCount_), ERROR_FAIL,
        "get track count failed.");

    for (int32_t index = 0; index < trackCount_; ++index) {
        auto track = TrackFactory::GetInstance().CreateTrack(source_, index);
        DP_CHECK_ERROR_RETURN_RET_LOG(track == nullptr, ERROR_FAIL, "track: %{public}d is nullptr", index);
        DP_DEBUG_LOG("track type: %{public}d", track->GetType());
        tracks_.emplace(std::pair(track->GetType(), track));
    }
    DP_DEBUG_LOG("trackCount num: %{public}d, trackMap size: %{public}d",
        trackCount_, static_cast<int32_t>(tracks_.size()));
    inputDemuxer_ = std::make_shared<Demuxer>();
    auto ret = inputDemuxer_->Create(source_, tracks_);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "audio demuxer init failed.");
    return OK;
}

MediaManagerError Reader::Read(TrackType trackType, std::shared_ptr<AVBuffer>& sample)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(inputDemuxer_ == nullptr, ERROR_FAIL, "demuxer is nullptr.");
    auto ret = inputDemuxer_->ReadStream(trackType, sample);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret == ERROR_FAIL, ERROR_FAIL,
        "read sample failed, track type: %{public}d", trackType);
    DP_CHECK_RETURN_RET_LOG(ret == EOS, EOS, "reading finished.");
    return ret;
}

MediaManagerError Reader::GetMediaInfo(std::shared_ptr<MediaInfo>& mediaInfo)
{
    GetSourceMediaInfo(mediaInfo);
    mediaInfo->streamCount = trackCount_;

    auto it = tracks_.find(TrackType::AV_KEY_VIDEO_TYPE);
    DP_CHECK_ERROR_RETURN_RET_LOG(it == tracks_.end(), ERROR_FAIL, "no video track.");
    
    auto videoFormat = it->second->GetFormat();
    GetTrackMediaInfo(videoFormat, mediaInfo);
    return OK;
}

MediaManagerError Reader::Reset(int64_t resetPts)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(resetPts < 0, ERROR_FAIL, "invalid reset pts.");
    DP_CHECK_ERROR_RETURN_RET_LOG(inputDemuxer_ == nullptr, ERROR_FAIL, "demuxer is null.");

    auto ret = inputDemuxer_->SeekToTime(resetPts);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != OK, ERROR_FAIL, "reset pts failed.");
    return OK;
}

void Reader::GetSourceMediaInfo(std::shared_ptr<MediaInfo>& mediaInfo) const
{
    DP_DEBUG_LOG("entered.");
    auto ret = sourceFormat_->GetStringValue(Tag::MEDIA_CREATION_TIME, mediaInfo->creationTime);
    DP_CHECK_ERROR_PRINT_LOG(!ret, "cannot get %{public}s", Tag::MEDIA_CREATION_TIME);
    ret = sourceFormat_->GetLongValue(Tag::MEDIA_DURATION, mediaInfo->codecInfo.duration);
    DP_CHECK_ERROR_PRINT_LOG(!ret, "cannot get %{public}s", Tag::MEDIA_DURATION);
    ret = sourceFormat_->GetStringValue(RECORD_SYSTEM_TIMESTAMP, mediaInfo->recorderTime);
    DP_CHECK_ERROR_PRINT_LOG(!ret, "cannot get %{public}s", RECORD_SYSTEM_TIMESTAMP.c_str());
    ret = sourceFormat_->GetFloatValue(Tag::MEDIA_LATITUDE, mediaInfo->latitude);
    DP_CHECK_ERROR_PRINT_LOG(!ret, "cannot get %{public}s", Tag::MEDIA_LATITUDE);
    ret = sourceFormat_->GetFloatValue(Tag::MEDIA_LONGITUDE, mediaInfo->longitude);
    DP_CHECK_ERROR_PRINT_LOG(!ret, "cannot get %{public}s", Tag::MEDIA_LONGITUDE);
}

MediaManagerError Reader::GetTrackMediaInfo(const TrackFormat& trackFormat,
    std::shared_ptr<MediaInfo>& mediaInfo) const
{
    DP_DEBUG_LOG("entered.");
    auto& format = trackFormat.format;
    auto ret = format->GetStringValue(Tag::MIME_TYPE, mediaInfo->codecInfo.mimeType);
    DP_CHECK_ERROR_PRINT_LOG(!ret, "cannot get %{public}s", Tag::MIME_TYPE);

    int32_t intVal {DEFAULT_INT_VAL};
    ret = format->GetIntValue(Tag::VIDEO_COLOR_RANGE, intVal);
    DP_CHECK_ERROR_PRINT_LOG(!ret, "cannot get %{public}s", Tag::VIDEO_COLOR_RANGE);
    if (intVal != DEFAULT_INT_VAL) {
        mediaInfo->codecInfo.colorRange = static_cast<ColorRange>(intVal);
    }
    ret = format->GetIntValue(Tag::VIDEO_PIXEL_FORMAT, intVal);
    DP_CHECK_ERROR_PRINT_LOG(!ret, "cannot get %{public}s", Tag::VIDEO_PIXEL_FORMAT);
    if (intVal != DEFAULT_INT_VAL) {
        mediaInfo->codecInfo.pixelFormat = static_cast<PixelFormat>(intVal);
    }
    ret = format->GetIntValue(Tag::VIDEO_COLOR_PRIMARIES, intVal);
    DP_CHECK_ERROR_PRINT_LOG(!ret, "cannot get %{public}s", Tag::VIDEO_COLOR_PRIMARIES);
    if (intVal != DEFAULT_INT_VAL) {
        mediaInfo->codecInfo.colorPrimary = static_cast<ColorPrimaries>(intVal);
    }
    ret = format->GetIntValue(Tag::VIDEO_COLOR_TRC, intVal);
    DP_CHECK_ERROR_PRINT_LOG(!ret, "cannot get %{public}s", Tag::VIDEO_COLOR_TRC);
    if (intVal != DEFAULT_INT_VAL) {
        mediaInfo->codecInfo.colorTransferCharacter = static_cast<ColorTransferCharacteristic>(intVal);
    }
    ret = format->GetIntValue(Tag::VIDEO_IS_HDR_VIVID,  mediaInfo->codecInfo.isHdrvivid);
    DP_CHECK_ERROR_PRINT_LOG(!ret, "cannot get %{public}s", Tag::VIDEO_IS_HDR_VIVID);
    ret = format->GetIntValue(Tag::MEDIA_PROFILE, mediaInfo->codecInfo.profile);
    DP_CHECK_ERROR_PRINT_LOG(!ret, "cannot get %{public}s", Tag::MEDIA_PROFILE);
    ret = format->GetIntValue(Tag::MEDIA_LEVEL, mediaInfo->codecInfo.level);
    DP_CHECK_ERROR_PRINT_LOG(!ret, "cannot get %{public}s", Tag::MEDIA_LEVEL);
    ret = format->GetIntValue(Tag::VIDEO_WIDTH, mediaInfo->codecInfo.width);
    DP_CHECK_ERROR_PRINT_LOG(!ret, "cannot get %{public}s", Tag::VIDEO_WIDTH);
    ret = format->GetIntValue(Tag::VIDEO_HEIGHT, mediaInfo->codecInfo.height);
    DP_CHECK_ERROR_PRINT_LOG(!ret, "cannot get %{public}s", Tag::VIDEO_HEIGHT);
    ret = format->GetIntValue(Tag::VIDEO_ROTATION, mediaInfo->codecInfo.rotation);
    DP_CHECK_ERROR_PRINT_LOG(!ret, "cannot get %{public}s", Tag::VIDEO_ROTATION);
    ret = format->GetIntValue(Tag::VIDEO_ENCODE_BITRATE_MODE, mediaInfo->codecInfo.bitMode);
    DP_CHECK_ERROR_PRINT_LOG(!ret, "cannot get %{public}s", Tag::VIDEO_ENCODE_BITRATE_MODE);
    ret = format->GetLongValue(Tag::MEDIA_BITRATE, mediaInfo->codecInfo.bitRate);
    DP_CHECK_ERROR_PRINT_LOG(!ret, "cannot get %{public}s", Tag::MEDIA_BITRATE);

    double doubleVal {DEFAULT_DOUBLE_VAL};
    ret = format->GetDoubleValue(Tag::VIDEO_FRAME_RATE, doubleVal);
    DP_CHECK_ERROR_PRINT_LOG(!ret, "cannot get %{public}s", Tag::VIDEO_FRAME_RATE);
    if (doubleVal !=DEFAULT_DOUBLE_VAL) {
        mediaInfo->codecInfo.fps = FixFPS(doubleVal);
    }

    DP_DEBUG_LOG("colorRange: %{public}d, pixelFormat: %{public}d, colorPrimary: %{public}d, "
        "transfer: %{public}d, profile: %{public}d, level: %{public}d, bitRate: %{public}lld, "
        "fps: %{public}d, rotation: %{public}d, frame count: %{public}d, mime: %{public}s, isHdrvivid: %{public}d",
        mediaInfo->codecInfo.colorRange, mediaInfo->codecInfo.pixelFormat, mediaInfo->codecInfo.colorPrimary,
        mediaInfo->codecInfo.colorTransferCharacter, mediaInfo->codecInfo.profile, mediaInfo->codecInfo.level,
        static_cast<long long>(mediaInfo->codecInfo.bitRate), mediaInfo->codecInfo.fps, mediaInfo->codecInfo.rotation,
        mediaInfo->codecInfo.numFrames, mediaInfo->codecInfo.mimeType.c_str(), mediaInfo->codecInfo.isHdrvivid);
    return OK;
}

inline int32_t Reader::FixFPS(const double fps)
{
    return fps < static_cast<double>(FPS_30) * FACTOR ? FPS_30 : FPS_60;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
