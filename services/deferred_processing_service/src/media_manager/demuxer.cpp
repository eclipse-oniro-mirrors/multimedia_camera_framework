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

#include "demuxer.h"

#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr int32_t INVALID_TRACK_ID = -1;
}

Demuxer::~Demuxer()
{
    DP_DEBUG_LOG("entered.");
    demuxer_ = nullptr;
}

MediaManagerError Demuxer::Create(const std::shared_ptr<AVSource>& source,
    const std::map<TrackType, const std::shared_ptr<Track>>& tracks)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(source == nullptr, ERROR_FAIL, "source is nullptr.");

    demuxer_ = AVDemuxerFactory::CreateWithSource(source);
    DP_CHECK_ERROR_RETURN_RET_LOG(demuxer_ == nullptr, ERROR_FAIL, "create demuxer failed.");

    auto ret = OK;
    DP_INFO_LOG("tracks size: %{public}d", static_cast<int32_t>(tracks.size()));
    auto iter = tracks.cbegin();
    for (; iter != tracks.cend(); ++iter) {
        auto trackFormat = iter->second->GetFormat();
        if (iter->first == TrackType::AV_KEY_AUDIO_TYPE) {
            audioTrackId_ = trackFormat.trackId;
        }
        if (iter->first == TrackType::AV_KEY_VIDEO_TYPE) {
            videoTrackId_ = trackFormat.trackId;
        }
        DP_DEBUG_LOG("track id: %{public}d, track type: %{public}d", trackFormat.trackId, iter->first);
        ret = SeletctTrackByID(trackFormat.trackId);
        DP_CHECK_ERROR_BREAK_LOG(ret != OK, "select track by id failed, track type: %{public}d", iter->first);
    }
    return ret;
}

MediaManagerError Demuxer::ReadStream(TrackType trackType, std::shared_ptr<AVBuffer>& sample)
{
    DP_DEBUG_LOG("entered.");
    int32_t trackId = INVALID_TRACK_ID;
    if (trackType == TrackType::AV_KEY_VIDEO_TYPE) {
        trackId = videoTrackId_;
    }
    if (trackType == TrackType::AV_KEY_AUDIO_TYPE) {
        trackId = audioTrackId_;
    }

    DP_CHECK_ERROR_RETURN_RET_LOG(trackId == INVALID_TRACK_ID, ERROR_FAIL, "invalid track id.");
    auto ret = demuxer_->ReadSampleBuffer(trackId, sample);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "read sample failed.");
    DP_CHECK_RETURN_RET_LOG(sample->flag_ == AVCODEC_BUFFER_FLAG_EOS, EOS, "track(%{public}d) is end.", trackId);
    return OK;
}

MediaManagerError Demuxer::SeekToTime(int64_t lastPts)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(lastPts < 0, ERROR_FAIL, "don't need to seek, demuxer from start.");
    auto ret = demuxer_->SeekToTime(lastPts / 1000, SeekMode::SEEK_PREVIOUS_SYNC);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "failed to seek.");
    return OK;
}

MediaManagerError Demuxer::SeletctTrackByID(int32_t trackId)
{
    DP_DEBUG_LOG("entered.");
    auto ret = demuxer_->SelectTrackByID(trackId);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "select track by id failed.");
    return OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
