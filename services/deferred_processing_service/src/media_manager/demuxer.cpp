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

#include "demuxer.h"

#include "avcodec_errors.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
Demuxer::~Demuxer()
{
    DP_DEBUG_LOG("entered.");
    demuxer_ = nullptr;
}

MediaManagerError Demuxer::Create(const std::shared_ptr<AVSource>& source,
    const std::map<Media::Plugins::MediaType, std::shared_ptr<Track>>& tracks)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(source == nullptr, ERROR_FAIL, "AVSource is nullptr.");

    demuxer_ = AVDemuxerFactory::CreateWithSource(source);
    DP_CHECK_ERROR_RETURN_RET_LOG(demuxer_ == nullptr, ERROR_FAIL, "Create demuxer failed.");

    DP_INFO_LOG("tracks size: %{public}d", static_cast<int32_t>(tracks.size()));
    for (const auto& [mediaType, trackPtr] : tracks) {
        auto trackFormat = trackPtr->GetFormat();
        SetTrackId(mediaType, trackFormat.trackId);
        auto ret = SeletctTrackByID(trackFormat.trackId);
        DP_CHECK_ERROR_BREAK_LOG(ret != OK,
            "Select track by id failed, track type: %{public}d, ret: %{public}d.", mediaType, ret);
    }
    
    return OK;
}

MediaManagerError Demuxer::ReadStream(Media::Plugins::MediaType trackType, std::shared_ptr<AVBuffer>& sample)
{
    DP_DEBUG_LOG("entered.");
    int32_t trackId = GetTrackId(trackType);
    DP_CHECK_ERROR_RETURN_RET_LOG(trackId == INVALID_TRACK_ID, ERROR_FAIL,
        "TrackType = %{public}d is not supported.", trackType);

    auto ret = demuxer_->ReadSampleBuffer(trackId, sample);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "Read sample failed, ret: %{public}d.", ret);
    DP_CHECK_RETURN_RET_LOG(sample->flag_ == AVCODEC_BUFFER_FLAG_EOS, EOS,
        "track(%{public}d) type: %{public}d is end.", trackId, trackType);
    return OK;
}

int32_t Demuxer::GetTrackId(Media::Plugins::MediaType trackType)
{
    auto it = trackIds_.find(trackType);
    return (it != trackIds_.end()) ? it->second : INVALID_TRACK_ID;
}

void Demuxer::SetTrackId(Media::Plugins::MediaType trackType, int32_t trackId)
{
    auto it = trackIds_.find(trackType);
    if (it != trackIds_.end()) {
        it->second = trackId;
    } else {
        DP_ERR_LOG("Unsupported media type: %{public}d", trackType);
    }
}

MediaManagerError Demuxer::SeekToTime(int64_t lastPts)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(lastPts < 0, ERROR_FAIL, "Don't need to seek, demuxer from start.");
    auto ret = demuxer_->SeekToTime(lastPts / 1000, SeekMode::SEEK_PREVIOUS_SYNC);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "Failed to seek, ret: %{public}d.", ret);
    return OK;
}

MediaManagerError Demuxer::SeletctTrackByID(int32_t trackId)
{
    DP_DEBUG_LOG("entered.");
    auto ret = demuxer_->SelectTrackByID(trackId);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "Select track by id failed, ret: %{public}d.", ret);
    return OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
