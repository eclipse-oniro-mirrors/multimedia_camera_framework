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

#include "muxer.h"

#include "basic_definitions.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
Muxer::~Muxer()
{
    DP_DEBUG_LOG("entered.");
    muxer_ = nullptr;
}

MediaManagerError Muxer::Create(int32_t outputFd, Plugins::OutputFormat format)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(outputFd == INVALID_FD, ERROR_FAIL, "outputFd is invalid: %{public}d.", outputFd);

    muxer_ = AVMuxerFactory::CreateAVMuxer(outputFd, format);
    DP_CHECK_ERROR_RETURN_RET_LOG(muxer_ == nullptr, ERROR_FAIL, "Create avmuxer failed.");

    return OK;
}

MediaManagerError Muxer::AddTracks(const std::map<Media::Plugins::MediaType, std::shared_ptr<Track>>& trackMap)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(trackMap.empty(), ERROR_FAIL, "Invalid track map: trackMap is empty.");
    
    for (const auto& trackType : trackList_) {
        auto it = trackMap.find(trackType);
        DP_CHECK_ERROR_RETURN_RET_LOG(it == trackMap.end() && trackType != Media::Plugins::MediaType::TIMEDMETA,
            ERROR_FAIL, "Not find trackType: %{public}d.", trackType);

        const auto track = it != trackMap.end() ? it->second : nullptr;
        if (trackType == Media::Plugins::MediaType::TIMEDMETA) {
            auto ret = CheckAndAddMetaTrack(track);
            DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
                "Failed to add track: %{public}d, ret: %{public}d.", trackType, ret);
            continue;
        }
        
        auto ret = muxer_->AddTrack(trackIds_[trackType], track->GetFormat().format->GetMeta());
        DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
            "Failed to add track: %{public}d, ret: %{public}d.", trackType, ret);
    }
    return OK;
}

MediaManagerError Muxer::CheckAndAddMetaTrack(const std::shared_ptr<Track>& track)
{
    std::shared_ptr<Meta> meta = nullptr;
    if (track == nullptr) {
        meta = std::make_shared<Meta>();
        meta->Set<Tag::MIME_TYPE>(MIME_TIMED_META);
        meta->Set<Tag::TIMED_METADATA_KEY>(TIMED_METADATA_VALUE);
    } else {
        meta = track->GetFormat().format->GetMeta();
    }
    meta->Set<Tag::TIMED_METADATA_SRC_TRACK>(trackIds_[Media::Plugins::MediaType::VIDEO]);
    auto ret = muxer_->AddTrack(trackIds_[Media::Plugins::MediaType::TIMEDMETA], meta);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "Failed to add track: %{public}d, ret: %{public}d.", Media::Plugins::MediaType::TIMEDMETA, ret);
    return OK;
}


MediaManagerError Muxer::WriteStream(Media::Plugins::MediaType trackType, const std::shared_ptr<AVBuffer>& sample)
{
    int32_t trackId = GetTrackId(trackType);
    DP_CHECK_ERROR_RETURN_RET_LOG(trackId == INVALID_TRACK_ID, ERROR_FAIL, "Invalid track id.");

    auto ret = muxer_->WriteSample(trackId, sample);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "Write sample failed, ret: %{public}d.", ret);

    return OK;
}

int32_t Muxer::GetTrackId(Media::Plugins::MediaType trackType)
{
    auto it = trackIds_.find(trackType);
    return (it != trackIds_.end()) ? it->second : INVALID_TRACK_ID;
}

MediaManagerError Muxer::Start()
{
    DP_DEBUG_LOG("entered.");
    auto ret = muxer_->Start();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "Failed to start, ret: %{public}d", ret);

    return OK;
}

MediaManagerError Muxer::Stop()
{
    DP_DEBUG_LOG("entered.");
    auto ret = muxer_->Stop();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "Failed to stop, ret: %{public}d", ret);

    return OK;
}
MediaManagerError Muxer::AddMediaInfo(const std::shared_ptr<MediaInfo>& mediaInfo)
{
    auto param = std::make_shared<Meta>();
    int32_t rotation = mediaInfo->codecInfo.rotation == -1 ? 0 : mediaInfo->codecInfo.rotation;
    param->Set<Tag::VIDEO_ROTATION>(static_cast<Plugins::VideoRotation>(rotation));
    param->Set<Tag::MEDIA_CREATION_TIME>(mediaInfo->creationTime);
    param->Set<Tag::VIDEO_IS_HDR_VIVID>(mediaInfo->codecInfo.isHdrvivid);
    if (mediaInfo->latitude > 0) {
        param->Set<Tag::MEDIA_LATITUDE>(mediaInfo->latitude);
    }
    if (mediaInfo->longitude > 0) {
        param->Set<Tag::MEDIA_LONGITUDE>(mediaInfo->longitude);
    }
    auto ret = muxer_->SetParameter(param);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "Add param failed, ret: %{public}d", ret);

    if (mediaInfo->livePhotoCovertime >= 0) {
        auto userMeta = std::make_shared<Meta>();
        userMeta->SetData(LIVE_PHOTO_COVERTIME, mediaInfo->livePhotoCovertime);
        ret = muxer_->SetUserMeta(userMeta);
        DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
            "Add userMeta failed, ret: %{public}d", ret);
    }

    return OK;
}

MediaManagerError Muxer::AddUserMeta(const std::shared_ptr<Meta>& userMeta)
{
    auto ret = muxer_->SetUserMeta(userMeta);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "Add user meta failed, ret: %{public}d", ret);

    return OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
