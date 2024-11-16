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

    for (auto& trackInfo : trackIds_) {
        auto it = trackMap.find(trackInfo.first);
        DP_CHECK_ERROR_RETURN_RET_LOG(it == trackMap.end(), ERROR_FAIL,
            "Not find trackType: %{public}d.", static_cast<int>(trackInfo.first));

        auto track = it->second;
        auto ret = muxer_->AddTrack(trackInfo.second, track->GetFormat().format->GetMeta());
        DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
            "Failed to add track: %{public}d, ret: %{public}d.", static_cast<int>(trackInfo.first), ret);
    }

    return OK;
}


MediaManagerError Muxer::WriteStream(Media::Plugins::MediaType trackType, const std::shared_ptr<AVBuffer>& sample)
{
    DP_DEBUG_LOG("entered.");
    
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
    param->Set<Tag::MEDIA_LATITUDE>(mediaInfo->latitude);
    param->Set<Tag::MEDIA_LONGITUDE>(mediaInfo->longitude);
    auto ret = muxer_->SetParameter(param);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "Add param failed, ret: %{public}d", ret);

    auto userMeta = std::make_shared<Meta>();
    userMeta->SetData(VIDEO_FRAME_COUNT, mediaInfo->codecInfo.numFrames);
    userMeta->SetData(RECORD_SYSTEM_TIMESTAMP, mediaInfo->recorderTime);
    ret = muxer_->SetUserMeta(userMeta);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "Add userMeta failed, ret: %{public}d", ret);

    return OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
