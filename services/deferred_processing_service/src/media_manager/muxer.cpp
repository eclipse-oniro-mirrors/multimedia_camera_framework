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

#include "muxer.h"

#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr int32_t INVALID_TRACK_ID = -1;
}

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
    DP_CHECK_ERROR_RETURN_RET_LOG(muxer_ == nullptr, ERROR_FAIL, "create avmuxer failed.");

    return OK;
}

MediaManagerError Muxer::AddTracks(const std::map<TrackType, const std::shared_ptr<Track>>& trackMap)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(trackMap.empty(), ERROR_FAIL, "finvalid track map.");

    DP_CHECK_ERROR_RETURN_RET_LOG(trackMap.find(TrackType::AV_KEY_VIDEO_TYPE) == trackMap.end(),
        ERROR_FAIL, "not find video track.");
    auto video = trackMap.at(TrackType::AV_KEY_VIDEO_TYPE);
    auto ret = muxer_->AddTrack(videoTrackId_, video->GetFormat().format->GetMeta());
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "add video track failed.");

    DP_CHECK_ERROR_RETURN_RET_LOG(trackMap.find(TrackType::AV_KEY_AUDIO_TYPE) == trackMap.end(),
        ERROR_FAIL, "not find audio track.");
    auto audio = trackMap.at(TrackType::AV_KEY_AUDIO_TYPE);
    ret = muxer_->AddTrack(audioTrackId_, audio->GetFormat().format->GetMeta());
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "add audio track failed.");

    return OK;
}

MediaManagerError Muxer::WriteStream(TrackType trackType, const std::shared_ptr<AVBuffer>& sample)
{
    DP_DEBUG_LOG("entered.");
    int32_t trackId = INVALID_TRACK_ID;
    if (trackType == TrackType::AV_KEY_VIDEO_TYPE) {
        trackId = videoTrackId_;
    } else if (trackType == TrackType::AV_KEY_AUDIO_TYPE) {
        trackId = audioTrackId_;
    }
    DP_CHECK_ERROR_RETURN_RET_LOG(trackId == INVALID_TRACK_ID, ERROR_FAIL, "invalid track id.");

    auto ret = muxer_->WriteSample(trackId, sample);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "write sample failed.");

    return OK;
}

MediaManagerError Muxer::Start()
{
    DP_DEBUG_LOG("entered.");
    auto ret = muxer_->Start();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "failed to start, ret: %{public}d", ret);

    return OK;
}

MediaManagerError Muxer::Stop()
{
    DP_DEBUG_LOG("entered.");
    auto ret = muxer_->Stop();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "failed to stop, ret: %{public}d", ret);

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
        "add param failed, ret: %{public}d", ret);

    auto userMeta = std::make_shared<Meta>();
    userMeta->SetData(VIDEO_FRAME_COUNT, mediaInfo->codecInfo.numFrames);
    userMeta->SetData(RECORD_SYSTEM_TIMESTAMP, mediaInfo->recorderTime);
    ret = muxer_->SetUserMeta(userMeta);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "add userMeta failed, ret: %{public}d", ret);

    return OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
