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
    DP_INFO_LOG("MuxerFilter Prepare.");
    DP_CHECK_ERROR_RETURN_RET_LOG(outputFd == INVALID_FD, ERROR_FAIL, "outputFd is invalid: %{public}d.", outputFd);

    muxer_ = AVMuxerFactory::CreateAVMuxer(outputFd, format);
    DP_CHECK_ERROR_RETURN_RET_LOG(muxer_ == nullptr, ERROR_FAIL, "Create avmuxer failed.");

    return OK;
}

MediaManagerError Muxer::AddTracks(const std::map<Media::Plugins::MediaType, std::shared_ptr<Track>>& trackMap)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(trackMap.empty(), ERROR_FAIL, "Invalid track map: trackMap is empty.");

    auto it = trackMap.find(Media::Plugins::MediaType::VIDEO);
    DP_CHECK_RETURN_RET(it == trackMap.end(), ERROR_FAIL);
    auto ret = CheckAddTrack(it->second);
    DP_CHECK_RETURN_RET(ret == ERROR_FAIL, ret);

    it = trackMap.find(Media::Plugins::MediaType::AUDIO);
    DP_CHECK_RETURN_RET(it == trackMap.end(), ERROR_FAIL);
    ret = CheckAddTrack(it->second);
    DP_CHECK_RETURN_RET(ret == ERROR_FAIL, ret);

    it = trackMap.find(Media::Plugins::MediaType::TIMEDMETA);
    auto track = it != trackMap.end() ? it->second : nullptr; 
    CheckAddMetaTrack(track);

    it = trackMap.find(Media::Plugins::MediaType::AUXILIARY);
    track = it != trackMap.end() ? it->second : nullptr;
    CheckAddRawAudioTrack(track);
    return OK;
}

MediaManagerError Muxer::CheckAddTrack(const std::shared_ptr<Track>& track)
{
    DP_CHECK_RETURN_RET(track == nullptr, ERROR_FAIL);
    auto type = track->GetType();
    auto ret = muxer_->AddTrack(trackIds_[type], track->GetMeta());
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "Failed to add track type: %{public}d, ret: %{public}d.", type, ret);
    return OK;
}

MediaManagerError Muxer::CheckAddMetaTrack(const std::shared_ptr<Track>& track)
{
    std::shared_ptr<Meta> meta = track != nullptr ? track->GetMeta() : nullptr;
    if (track == nullptr || meta == nullptr) {
        meta = std::make_shared<Meta>();
        meta->Set<Tag::MIME_TYPE>(MIME_TIMED_META);
        meta->Set<Tag::TIMED_METADATA_KEY>(TIMED_METADATA_VALUE);
    }
    meta->Set<Tag::TIMED_METADATA_SRC_TRACK>(trackIds_[Media::Plugins::MediaType::VIDEO]);
    auto ret = muxer_->AddTrack(trackIds_[Media::Plugins::MediaType::TIMEDMETA], meta);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "Failed to add meta track ret: %{public}d.", ret);
    return OK;
}

MediaManagerError Muxer::CheckAddRawAudioTrack(const std::shared_ptr<Track>& track)
{
    DP_CHECK_RETURN_RET(track == nullptr, ERROR_FAIL);
    auto meta = track->GetMeta();
    DP_CHECK_RETURN_RET(meta == nullptr, ERROR_FAIL);
    std::vector<int32_t> audioIds {trackIds_[Media::Plugins::MediaType::AUDIO]};
    meta->Set<Tag::REFERENCE_TRACK_IDS>(audioIds);
    auto ret = muxer_->AddTrack(trackIds_[Media::Plugins::MediaType::AUXILIARY], meta);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "Failed to add auxiliary track ret: %{public}d.", ret);
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
    DP_INFO_LOG("MuxerFilter Start.");
    auto ret = muxer_->Start();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "Failed to start, ret: %{public}d", ret);

    return OK;
}

MediaManagerError Muxer::Stop()
{
    DP_INFO_LOG("MuxerFilter Stop.");
    auto ret = muxer_->Stop();
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL, "Failed to stop, ret: %{public}d", ret);

    return OK;
}

MediaManagerError Muxer::AddMediaInfo(const std::shared_ptr<MediaInfo>& mediaInfo)
{
    DP_CHECK_RETURN_RET(mediaInfo == nullptr, ERROR_FAIL);
    auto param = std::make_shared<Meta>();
    param->Set<Tag::VIDEO_ROTATION>(mediaInfo->codecInfo.rotation);
    param->Set<Tag::MEDIA_CREATION_TIME>(mediaInfo->creationTime);
    param->Set<Tag::VIDEO_IS_HDR_VIVID>(mediaInfo->codecInfo.isHdrvivid);
    DP_CHECK_EXECUTE(mediaInfo->latitude != -1.0, param->Set<Tag::MEDIA_LATITUDE>(mediaInfo->latitude));
    DP_CHECK_EXECUTE(mediaInfo->longitude != -1.0, param->Set<Tag::MEDIA_LONGITUDE>(mediaInfo->longitude));
    auto ret = muxer_->SetParameter(param);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), ERROR_FAIL,
        "Add param failed, ret: %{public}d", ret);
    
    auto userMeta = std::make_shared<Meta>();
    DP_CHECK_EXECUTE(!mediaInfo->isWaterMark.empty(),
        userMeta->SetData(IS_WATER_MARK_KEY, mediaInfo->isWaterMark));
    DP_CHECK_EXECUTE(mediaInfo->livePhotoCovertime >= 0,
        userMeta->SetData(LIVE_PHOTO_COVERTIME, mediaInfo->livePhotoCovertime));
    DP_CHECK_EXECUTE(!mediaInfo->deviceFoldState.empty(),
        userMeta->SetData(DEVICE_FOLD_STATE_KEY, mediaInfo->deviceFoldState));
    DP_CHECK_EXECUTE(!mediaInfo->deviceModel.empty(),
        userMeta->SetData(DEVICE_MODEL_KEY, mediaInfo->deviceModel));
    DP_CHECK_EXECUTE(!mediaInfo->cameraPosition.empty(),
        userMeta->SetData(CAMERA_POSITION_KEY, mediaInfo->cameraPosition));
    if (!userMeta->Empty()) {
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
        "Add userMeta failed, ret: %{public}d", ret);
    return OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP