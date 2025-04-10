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

#include "sync_command.h"

#include "dps.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

SyncCommand::SyncCommand(const int32_t userId) : userId_(userId)
{
    DP_DEBUG_LOG("entered. userId: %{public}d", userId_);
}

SyncCommand::~SyncCommand()
{
    DP_DEBUG_LOG("entered.");
}

int32_t SyncCommand::Initialize()
{
    DP_CHECK_RETURN_RET(initialized_.load(), DP_OK);

    schedulerManager_ = DPS_GetSchedulerManager();
    DP_CHECK_ERROR_RETURN_RET_LOG(schedulerManager_ == nullptr, DP_NULL_POINTER, "SchedulerManager is nullptr.");
    sessionManager_ = DPS_GetSessionManager();
    DP_CHECK_ERROR_RETURN_RET_LOG(sessionManager_ == nullptr, DP_NULL_POINTER, "SessionManager is nullptr.");
    initialized_.store(true);
    return DP_OK;
}

// LCOV_EXCL_START
PhotoSyncCommand::PhotoSyncCommand(const int32_t userId,
    const std::unordered_map<std::string, std::shared_ptr<DeferredPhotoProcessingSession::PhotoInfo>>& imageIds)
    : SyncCommand(userId), imageIds_(imageIds)
{
    DP_DEBUG_LOG("VideoSyncCommand, video job num: %{public}d", static_cast<int32_t>(imageIds_.size()));
}

int32_t PhotoSyncCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }

    auto processor = schedulerManager_->GetPhotoProcessor(userId_);
    DP_CHECK_ERROR_RETURN_RET_LOG(processor == nullptr, DP_NULL_POINTER, "PhotoProcessor is nullptr.");

    std::vector<std::string> pendingImages;
    bool isSuccess = processor->GetPendingImages(pendingImages);
    if (!isSuccess) {
        for (const auto& it : imageIds_) {
            processor->AddImage(it.first, it.second->discardable_, it.second->metadata_);
        }
        return DP_OK;
    }

    std::set<std::string> hdiImageIds(pendingImages.begin(), pendingImages.end());
    for (const auto& photoId : hdiImageIds) {
        auto item = imageIds_.find(photoId);
        if (item != imageIds_.end()) {
            processor->AddImage(photoId, item->second->discardable_, item->second->metadata_);
            imageIds_.erase(photoId);
        } else {
            processor->RemoveImage(photoId, false);
        }
    }

    auto info = sessionManager_->GetPhotoInfo(userId_);
    if (info != nullptr) {
        auto callbacks =  info->GetRemoteCallback();
        for (const auto& it : imageIds_) {
            callbacks->OnError(it.first, ErrorCode::ERROR_IMAGE_PROC_INVALID_PHOTO_ID);
        }
    }
    pendingImages.clear();
    hdiImageIds.clear();
    return DP_OK;
}
// LCOV_EXCL_STOP

VideoSyncCommand::VideoSyncCommand(const int32_t userId,
    const std::unordered_map<std::string, std::shared_ptr<DeferredVideoProcessingSession::VideoInfo>>& videoIds)
    : SyncCommand(userId), videoIds_(videoIds)
{
    DP_DEBUG_LOG("VideoSyncCommand, video job num: %{public}d", static_cast<int32_t>(videoIds_.size()));
}

int32_t VideoSyncCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }

    auto processor = schedulerManager_->GetVideoProcessor(userId_);
    DP_CHECK_ERROR_RETURN_RET_LOG(processor == nullptr, DP_NULL_POINTER, "VideoProcessor is nullptr.");

    std::vector<std::string> pendingVidoes;
    bool isSuccess = processor->GetPendingVideos(pendingVidoes);
    if (!isSuccess) {
        for (const auto& it : videoIds_) {
            processor->AddVideo(it.first, it.second->srcFd_, it.second->dstFd_);
        }
        return DP_OK;
    }

    std::set<std::string> hdiVideoIds(pendingVidoes.begin(), pendingVidoes.end());
    for (const auto& videoId : hdiVideoIds) {
        // LCOV_EXCL_START
        auto item = videoIds_.find(videoId);
        if (item != videoIds_.end()) {
            processor->AddVideo(videoId, item->second->srcFd_, item->second->dstFd_);
            videoIds_.erase(videoId);
        } else {
            processor->RemoveVideo(videoId, false);
        }
        // LCOV_EXCL_STOP
    }

    auto info = sessionManager_->GetVideoInfo(userId_);
    if (info != nullptr) {
        auto callbacks =  info->GetRemoteCallback();
        for (const auto& it : videoIds_) {
            callbacks->OnError(it.first, ErrorCode::ERROR_VIDEO_PROC_INVALID_VIDEO_ID);
        }
    }
    pendingVidoes.clear();
    hdiVideoIds.clear();
    return DP_OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS