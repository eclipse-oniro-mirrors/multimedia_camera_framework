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

#include "photo_command.h"

#include "dps.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

PhotoCommand::PhotoCommand(const int32_t userId, const std::string& photoId)
    : userId_(userId), photoId_(photoId)
{
    DP_DEBUG_LOG("entered. userId: %{public}d, photoId: %{public}s", userId_, photoId_.c_str());
}

PhotoCommand::~PhotoCommand()
{
    DP_DEBUG_LOG("entered.");
}

int32_t PhotoCommand::Initialize()
{
    DP_CHECK_RETURN_RET(initialized_.load(), DP_OK);

    schedulerManager_ = DPS_GetSchedulerManager();
    DP_CHECK_ERROR_RETURN_RET_LOG(schedulerManager_ == nullptr, DP_NULL_POINTER, "SchedulerManager is nullptr.");
    processor_ = schedulerManager_->GetPhotoProcessor(userId_);
    DP_CHECK_ERROR_RETURN_RET_LOG(processor_ == nullptr, DP_NULL_POINTER, "VideoProcessor is nullptr.");
    initialized_.store(true);
    return DP_OK;
}

AddPhotoCommand::AddPhotoCommand(const int32_t userId, const std::string& photoId, const DpsMetadata& metadata,
    bool discardable)
    : PhotoCommand(userId, photoId), metadata_(metadata), discardable_(discardable)
{
    DP_DEBUG_LOG("AddPhotoCommand, photoId: %{public}s, discardable: %{public}d", photoId_.c_str(), discardable_);
}

int32_t AddPhotoCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }

    processor_->AddImage(photoId_, discardable_, metadata_);
    return DP_OK;
}

RemovePhotoCommand::RemovePhotoCommand(const int32_t userId, const std::string& photoId, const bool restorable)
    : PhotoCommand(userId, photoId), restorable_(restorable)
{
    DP_DEBUG_LOG("RemovePhotoCommand, photoId: %{public}s, restorable: %{public}d", photoId_.c_str(), restorable_);
}

int32_t RemovePhotoCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }
    
    processor_->RemoveImage(photoId_, restorable_);
    return DP_OK;
}

int32_t RestorePhotoCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }

    processor_->RestoreImage(photoId_);
    return DP_OK;
}

ProcessPhotoCommand::ProcessPhotoCommand(const int32_t userId, const std::string& photoId, const std::string& appName)
    : PhotoCommand(userId, photoId), appName_(appName)
{
    DP_DEBUG_LOG("RemovePhotoCommand, photoId: %{public}s, appName: %{public}s", photoId_.c_str(), appName.c_str());
}

int32_t ProcessPhotoCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }

    processor_->ProcessImage(appName_, photoId_);
    return DP_OK;
}

int32_t CancelProcessPhotoCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }

    processor_->CancelProcessImage(photoId_);
    return DP_OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS