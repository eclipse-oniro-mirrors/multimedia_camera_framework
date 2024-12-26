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

#include "video_command.h"

#include "dps.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

VideoCommand::VideoCommand(const int32_t userId, const std::string& videoId)
    : userId_(userId), videoId_(videoId)
{
    DP_DEBUG_LOG("entered. userId: %{public}d, videoId: %{public}s", userId_, videoId_.c_str());
}

VideoCommand::~VideoCommand()
{
    DP_DEBUG_LOG("entered.");
    schedulerManager_ = nullptr;
    processor_ = nullptr;
}

int32_t VideoCommand::Initialize()
{
    DP_CHECK_RETURN_RET(initialized_.load(), DP_OK);

    schedulerManager_ = DPS_GetSchedulerManager();
    DP_CHECK_ERROR_RETURN_RET_LOG(schedulerManager_ == nullptr, DP_NULL_POINTER, "SchedulerManager is nullptr.");
    processor_ = schedulerManager_->GetVideoProcessor(userId_);
    DP_CHECK_ERROR_RETURN_RET_LOG(processor_ == nullptr, DP_NULL_POINTER, "VideoProcessor is nullptr.");
    initialized_.store(true);
    return DP_OK;
}

AddVideoCommand::AddVideoCommand(const int32_t userId, const std::string& videoId,
    const sptr<IPCFileDescriptor>& srcFd, const sptr<IPCFileDescriptor>& dstFd)
    : VideoCommand(userId, videoId), srcFd_(srcFd), dstFd_(dstFd)
{
    DP_DEBUG_LOG("AddVideoCommand, videoId: %{public}s, srcFd: %{public}d, dstFd: %{public}d",
        videoId_.c_str(), srcFd_->GetFd(), dstFd_->GetFd());
}

int32_t AddVideoCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }

    processor_->AddVideo(videoId_, srcFd_, dstFd_);
    return DP_OK;
}

RemoveVideoCommand::RemoveVideoCommand(const int32_t userId, const std::string& videoId, const bool restorable)
    : VideoCommand(userId, videoId), restorable_(restorable)
{
    DP_DEBUG_LOG("RemoveVideoCommand, videoId: %{public}s, restorable: %{public}d", videoId_.c_str(), restorable_);
}

int32_t RemoveVideoCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }
    
    processor_->RemoveVideo(videoId_, restorable_);
    return DP_OK;
}

int32_t RestoreVideoCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }

    processor_->RestoreVideo(videoId_);
    return DP_OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS