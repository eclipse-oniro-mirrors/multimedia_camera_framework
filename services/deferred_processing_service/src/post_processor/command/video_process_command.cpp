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

#include "video_process_command.h"

#include "basic_definitions.h"
#include "dp_utils.h"
#include "dps.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
VideoProcessCommand::VideoProcessCommand(const int32_t userId) : userId_(userId)
{
    DP_DEBUG_LOG("entered. userId: %{public}d", userId_);
}

int32_t VideoProcessCommand::Initialize()
{
    DP_CHECK_RETURN_RET(initialized_.load(), DP_OK);
    auto schedulerManager = DPS_GetSchedulerManager();
    DP_CHECK_ERROR_RETURN_RET_LOG(schedulerManager == nullptr, DP_NULL_POINTER, "SchedulerManager is nullptr.");

    videdPostProcess_ = schedulerManager->GetVideoPostProcessor(userId_);
    DP_CHECK_ERROR_RETURN_RET_LOG(videdPostProcess_ == nullptr, DP_NULL_POINTER, "VideoPostProcessor is nullptr.");

    initialized_.store(true);
    return DP_OK;
}

int32_t VideoProcessSuccessCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }

    videdPostProcess_->OnProcessDone(videoId_);
    return DP_OK;
}

int32_t VideoProcessFailedCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }

    videdPostProcess_->OnError(videoId_, error_);
    return DP_OK;
}

int32_t VideoStateChangedCommand::Executing()
{
    return DP_OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS