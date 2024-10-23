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

VideoProcessCommand::~VideoProcessCommand()
{
    DP_DEBUG_LOG("entered.");
    schedulerManager_ = nullptr;
    controller_ = nullptr;
}

int32_t VideoProcessCommand::Initialize()
{
    DP_CHECK_RETURN_RET(initialized_.load(), DP_OK);
    schedulerManager_ = DPS_GetSchedulerManager();
    DP_CHECK_ERROR_RETURN_RET_LOG(schedulerManager_ == nullptr, DP_NULL_POINTER, "SchedulerManager is nullptr.");

    controller_ = schedulerManager_->GetVideoController(userId_);
    DP_CHECK_ERROR_RETURN_RET_LOG(controller_ == nullptr, DP_NULL_POINTER, "VideoController is nullptr.");
    initialized_.store(true);
    return DP_OK;
}

VideoProcessSuccessCommand::VideoProcessSuccessCommand(const int32_t userId, const DeferredVideoWorkPtr& work)
    : VideoProcessCommand(userId),
      work_(work)
{
    DP_DEBUG_LOG("entered.");
}

VideoProcessSuccessCommand::~VideoProcessSuccessCommand()
{
    DP_DEBUG_LOG("entered.");
    work_ = nullptr;
}

int32_t VideoProcessSuccessCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }

    controller_->HandleSuccess(userId_, work_);
    return DP_OK;
}

VideoProcessFailedCommand::VideoProcessFailedCommand(const int32_t userId,
    const DeferredVideoWorkPtr& work, DpsError errorCode)
    : VideoProcessCommand(userId),
      work_(work),
      error_(errorCode)
{
    DP_DEBUG_LOG("entered.");
}

VideoProcessFailedCommand::~VideoProcessFailedCommand()
{
    DP_DEBUG_LOG("entered.");
    work_ = nullptr;
}

int32_t VideoProcessFailedCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }

    controller_->HandleError(userId_, work_, error_);
    return DP_OK;
}

int32_t VideoStateChangedCommand::Executing()
{
    return DP_OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS