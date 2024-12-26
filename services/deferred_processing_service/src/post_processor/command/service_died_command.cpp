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

#include "service_died_command.h"

#include "basic_definitions.h"
#include "dps.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

ServiceDiedCommand::ServiceDiedCommand(const int32_t userId) : userId_(userId)
{
    DP_DEBUG_LOG("entered.");
}

int32_t ServiceDiedCommand::Initialize()
{
    DP_CHECK_RETURN_RET(initialized_.load(), DP_OK);
    schedulerManager_ = DPS_GetSchedulerManager();
    DP_CHECK_ERROR_RETURN_RET_LOG(schedulerManager_ == nullptr, DP_NULL_POINTER, "SchedulerManager is nullptr.");

    initialized_.store(true);
    return DP_OK;
}

int32_t PhotoDiedCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }

    auto photoPost = schedulerManager_->GetPhotoPostProcessor(userId_);
    DP_CHECK_ERROR_RETURN_RET_LOG(photoPost == nullptr, DP_NULL_POINTER, "PhotoPostProcessor is nullptr.");
    photoPost->OnSessionDied();
    return DP_OK;
}

int32_t VideoDiedCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }

    auto videoPost = schedulerManager_->GetVideoPostProcessor(userId_);
    DP_CHECK_ERROR_RETURN_RET_LOG(videoPost == nullptr, DP_NULL_POINTER, "VideoPostProcessor is nullptr.");
    videoPost->OnSessionDied();

    auto controller = schedulerManager_->GetVideoController(userId_);
    DP_CHECK_ERROR_RETURN_RET_LOG(controller == nullptr, DP_NULL_POINTER, "VideoController is nullptr.");

    controller->HandleServiceDied();
    return DP_OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS