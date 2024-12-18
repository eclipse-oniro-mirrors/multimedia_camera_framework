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

#include "photo_process_command.h"

#include "basic_definitions.h"
#include "dp_utils.h"
#include "dps.h"
#include <utility>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
PhotoProcessCommand::PhotoProcessCommand(const int32_t userId) : userId_(userId)
{
    DP_DEBUG_LOG("entered. userId: %{public}d", userId_);
}

PhotoProcessCommand::~PhotoProcessCommand()
{
    DP_DEBUG_LOG("entered.");
}

int32_t PhotoProcessCommand::Initialize()
{
    DP_CHECK_RETURN_RET(initialized_.load(), DP_OK);
    auto schedulerManager = DPS_GetSchedulerManager();
    DP_CHECK_ERROR_RETURN_RET_LOG(schedulerManager == nullptr, DP_NULL_POINTER, "SchedulerManager is nullptr.");

    postProcessor_ = schedulerManager->GetPhotoPostProcessor(userId_);
    DP_CHECK_ERROR_RETURN_RET_LOG(postProcessor_ == nullptr, DP_NULL_POINTER, "PhotoPostProcessor is nullptr.");
    
    initialized_.store(true);
    return DP_OK;
}

PhotoProcessSuccessCommand::PhotoProcessSuccessCommand(const int32_t userId, const std::string& imageId,
    const std::shared_ptr<BufferInfo>& bufferInfo)
    : PhotoProcessCommand(userId), imageId_(imageId), bufferInfo_(bufferInfo)
{
    DP_DEBUG_LOG("entered.");
}

int32_t PhotoProcessSuccessCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }

    postProcessor_->OnProcessDone(imageId_, bufferInfo_);
    return DP_OK;
}

PhotoProcessSuccessExtCommand::PhotoProcessSuccessExtCommand(const int32_t userId, const std::string& imageId,
    const std::shared_ptr<BufferInfoExt>& bufferInfo)
    : PhotoProcessCommand(userId), imageId_(imageId), bufferInfo_(bufferInfo)
{
    DP_DEBUG_LOG("entered.");
}

int32_t PhotoProcessSuccessExtCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }

    postProcessor_->OnProcessDoneExt(imageId_, bufferInfo_);
    return DP_OK;
}

PhotoProcessFailedCommand::PhotoProcessFailedCommand(const int32_t userId,
    const std::string& imageId, DpsError errorCode)
    : PhotoProcessCommand(userId), imageId_(imageId), error_(errorCode)
{
    DP_DEBUG_LOG("entered.");
}

int32_t PhotoProcessFailedCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }

    postProcessor_->OnError(imageId_, error_);
    return DP_OK;
}

int32_t PhotoStateChangedCommand::Executing()
{
    postProcessor_->OnStateChanged(status_);
    return DP_OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS