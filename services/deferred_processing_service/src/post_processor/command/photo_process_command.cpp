/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "photo_process_command.h"

#include "dp_utils.h"
#include "dps.h"

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
    photoProcessor_ = schedulerManager->GetPhotoProcessor(userId_);
    DP_CHECK_ERROR_RETURN_RET_LOG(photoProcessor_ == nullptr, DP_NULL_POINTER, "DeferredPhotoProcessor is nullptr.");
    initialized_.store(true);
    return DP_OK;
}

PhotoProcessSuccessCommand::PhotoProcessSuccessCommand(const int32_t userId, const std::string& imageId,
    std::unique_ptr<ImageInfo> imageInfo)
    : PhotoProcessCommand(userId), imageId_(imageId), imageInfo_(std::move(imageInfo))
{
    DP_DEBUG_LOG("entered.");
}

int32_t PhotoProcessSuccessCommand::Executing()
{
    int32_t ret = Initialize();
    DP_CHECK_RETURN_RET(ret != DP_OK, ret);

    photoProcessor_->OnProcessSuccess(userId_, imageId_, std::move(imageInfo_));
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
    int32_t ret = Initialize();
    DP_CHECK_RETURN_RET(ret != DP_OK, ret);

    photoProcessor_->OnProcessError(userId_, imageId_, error_);
    return DP_OK;
}

int32_t PhotoProcessTimeOutCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }

    photoProcessor_->OnProcessError(userId_, imageId_, error_);
    return DP_OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP