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
#include <vector>
#include <shared_mutex>
#include <iostream>

#include "user_initiated_strategy.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
UserInitiatedStrategy::UserInitiatedStrategy(std::shared_ptr<PhotoJobRepository> photoJobRepository)
    : photoJobRepository_(photoJobRepository)
{
    DP_DEBUG_LOG("entered");
}

UserInitiatedStrategy::~UserInitiatedStrategy()
{
    DP_DEBUG_LOG("entered");
    photoJobRepository_ = nullptr;
}

DeferredPhotoWorkPtr UserInitiatedStrategy::GetWork()
{
    DP_INFO_LOG("entered");
    DeferredPhotoJobPtr jobPtr = GetJob();
    ExecutionMode mode = GetExecutionMode();
    if ((jobPtr != nullptr) && (mode != ExecutionMode::DUMMY)) {
        return std::make_shared<DeferredPhotoWork>(jobPtr, mode);
    }
    return nullptr;
}

DeferredPhotoJobPtr UserInitiatedStrategy::GetJob()
{
    return photoJobRepository_->GetHighPriorityJob();
}

ExecutionMode UserInitiatedStrategy::GetExecutionMode()
{
    if (cameraSessionStatus_ == CameraSessionStatus::SYSTEM_CAMERA_OPEN
        || cameraSessionStatus_ == CameraSessionStatus::NORMAL_CAMERA_OPEN
        || !(hdiStatus_ == HdiStatus::HDI_READY || hdiStatus_ == HdiStatus::HDI_READY_SPACE_LIMIT_REACHED)
        || mediaLibraryStatus_ != MediaLibraryStatus::MEDIA_LIBRARY_AVAILABLE) {
        DP_INFO_LOG("cameraSessionStatus_: %{public}d, hdiStatus_: %{public}d, mediaLibraryStatus_: %{public}d, ",
            cameraSessionStatus_, hdiStatus_, mediaLibraryStatus_);
        return ExecutionMode::DUMMY;
    }

    return ExecutionMode::HIGH_PERFORMANCE;
}

void UserInitiatedStrategy::NotifyHdiStatusChanged(HdiStatus status)
{
    DP_INFO_LOG("previous hdi status %{public}d, new status: %{public}d", hdiStatus_, status);
    hdiStatus_ = status;
}

void UserInitiatedStrategy::NotifyMediaLibStatusChanged(MediaLibraryStatus status)
{
    DP_INFO_LOG("previous media lib status %{public}d, new status: %{public}d", mediaLibraryStatus_, status);
    mediaLibraryStatus_ = status;
}

void UserInitiatedStrategy::NotifyCameraStatusChanged(CameraSessionStatus status)
{
    DP_INFO_LOG("previous camera session status %{public}d, new status: %{public}d", cameraSessionStatus_, status);
    cameraSessionStatus_ = status;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS