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

#include "background_strategy.h"

#include "dp_log.h"
#include "dp_utils.h"

namespace OHOS {
namespace CameraStandard {

namespace {
    constexpr int32_t DURATIONMS_25_SEC = 25 * 1000;
}

namespace DeferredProcessing {
BackgroundStrategy::BackgroundStrategy(const std::shared_ptr<PhotoJobRepository>& repository)
    : repository_(repository)
{
    DP_DEBUG_LOG("entered");
}

BackgroundStrategy::~BackgroundStrategy()
{
    DP_DEBUG_LOG("entered");
}

DeferredPhotoWorkPtr BackgroundStrategy::GetWork()
{
    DP_DEBUG_LOG("entered");
    ExecutionMode mode = GetExecutionMode();
    if (mode == ExecutionMode::DUMMY) {
        return nullptr;
    }
    DeferredPhotoJobPtr jobPtr = GetJob();
    if (jobPtr == nullptr) {
        return nullptr;
    }
    return std::make_shared<DeferredPhotoWork>(jobPtr, mode);
}

DeferredPhotoJobPtr BackgroundStrategy::GetJob()
{
    DP_DEBUG_LOG("entered");
    DeferredPhotoJobPtr jobPtr = nullptr;
    jobPtr = repository_->GetNormalPriorityJob();
    if (jobPtr == nullptr) {
        jobPtr = repository_->GetLowPriorityJob();
    }
    return jobPtr;
}

ExecutionMode BackgroundStrategy::GetExecutionMode()
{
    DP_DEBUG_LOG("entered");
    if (cameraSessionStatus_ == CameraSessionStatus::SYSTEM_CAMERA_OPEN
        || cameraSessionStatus_ == CameraSessionStatus::NORMAL_CAMERA_OPEN
        || !(hdiStatus_ == HdiStatus::HDI_READY || hdiStatus_ == HdiStatus::HDI_READY_SPACE_LIMIT_REACHED)
        || mediaLibraryStatus_ != MediaLibraryStatus::MEDIA_LIBRARY_AVAILABLE) {
        DP_INFO_LOG("DPS_PHOTO: cameraStatus: %{public}d, hdiStatus: %{public}d, mediaStatus: %{public}d",
            cameraSessionStatus_, hdiStatus_, mediaLibraryStatus_);
        return ExecutionMode::DUMMY;
    }
    FlashTrailingState();
    DP_INFO_LOG("DPS_PHOTO: isInTrailing: %{public}d", isInTrailing_);
    if (isInTrailing_) {
        return ExecutionMode::LOAD_BALANCE;
    }
    DP_INFO_LOG("DPS_PHOTO: systemPressureLevel: %{public}d", systemPressureLevel_);
    if (systemPressureLevel_ == SystemPressureLevel::NOMINAL) {
        return ExecutionMode::LOAD_BALANCE;
    }
    return ExecutionMode::DUMMY;
}

HdiStatus BackgroundStrategy::GetHdiStatus()
{
    DP_INFO_LOG("hdiStatus_: %{public}d", hdiStatus_);
    return hdiStatus_;
}

void BackgroundStrategy::NotifyPressureLevelChanged(SystemPressureLevel level)
{
    DP_INFO_LOG("previous system pressure level: %{public}d, new level: %{public}d", systemPressureLevel_, level);
    systemPressureLevel_ = level;
}

void BackgroundStrategy::NotifyHdiStatusChanged(HdiStatus status)
{
    DP_INFO_LOG("previous hdi status %{public}d, new status: %{public}d", hdiStatus_, status);
    hdiStatus_ = status;
}

void BackgroundStrategy::NotifyMediaLibStatusChanged(MediaLibraryStatus status)
{
    DP_INFO_LOG("previous media lib status %{public}d, new status: %{public}d", mediaLibraryStatus_, status);
    mediaLibraryStatus_ = status;
}

void BackgroundStrategy::NotifyCameraStatusChanged(CameraSessionStatus status)
{
    DP_INFO_LOG("previous camera session status %{public}d, new status: %{public}d", cameraSessionStatus_, status);
    cameraSessionStatus_ = status;
    switch (status) {
        case CameraSessionStatus::SYSTEM_CAMERA_CLOSED:
            StartTrailing(DURATIONMS_25_SEC);
            break;
        case CameraSessionStatus::NORMAL_CAMERA_CLOSED:
            StartTrailing(0);
            break;
        case CameraSessionStatus::SYSTEM_CAMERA_OPEN:
        case CameraSessionStatus::NORMAL_CAMERA_OPEN:
            StopTrailing();
            break;
        default:
            break;
    }
}

void BackgroundStrategy::StartTrailing(uint64_t duration)
{
    DP_INFO_LOG("entered, is in trailing: %{public}d", isInTrailing_);
    if (duration <= 0) {
        return;
    }
    if (isInTrailing_) {
        auto passedTime = GetTimestampMilli() - trailingStartTimeStamp_;
        if (passedTime >= remainingTrailingTime_) {
            remainingTrailingTime_ = 0;
        } else {
            remainingTrailingTime_ = remainingTrailingTime_ - passedTime;
        }
    }
    remainingTrailingTime_ = duration > remainingTrailingTime_ ? duration : remainingTrailingTime_;
    trailingStartTimeStamp_ = GetTimestampMilli();
    isInTrailing_ = true;
}

void BackgroundStrategy::StopTrailing()
{
    DP_INFO_LOG("entered, is in trailing: %{public}d", isInTrailing_);
    if (isInTrailing_) {
        auto passedTime = GetTimestampMilli() - trailingStartTimeStamp_;
        if (passedTime >= remainingTrailingTime_) {
            remainingTrailingTime_ = 0;
        } else {
            remainingTrailingTime_ = remainingTrailingTime_ - passedTime;
        }
        isInTrailing_ = false;
    }
}

void BackgroundStrategy::FlashTrailingState()
{
    DP_INFO_LOG("entered, is in trailing: %{public}d", isInTrailing_);
    if (isInTrailing_) {
        auto passedTime = GetTimestampMilli() - trailingStartTimeStamp_;
        if (passedTime >= remainingTrailingTime_) {
            remainingTrailingTime_ = 0;
            isInTrailing_ = false;
        }
    }
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS