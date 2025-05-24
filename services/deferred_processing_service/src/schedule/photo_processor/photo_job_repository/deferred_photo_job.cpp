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

#include "deferred_photo_job.h"

#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
void PhotoState::OnStateEntered()
{
    auto listener = listener_.lock();
    DP_CHECK_ERROR_RETURN_LOG(listener == nullptr, "Joblistener is nullptr.");
    listener->TryDoNextJob(imageId_, true);
}

void AddState::OnStateEntered()
{
    DP_DEBUG_LOG("entered.");
}

void AddState::OnStateExited()
{
    auto listener = listener_.lock();
    DP_CHECK_ERROR_RETURN_LOG(listener == nullptr, "Joblistener is nullptr.");
    listener->UpdateJobSize();
}

void PendingState::OnStateEntered()
{
    DP_DEBUG_LOG("entered.");
}

void RunningState::OnStateEntered()
{
    auto listener = listener_.lock();
    DP_CHECK_ERROR_RETURN_LOG(listener == nullptr, "Joblistener is nullptr.");
    listener->UpdateRunningJob(imageId_, true);
    listener->TryDoNextJob(imageId_, false);
}

void RunningState::OnStateExited()
{
    auto listener = listener_.lock();
    DP_CHECK_ERROR_RETURN_LOG(listener == nullptr, "Joblistener is nullptr.");
    listener->UpdateRunningJob(imageId_, false);
}

void DeleteState::OnStateEntered()
{
    auto listener = listener_.lock();
    DP_CHECK_ERROR_RETURN_LOG(listener == nullptr, "Joblistener is nullptr.");
    listener->UpdateJobSize();
}

DeferredPhotoJob::DeferredPhotoJob(const std::string& imageId, const PhotoJobType photoJobType, const bool discardable,
    const std::weak_ptr<IJobStateChangeListener>& jobChangeListener)
    : imageId_(imageId), photoJobType_(photoJobType), discardable_(discardable),
      createTime_(GetSteadyNow()), jobChangeListener_(jobChangeListener)
{
    DP_DEBUG_LOG("entered.");
    add_ = std::make_shared<AddState>(imageId, jobChangeListener_);
    pending_ = std::make_shared<PendingState>(imageId, jobChangeListener_);
    failed_ = std::make_shared<FailedState>(imageId, jobChangeListener_);
    running_ = std::make_shared<RunningState>(imageId, jobChangeListener_);
    completed_ = std::make_shared<CompletedState>(imageId, jobChangeListener_);
    error_ = std::make_shared<ErrorState>(imageId, jobChangeListener_);
    delete_ = std::make_shared<DeleteState>(imageId, jobChangeListener_);
    ChangeStateTo(add_);
    SetJobPriority(JobPriority::NORMAL);
}

bool DeferredPhotoJob::Prepare()
{
    ChangeStateTo(pending_);
    return true;
}

bool DeferredPhotoJob::Start(uint32_t timerId)
{
    timerId_ = timerId;
    ChangeStateTo(running_);
    RecordJobRunningPriority();
    return true;
}
bool DeferredPhotoJob::Complete()
{
    ResetTimer();
    ChangeStateTo(completed_);
    return true;
}

bool DeferredPhotoJob::Fail()
{
    SetJobPriority(JobPriority::NORMAL);
    ResetTimer();
    ChangeStateTo(failed_);
    return true;
}

bool DeferredPhotoJob::Error()
{
    SetJobPriority(JobPriority::NORMAL);
    ResetTimer();
    ChangeStateTo(error_);
    return true;
}

bool DeferredPhotoJob::Delete()
{
    SetJobPriority(JobPriority::NONE);
    ResetTimer();
    ChangeStateTo(delete_);
    return true;
}

bool DeferredPhotoJob::SetJobPriority(JobPriority priority)
{
    DP_INFO_LOG("imageId: %{public}s, current priority: %{public}d, priority to set: %{public}d",
        imageId_.c_str(), priority_, priority);
    DP_CHECK_EXECUTE(priority == JobPriority::HIGH, UpdateTime());
    DP_CHECK_RETURN_RET(priority_ == priority, false);
    auto listener = jobChangeListener_.lock();
    DP_CHECK_ERROR_RETURN_RET_LOG(listener == nullptr, true, "Joblistener is nullptr.");
    listener->UpdatePriorityJob(priority, priority_);
    priority_ = priority;
    return true;
}

void DeferredPhotoJob::SetExecutionMode(ExecutionMode mode)
{
    DP_DEBUG_LOG("imageId: %{public}s, ExecutionMode to set: %{public}d", imageId_.c_str(), mode);
    executionMode_ = mode;
}

void DeferredPhotoJob::UpdateTime()
{
    createTime_ = GetSteadyNow();
}

void DeferredPhotoJob::RecordJobRunningPriority()
{
    DP_DEBUG_LOG("imageId: %{public}s, current priority: %{public}d, running priority: %{public}d",
        imageId_.c_str(), priority_, runningPriority_);
    runningPriority_ = priority_;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS