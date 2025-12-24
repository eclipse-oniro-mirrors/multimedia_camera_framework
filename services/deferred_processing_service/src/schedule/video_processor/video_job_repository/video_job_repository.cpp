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

#include "video_job_repository.h"
#include "dp_log.h"
#include "dps.h"
#include "notify_video_job_command.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
VideoJobRepository::VideoJobRepository(const int32_t userId) : userId_(userId)
{
    DP_DEBUG_LOG("entered, userid: %{public}d", userId_);
}

VideoJobRepository::~VideoJobRepository()
{
    DP_INFO_LOG("entered, userid: %{public}d", userId_);
    ClearCatch();
}

int32_t VideoJobRepository::Initialize()
{
    jobQueue_ = std::make_unique<VideoJobQueue>(
        [] (const DeferredVideoJobPtr& a, const DeferredVideoJobPtr& b) {return *a > *b;});
    return DP_OK;
}

void VideoJobRepository::AddVideoJob(const std::string& videoId, const std::shared_ptr<VideoInfo>& info)
{
    // LCOV_EXCL_START
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    DP_CHECK_RETURN_LOG(jobPtrFind != nullptr, "already existed, videoId: %{public}s", videoId.c_str());
    DP_CHECK_RETURN_LOG(info == nullptr, "invailid videoId: %{public}s", videoId.c_str());
    DeferredVideoJobPtr jobPtr = std::make_shared<DeferredVideoJob>(
        videoId, info->srcFd_, info->dstFd_, info->movieFd_, info->movieCopyFd_);
    jobPtr->SetJobState(VideoJobState::PENDING);
    jobQueue_->Push(jobPtr);
    DP_INFO_LOG("DPS_VIDEO: AddVideoJob size: %{public}d, videoId: %{public}s",
        static_cast<int>(jobQueue_->GetSize()), videoId.c_str());
    // LCOV_EXCL_STOP
}

bool VideoJobRepository::RemoveVideoJob(const std::string& videoId, bool restorable)
{
    // LCOV_EXCL_START
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    bool isNeedStop = false;
    DP_CHECK_RETURN_RET_LOG(jobPtrFind == nullptr, isNeedStop,
        "Does not existed, videoId: %{public}s", videoId.c_str());
    DP_INFO_LOG("DPS_VIDEO: RemoveVideoJob videoId: %{public}s, restorable: %{public}d", videoId.c_str(), restorable);

    isNeedStop = jobPtrFind->GetCurStatus() == VideoJobState::RUNNING;
    if (!restorable) {
        jobQueue_->Remove(jobPtrFind);
        DP_INFO_LOG("DPS_VIDEO: job size: %{public}d, videoId: %{public}s",
            static_cast<int>(jobQueue_->GetSize()), videoId.c_str());
    }
    jobPtrFind->SetJobState(VideoJobState::DELETED);
    jobPtrFind->SetJobPriority(JobPriority::NORMAL);
    UpdateRunningCountUnLocked(false, jobPtrFind);
    return isNeedStop;
    // LCOV_EXCL_STOP
}

void VideoJobRepository::RestoreVideoJob(const std::string& videoId)
{
    // LCOV_EXCL_START
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    DP_CHECK_RETURN_LOG(jobPtrFind == nullptr, "Does not existed, videoId: %{public}s", videoId.c_str());
    DP_INFO_LOG("DPS_VIDEO: RestoreVideoJob videoId: %{public}s", videoId.c_str());

    bool statusChanged = jobPtrFind->SetJobState(VideoJobState::PENDING);
    DP_CHECK_EXECUTE(statusChanged, jobQueue_->Update(jobPtrFind));
    // LCOV_EXCL_STOP
}

bool VideoJobRepository::RequestJob(const std::string& videoId)
{
    // LCOV_EXCL_START
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    DP_CHECK_ERROR_RETURN_RET_LOG(jobPtrFind == nullptr, false,
        "Does not existed, videoId: %{public}s", videoId.c_str());
    DP_INFO_LOG("DPS_VIDEO: RequestJob videoId: %{public}s", videoId.c_str());
    jobPtrFind->SetJobPriority(JobPriority::HIGH);
    if (jobPtrFind->GetCurStatus() == VideoJobState::FAILED) {
        DP_INFO_LOG("Failed to Pending, videoId: %{public}s", videoId.c_str());
        jobPtrFind->SetJobState(VideoJobState::PENDING);
    }
    jobQueue_->Update(jobPtrFind);
    NotifyJobChangedUnLocked(videoId);
    return true;
    // LCOV_EXCL_STOP
}

void VideoJobRepository::CancelJob(const std::string& videoId)
{
    // LCOV_EXCL_START
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    DP_CHECK_ERROR_RETURN_LOG(jobPtrFind == nullptr, "Does not existed, videoId: %{public}s", videoId.c_str());
    DP_INFO_LOG("DPS_VIDEO: CancelJob videoId: %{public}s", videoId.c_str());
    bool changed = jobPtrFind->SetJobPriority(JobPriority::NORMAL);
    DP_CHECK_EXECUTE(changed, jobQueue_->Update(jobPtrFind));
    // LCOV_EXCL_STOP
}

void VideoJobRepository::SetJobPending(const std::string& videoId)
{
    // LCOV_EXCL_START
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    DP_CHECK_RETURN_LOG(jobPtrFind == nullptr, "Does not existed, videoId: %{public}s", videoId.c_str());
    DP_INFO_LOG("DPS_VIDEO: SetJobPending videoId: %{public}s", videoId.c_str());

    bool statusChanged = jobPtrFind->SetJobState(VideoJobState::PENDING);
    UpdateRunningCountUnLocked(statusChanged, jobPtrFind);
    NotifyJobChangedUnLocked(videoId);
    // LCOV_EXCL_STOP
}

void VideoJobRepository::SetJobRunning(const std::string& videoId)
{
    // LCOV_EXCL_START
    DP_INFO_LOG("DPS_VIDEO: SetJobRunning videoId: %{public}s", videoId.c_str());
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    DP_CHECK_RETURN_LOG(jobPtrFind == nullptr, "Does not existed, videoId: %{public}s", videoId.c_str());

    bool statusChanged = jobPtrFind->SetJobState(VideoJobState::RUNNING);
    UpdateRunningCountUnLocked(statusChanged, jobPtrFind);
    // LCOV_EXCL_STOP
}

void VideoJobRepository::SetJobCompleted(const std::string& videoId)
{
    // LCOV_EXCL_START
    DP_INFO_LOG("DPS_VIDEO: SetJobCompleted videoId: %{public}s", videoId.c_str());
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    DP_CHECK_RETURN_LOG(jobPtrFind == nullptr, "Does not existed, videoId: %{public}s", videoId.c_str());

    bool statusChanged = jobPtrFind->SetJobState(VideoJobState::COMPLETED);
    UpdateRunningCountUnLocked(statusChanged, jobPtrFind);
    NotifyJobChangedUnLocked(videoId);
    // LCOV_EXCL_STOP
}

void VideoJobRepository::SetJobFailed(const std::string& videoId)
{
    // LCOV_EXCL_START
    DP_INFO_LOG("DPS_VIDEO: SetJobFailed videoId: %{public}s", videoId.c_str());
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    DP_CHECK_RETURN_LOG(jobPtrFind == nullptr, "Does not existed, videoId: %{public}s", videoId.c_str());

    bool statusChanged = jobPtrFind->SetJobState(VideoJobState::FAILED);
    UpdateRunningCountUnLocked(statusChanged, jobPtrFind);
    NotifyJobChangedUnLocked(videoId);
    // LCOV_EXCL_STOP
}

void VideoJobRepository::SetJobPause(const std::string& videoId)
{
    // LCOV_EXCL_START
    DP_INFO_LOG("DPS_VIDEO: SetJobPause videoId: %{public}s", videoId.c_str());
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    DP_CHECK_RETURN_LOG(jobPtrFind == nullptr, "Does not existed, videoId: %{public}s", videoId.c_str());

    bool statusChanged = jobPtrFind->SetJobState(VideoJobState::PAUSE);
    UpdateRunningCountUnLocked(statusChanged, jobPtrFind);
    // LCOV_EXCL_STOP
}

void VideoJobRepository::SetJobError(const std::string& videoId)
{
    // LCOV_EXCL_START
    DP_INFO_LOG("DPS_VIDEO: SetJobError videoId: %{public}s", videoId.c_str());
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    DP_CHECK_RETURN_LOG(jobPtrFind == nullptr, "Does not existed, videoId: %{public}s", videoId.c_str());

    bool statusChanged = jobPtrFind->SetJobState(VideoJobState::ERROR);
    UpdateRunningCountUnLocked(statusChanged, jobPtrFind);
    NotifyJobChangedUnLocked(videoId);
    // LCOV_EXCL_STOP
}

DeferredVideoJobPtr VideoJobRepository::GetJob()
{
    // LCOV_EXCL_START
    DP_INFO_LOG("DPS_VIDEO: Video job size: %{public}d, running num: %{public}d",
        jobQueue_->GetSize(), static_cast<int32_t>(runningSet_.size()));
    auto jobPtr = jobQueue_->Peek();
    DP_CHECK_RETURN_RET(jobPtr == nullptr || jobPtr->GetCurStatus() >= VideoJobState::RUNNING, nullptr);

    if (jobPtr->GetCurStatus() == VideoJobState::FAILED) {
        jobPtr->SetJobState(VideoJobState::PENDING);
        jobQueue_->Update(jobPtr);
    }
    return jobPtr;
    // LCOV_EXCL_STOP
}

uint32_t VideoJobRepository::GetJobTimerId(const std::string& videoId)
{
    // LCOV_EXCL_START
    DeferredVideoJobPtr jobPtr = GetJobUnLocked(videoId);
    DP_CHECK_RETURN_RET(jobPtr == nullptr, INVALID_TIMERID);
    return jobPtr->GetTimerId();
    // LCOV_EXCL_STOP
}

void VideoJobRepository::GetRunningJobList(std::vector<std::string>& list)
{
    // LCOV_EXCL_START
    DP_DEBUG_LOG("Video running jobs num: %{public}d", static_cast<int32_t>(runningSet_.size()));
    list.clear();
    list.reserve(runningSet_.size());
    std::copy(runningSet_.begin(), runningSet_.end(), std::back_inserter(list));
    // LCOV_EXCL_STOP
}

bool VideoJobRepository::HasRunningJob()
{
    return !runningSet_.empty();
}

bool VideoJobRepository::IsHighJob(const std::string& videoId)
{
    DeferredVideoJobPtr jobPtr = GetJobUnLocked(videoId);
    DP_CHECK_RETURN_RET(jobPtr == nullptr, false);

    return jobPtr->GetCurPriority() ==  JobPriority::HIGH;
}

bool VideoJobRepository::IsRunningJob(const std::string& videoId)
{
    return runningSet_.find(videoId) != runningSet_.end();
}

bool VideoJobRepository::IsNeedStopJob()
{
    bool stopRunningJob = false;
    if (!runningSet_.empty()) {
        auto it = runningSet_.begin();
        DP_CHECK_EXECUTE(!IsHighJob(*it), stopRunningJob = true);
    }
    return stopRunningJob;
}

DeferredVideoJobPtr VideoJobRepository::GetJobUnLocked(const std::string& videoId)
{
    // LCOV_EXCL_START
    auto jobPtr = jobQueue_->GetJobById(videoId);
    if (jobPtr) {
        DP_DEBUG_LOG("video job videoId: %{public}s", videoId.c_str());
        return jobPtr;
    }
    return nullptr;
    // LCOV_EXCL_STOP
}

void VideoJobRepository::NotifyJobChangedUnLocked(const std::string& videoId)
{
    // LCOV_EXCL_START
    DP_INFO_LOG("DPS_VIDEO: NotifyJobChanged videoId: %{public}s", videoId.c_str());
    auto ret = DPS_SendCommand<NotifyVideoJobChangedCommand>(userId_);
    DP_CHECK_ERROR_RETURN_LOG(ret != DP_OK, "NotifyJobChanged failed, ret: %{public}d", ret);
    // LCOV_EXCL_STOP
}

// LCOV_EXCL_START
void VideoJobRepository::UpdateRunningCountUnLocked(bool statusChanged, const DeferredVideoJobPtr& jobPtr)
{
    DP_CHECK_EXECUTE(statusChanged, jobQueue_->Update(jobPtr));

    if (statusChanged && (jobPtr->GetPreStatus() == VideoJobState::RUNNING)) {
        runningSet_.erase(jobPtr->GetVideoId());
    }
    if (statusChanged && (jobPtr->GetCurStatus() == VideoJobState::RUNNING)) {
        runningSet_.emplace(jobPtr->GetVideoId());
    }
    DP_INFO_LOG("DPS_VIDEO: Video running jobs num: %{public}d, videoId: %{public}s",
        static_cast<int32_t>(runningSet_.size()), jobPtr->GetVideoId().c_str());
}
// LCOV_EXCL_STOP

void VideoJobRepository::ClearCatch()
{
    DP_CHECK_EXECUTE(jobQueue_, jobQueue_->Clear());
    runningSet_.clear();
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS