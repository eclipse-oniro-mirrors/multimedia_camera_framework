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

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
VideoJobRepository::VideoJobRepository(const int32_t userId) : userId_(userId)
{
    DP_DEBUG_LOG("entered, userid: %{public}d", userId_);
    jobQueue_ = std::make_shared<VideoJobQueue>([] (DeferredVideoJobPtr a, DeferredVideoJobPtr b) {return *a > *b;});
}

VideoJobRepository::~VideoJobRepository()
{
    DP_DEBUG_LOG("entered, userid: %{public}d", userId_);
    ClearCatch();
}

void VideoJobRepository::AddVideoJob(const std::string& videoId,
    const sptr<IPCFileDescriptor>& srcFd, const sptr<IPCFileDescriptor>& dstFd)
{
    DP_INFO_LOG("DPS_VIDEO: AddVideoJob videoId: %{public}s", videoId.c_str());
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    DP_CHECK_RETURN_LOG(jobPtrFind != nullptr, "already existed, videoId: %{public}s", videoId.c_str());

    DeferredVideoJobPtr jobPtr = std::make_shared<DeferredVideoJob>(videoId, srcFd, dstFd);
    jobPtr->SetJobStatus(VideoJobStatus::PENDING);
    jobMap_.emplace(videoId, jobPtr);
    jobQueue_->Push(jobPtr);
    DP_INFO_LOG("DPS_VIDEO: Add video job size: %{public}d, videoId: %{public}s, srcFd: %{public}d",
        static_cast<int>(jobQueue_->GetSize()), videoId.c_str(), srcFd->GetFd());
}

bool VideoJobRepository::RemoveVideoJob(const std::string& videoId, bool restorable)
{
    DP_INFO_LOG("DPS_VIDEO: RemoveVideoJob videoId: %{public}s, restorable: %{public}d", videoId.c_str(), restorable);
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    bool isNeedStop = false;
    DP_CHECK_RETURN_RET_LOG(jobPtrFind == nullptr, isNeedStop,
        "does not existed, videoId: %{public}s", videoId.c_str());

    isNeedStop = jobPtrFind->GetCurStatus() == VideoJobStatus::RUNNING;
    if (!restorable) {
        jobMap_.erase(videoId);
        jobQueue_->Remove(jobPtrFind);
        DP_INFO_LOG("DPS_VIDEO: Remove video job size: %{public}d, videoId: %{public}s",
            static_cast<int>(jobQueue_->GetSize()), videoId.c_str());
    }
    bool statusChanged = jobPtrFind->SetJobStatus(VideoJobStatus::DELETED);
    UpdateRunningCountUnLocked(statusChanged, jobPtrFind);
    return isNeedStop;
}

void VideoJobRepository::RestoreVideoJob(const std::string& videoId)
{
    DP_INFO_LOG("DPS_VIDEO: RestoreVideoJob videoId: %{public}s", videoId.c_str());
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    DP_CHECK_RETURN_LOG(jobPtrFind == nullptr, "does not existed, videoId: %{public}s", videoId.c_str());

    bool statusChanged = jobPtrFind->SetJobStatus(VideoJobStatus::PENDING);
    DP_CHECK_EXECUTE(statusChanged, jobQueue_->Update(jobPtrFind));
}

void VideoJobRepository::SetJobPending(const std::string& videoId)
{
    DP_INFO_LOG("DPS_VIDEO: SetJobPending videoId: %{public}s", videoId.c_str());
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    DP_CHECK_RETURN_LOG(jobPtrFind == nullptr, "does not existed, videoId: %{public}s", videoId.c_str());

    bool statusChanged = jobPtrFind->SetJobStatus(VideoJobStatus::PENDING);
    UpdateRunningCountUnLocked(statusChanged, jobPtrFind);
    NotifyJobChangedUnLocked(statusChanged, jobPtrFind);
}

void VideoJobRepository::SetJobRunning(const std::string& videoId)
{
    DP_INFO_LOG("DPS_VIDEO: SetJobRunning videoId: %{public}s", videoId.c_str());
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    DP_CHECK_RETURN_LOG(jobPtrFind == nullptr, "does not existed, videoId: %{public}s", videoId.c_str());

    bool statusChanged = jobPtrFind->SetJobStatus(VideoJobStatus::RUNNING);
    UpdateRunningCountUnLocked(statusChanged, jobPtrFind);
}

void VideoJobRepository::SetJobCompleted(const std::string& videoId)
{
    DP_INFO_LOG("DPS_VIDEO: SetJobCompleted videoId: %{public}s", videoId.c_str());
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    DP_CHECK_RETURN_LOG(jobPtrFind == nullptr, "does not existed, videoId: %{public}s", videoId.c_str());

    bool statusChanged = jobPtrFind->SetJobStatus(VideoJobStatus::COMPLETED);
    UpdateRunningCountUnLocked(statusChanged, jobPtrFind);
    NotifyJobChangedUnLocked(statusChanged, jobPtrFind);
}

void VideoJobRepository::SetJobFailed(const std::string& videoId)
{
    DP_INFO_LOG("DPS_VIDEO: SetJobFailed videoId: %{public}s", videoId.c_str());
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    DP_CHECK_RETURN_LOG(jobPtrFind == nullptr, "does not existed, videoId: %{public}s", videoId.c_str());

    bool statusChanged = jobPtrFind->SetJobStatus(VideoJobStatus::FAILED);
    UpdateRunningCountUnLocked(statusChanged, jobPtrFind);
    NotifyJobChangedUnLocked(statusChanged, jobPtrFind);
}

void VideoJobRepository::SetJobPause(const std::string& videoId)
{
    DP_INFO_LOG("DPS_VIDEO: SetJobPause videoId: %{public}s", videoId.c_str());
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    DP_CHECK_RETURN_LOG(jobPtrFind == nullptr, "does not existed, videoId: %{public}s", videoId.c_str());

    bool statusChanged = jobPtrFind->SetJobStatus(VideoJobStatus::PAUSE);
    UpdateRunningCountUnLocked(statusChanged, jobPtrFind);
}

void VideoJobRepository::SetJobError(const std::string& videoId)
{
    DP_INFO_LOG("DPS_VIDEO: SetJobError videoId: %{public}s", videoId.c_str());
    DeferredVideoJobPtr jobPtrFind = GetJobUnLocked(videoId);
    DP_CHECK_RETURN_LOG(jobPtrFind == nullptr, "does not existed, videoId: %{public}s", videoId.c_str());

    bool statusChanged = jobPtrFind->SetJobStatus(VideoJobStatus::ERROR);
    UpdateRunningCountUnLocked(statusChanged, jobPtrFind);
}

DeferredVideoJobPtr VideoJobRepository::GetJob()
{
    DP_INFO_LOG("DPS_VIDEO: Video job size: %{public}d, running num: %{public}d",
        jobQueue_->GetSize(), static_cast<int32_t>(runningSet_.size()));
    auto jobPtr = jobQueue_->Peek();
    DP_CHECK_RETURN_RET(jobPtr == nullptr || jobPtr->GetCurStatus() >= VideoJobStatus::RUNNING, nullptr);

    if (jobPtr->GetCurStatus() == VideoJobStatus::FAILED) {
        jobPtr->SetJobStatus(VideoJobStatus::PENDING);
        jobQueue_->Update(jobPtr);
    }
    return jobPtr;
}


int32_t VideoJobRepository::GetRunningJobCounts()
{
    DP_DEBUG_LOG("Video running jobs num: %{public}d", static_cast<int32_t>(runningSet_.size()));
    return static_cast<int32_t>(runningSet_.size());
}

void VideoJobRepository::GetRunningJobList(std::vector<std::string>& list)
{
    DP_DEBUG_LOG("Video running jobs num: %{public}d", static_cast<int32_t>(runningSet_.size()));
    list.clear();
    list.reserve(runningSet_.size());
    std::copy(runningSet_.begin(), runningSet_.end(), std::back_inserter(list));
}

void VideoJobRepository::RegisterJobListener(const std::weak_ptr<IVideoJobRepositoryListener>& listener)
{
    DP_DEBUG_LOG("entered.");
    jobListener_ = listener;
}

DeferredVideoJobPtr VideoJobRepository::GetJobUnLocked(const std::string& videoId)
{
    auto it = jobMap_.find(videoId);
    if (it != jobMap_.end()) {
        DP_DEBUG_LOG("video job videoId: %{public}s", videoId.c_str());
        return it->second;
    }
    return nullptr;
}

void VideoJobRepository::NotifyJobChangedUnLocked(bool statusChanged, DeferredVideoJobPtr jobPtr)
{
    DP_INFO_LOG("DPS_VIDEO: JobStatusChanged: %{public}d, videoId: %{public}s",
        statusChanged, jobPtr->GetVideoId().c_str());
    if (auto listenerSptr = jobListener_.lock()) {
        listenerSptr->OnVideoJobChanged(jobPtr);
    }
}

void VideoJobRepository::UpdateRunningCountUnLocked(bool statusChanged, const DeferredVideoJobPtr& jobPtr)
{
    DP_CHECK_EXECUTE(statusChanged, jobQueue_->Update(jobPtr));

    if (statusChanged && (jobPtr->GetPreStatus() == VideoJobStatus::RUNNING)) {
        runningSet_.erase(jobPtr->GetVideoId());
    }
    if (statusChanged && (jobPtr->GetCurStatus() == VideoJobStatus::RUNNING)) {
        runningSet_.emplace(jobPtr->GetVideoId());
    }
    DP_INFO_LOG("DPS_VIDEO: Video running jobs num: %{public}d, videoId: %{public}s",
        static_cast<int32_t>(runningSet_.size()), jobPtr->GetVideoId().c_str());
}

void VideoJobRepository::ClearCatch()
{
    jobQueue_->Clear();
    jobMap_.clear();
    runningSet_.clear();
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS