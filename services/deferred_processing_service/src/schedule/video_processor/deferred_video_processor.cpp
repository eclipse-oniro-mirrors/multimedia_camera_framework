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

#include "deferred_video_processor.h"

#include "dps_video_report.h"
#include "dp_utils.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
DeferredVideoProcessor::DeferredVideoProcessor(const std::shared_ptr<VideoJobRepository>& repository,
    const std::shared_ptr<VideoPostProcessor>& postProcessor, const std::shared_ptr<IVideoProcessCallbacks>& callback)
    : repository_(repository), postProcessor_(postProcessor), callback_(callback)
{
    DP_DEBUG_LOG("entered.");
}

DeferredVideoProcessor::~DeferredVideoProcessor()
{
    DP_DEBUG_LOG("entered.");
}

void DeferredVideoProcessor::Initialize()
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_LOG(postProcessor_ == nullptr, "VideoPostProcessor is nullptr.");

    postProcessor_->Initialize();
}

void DeferredVideoProcessor::AddVideo(const std::string& videoId,
    const sptr<IPCFileDescriptor>& srcFd, const sptr<IPCFileDescriptor>& dstFd)
{
    DP_DEBUG_LOG("DPS_VIDEO: videoId: %{public}s", videoId.c_str());
    DP_CHECK_ERROR_RETURN_LOG(repository_ == nullptr, "VideoJobRepository is nullptr.");

    repository_->AddVideoJob(videoId, srcFd, dstFd);
}

void DeferredVideoProcessor::RemoveVideo(const std::string& videoId, bool restorable)
{
    DP_CHECK_ERROR_RETURN_LOG(repository_ == nullptr, "VideoJobRepository is nullptr.");

    bool isNeedStop = repository_->RemoveVideoJob(videoId, restorable);
    DP_DEBUG_LOG("DPS_VIDEO: videoId: %{public}s, isNeedStop: %{public}d, restorable: %{public}d",
        videoId.c_str(), isNeedStop, restorable);
    DP_CHECK_ERROR_RETURN_LOG(postProcessor_ == nullptr, "VideoPostProcessor is nullptr.");

    DP_CHECK_EXECUTE(isNeedStop, postProcessor_->PauseRequest(videoId, SchedulerType::REMOVE));
    DP_CHECK_EXECUTE(!restorable, postProcessor_->RemoveRequest(videoId));
}

void DeferredVideoProcessor::RestoreVideo(const std::string& videoId)
{
    DP_DEBUG_LOG("DPS_VIDEO: videoId: %{public}s", videoId.c_str());
    DP_CHECK_ERROR_RETURN_LOG(repository_ == nullptr, "VideoJobRepository is nullptr.");

    repository_->RestoreVideoJob(videoId);
}

void DeferredVideoProcessor::OnProcessDone(const int32_t userId,
    const std::string& videoId, const sptr<IPCFileDescriptor>& ipcFd)
{
    DP_DEBUG_LOG("DPS_VIDEO: videoId: %{public}s, fd: %{public}d", videoId.c_str(), ipcFd->GetFd());
    DP_CHECK_ERROR_RETURN_LOG(callback_ == nullptr, "IVideoProcessCallbacks is nullptr.");

    callback_->OnProcessDone(userId, videoId, ipcFd);
    DP_CHECK_ERROR_RETURN_LOG(repository_ == nullptr, "VideoJobRepository is nullptr.");

    repository_->SetJobCompleted(videoId);
    DfxVideoReport::GetInstance().ReportCompleteVideoEvent(videoId);
}

void DeferredVideoProcessor::OnError(const int32_t userId, const std::string& videoId, DpsError errorCode)
{
    DP_DEBUG_LOG("DPS_VIDEO: videoId: %{public}s, error: %{public}d", videoId.c_str(), errorCode);
    DP_CHECK_ERROR_RETURN_LOG(callback_ == nullptr, "IVideoProcessCallbacks is nullptr.");

    DP_CHECK_EXECUTE(IsFatalError(errorCode), callback_->OnError(userId, videoId, errorCode));
    DP_CHECK_ERROR_RETURN_LOG(repository_ == nullptr, "VideoJobRepository is nullptr.");

    if (errorCode == DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED) {
        repository_->SetJobPause(videoId);
    } else if (errorCode == DpsError::DPS_ERROR_VIDEO_PROC_INVALID_VIDEO_ID ||
        errorCode == DpsError::DPS_ERROR_VIDEO_PROC_FAILED) {
        repository_->SetJobError(videoId);
    } else {
        repository_->SetJobFailed(videoId);
    }
}

void DeferredVideoProcessor::OnStateChanged(const int32_t userId, DpsStatus statusCode)
{
    DP_DEBUG_LOG("DPS_VIDEO: userId: %{public}d, status: %{public}d", userId, statusCode);
}

void DeferredVideoProcessor::PostProcess(const DeferredVideoWorkPtr& work)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_LOG(repository_ == nullptr, "VideoJobRepository is nullptr.");

    auto videoId = work->GetDeferredVideoJob()->GetVideoId();
    repository_->SetJobRunning(videoId);
    DP_CHECK_ERROR_RETURN_LOG(postProcessor_ == nullptr, "VideoPostProcessor is nullptr.");
    
    postProcessor_->ProcessRequest(work);
    DfxVideoReport::GetInstance().ReportResumeVideoEvent(videoId);
}

void DeferredVideoProcessor::PauseRequest(const SchedulerType& type)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_LOG(repository_ == nullptr, "VideoJobRepository is nullptr.");

    std::vector<std::string> runningList;
    repository_->GetRunningJobList(runningList);
    DP_CHECK_ERROR_RETURN_LOG(postProcessor_ == nullptr, "VideoPostProcessor is nullptr.");

    for (const auto& videoId: runningList) {
        postProcessor_->PauseRequest(videoId, type);
        DfxVideoReport::GetInstance().ReportPauseVideoEvent(videoId, type);
    }
}

void DeferredVideoProcessor::SetDefaultExecutionMode()
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_LOG(postProcessor_ == nullptr, "VideoPostProcessor is nullptr.");

    postProcessor_->SetDefaultExecutionMode();
}

bool DeferredVideoProcessor::GetPendingVideos(std::vector<std::string>& pendingVideos)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(postProcessor_ == nullptr, false, "VideoPostProcessor is nullptr.");

    return postProcessor_->GetPendingVideos(pendingVideos);
}

bool DeferredVideoProcessor::IsFatalError(DpsError errorCode)
{
    return (errorCode == DpsError::DPS_ERROR_VIDEO_PROC_FAILED ||
        errorCode == DpsError::DPS_ERROR_VIDEO_PROC_INVALID_VIDEO_ID);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS