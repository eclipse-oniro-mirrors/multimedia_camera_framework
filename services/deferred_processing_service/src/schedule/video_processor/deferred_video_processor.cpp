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

#include "deferred_video_processor.h"

#include "dps_video_report.h"
#include "dp_utils.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
DeferredVideoProcessor::DeferredVideoProcessor(const int32_t userId, std::shared_ptr<VideoJobRepository> repository,
    std::shared_ptr<IVideoProcessCallbacks> callbacks)
    : userId_(userId),
      repository_(repository),
      callbacks_(callbacks),
      postProcessor_(nullptr)
{
    DP_DEBUG_LOG("entered.");
    postProcessor_ = CreateShared<VideoPostProcessor>(userId_);
}

DeferredVideoProcessor::~DeferredVideoProcessor()
{
    DP_DEBUG_LOG("entered.");
    repository_ = nullptr;
    callbacks_ = nullptr;
    postProcessor_ = nullptr;
}

void DeferredVideoProcessor::Initialize()
{
    DP_DEBUG_LOG("entered.");
    postProcessor_->Initialize();
}

void DeferredVideoProcessor::AddVideo(const std::string& videoId,
    const sptr<IPCFileDescriptor>& srcFd, const sptr<IPCFileDescriptor>& dstFd)
{
    DP_DEBUG_LOG("entered, videoId: %{public}s", videoId.c_str());
    repository_->AddVideoJob(videoId, srcFd, dstFd);
}

void DeferredVideoProcessor::RemoveVideo(const std::string& videoId, bool restorable)
{
    bool isNeedStop = repository_->RemoveVideoJob(videoId, restorable);
    DP_DEBUG_LOG("entered, videoId: %{public}s, isNeedStop: %{public}d, restorable: %{public}d",
        videoId.c_str(), isNeedStop, restorable);
    DP_CHECK_EXECUTE(isNeedStop, postProcessor_->PauseRequest(videoId, ScheduleType::REMOVE));
    DP_CHECK_EXECUTE(!restorable, postProcessor_->RemoveRequest(videoId));
}

void DeferredVideoProcessor::RestoreVideo(const std::string& videoId)
{
    DP_DEBUG_LOG("entered, videoId: %{public}s", videoId.c_str());
    repository_->RestoreVideoJob(videoId);
}

void DeferredVideoProcessor::OnProcessDone(const int32_t userId,
    const std::string& videoId, const sptr<IPCFileDescriptor>& ipcFd)
{
    DP_DEBUG_LOG("entered, videoId: %{public}s, fd: %{public}d", videoId.c_str(), ipcFd->GetFd());
    repository_->SetJobCompleted(videoId);
    callbacks_->OnProcessDone(userId, videoId, ipcFd);
    DfxVideoReport::GetInstance().ReportCompleteVideoEvent(videoId);
}

void DeferredVideoProcessor::OnError(const int32_t userId, const std::string& videoId, DpsError errorCode)
{
    DP_DEBUG_LOG("entered, videoId: %{public}s, error: %{public}d", videoId.c_str(), errorCode);
    DP_CHECK_EXECUTE(IsFatalError(errorCode), callbacks_->OnError(userId, videoId, errorCode));
    if (errorCode == DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED) {
        repository_->SetJobPause(videoId);
    } else if (errorCode == DpsError::DPS_ERROR_VIDEO_PROC_INVALID_VIDEO_ID) {
        repository_->SetJobError(videoId);
    } else {
        repository_->SetJobFailed(videoId);
    }
}

void DeferredVideoProcessor::OnStateChanged(const int32_t userId, DpsStatus statusCode)
{
    DP_DEBUG_LOG("entered, userId: %{public}d, status: %{public}d", userId, statusCode);
}

void DeferredVideoProcessor::PostProcess(const DeferredVideoWorkPtr& work)
{
    DP_DEBUG_LOG("entered.");
    auto videoId = work->GetDeferredVideoJob()->GetVideoId();
    repository_->SetJobRunning(videoId);
    postProcessor_->ProcessRequest(work);
    DfxVideoReport::GetInstance().ReportResumeVideoEvent(videoId);
}

void DeferredVideoProcessor::PauseRequest(const ScheduleType& type)
{
    DP_DEBUG_LOG("entered.");
    std::vector<std::string> runningList;
    repository_->GetRunningJobList(runningList);
    for (const auto& videoId: runningList) {
        repository_->SetJobPause(videoId);
        postProcessor_->PauseRequest(videoId, type);
        DfxVideoReport::GetInstance().ReportPauseVideoEvent(videoId, type);
    }
}

void DeferredVideoProcessor::SetDefaultExecutionMode()
{
    DP_DEBUG_LOG("entered.");
    postProcessor_->SetDefaultExecutionMode();
}

bool DeferredVideoProcessor::GetPendingVideos(std::vector<std::string>& pendingVideos)
{
    DP_DEBUG_LOG("entered.");
    return postProcessor_->GetPendingVideos(pendingVideos);
}

bool DeferredVideoProcessor::IsFatalError(DpsError errorCode)
{
    DP_INFO_LOG("entered, code: %{public}d", errorCode);
    if (errorCode == DpsError::DPS_ERROR_VIDEO_PROC_FAILED ||
        errorCode == DpsError::DPS_ERROR_VIDEO_PROC_INVALID_VIDEO_ID) {
        return true;
    }
    return false;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS