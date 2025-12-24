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

#include <sys/sendfile.h>
#include <sys/stat.h>
#include <utility>

#include "basic_definitions.h"
#include "camera_timer.h"
#include "dps.h"
#include "dps_video_report.h"
#include "dp_utils.h"
#include "video_process_command.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr uint32_t X10 = 10;
    constexpr uint32_t MAX_PROC_TIME_MS = 2 * 60 * 1000 * X10;
}
MovieProgress::MovieProgress(const std::string& videoId, const std::weak_ptr<DeferredVideoProcessor>& process)
    : videoId_(videoId), process_(process)
{
    DP_DEBUG_LOG("entered.");
}

void MovieProgress::OnProgressUpdate(float progress)
{
    auto process = process_.lock();
    DP_CHECK_EXECUTE(process != nullptr, process->OnProcessProgress(videoId_, progress));
}

DeferredVideoProcessor::DeferredVideoProcessor(const int32_t userId,
    const std::shared_ptr<VideoJobRepository>& repository, const std::shared_ptr<VideoPostProcessor>& postProcessor)
    : userId_(userId), repository_(repository), postProcessor_(postProcessor)
{
    DP_DEBUG_LOG("entered.");
}

DeferredVideoProcessor::~DeferredVideoProcessor()
{
    DP_INFO_LOG("entered.");
    initialized_.store(false);
}

int32_t DeferredVideoProcessor::Initialize()
{
    DP_CHECK_ERROR_RETURN_RET_LOG(repository_ == nullptr, DP_NULL_POINTER, "VideoJobRepository is nullptr.");
    DP_CHECK_ERROR_RETURN_RET_LOG(postProcessor_ == nullptr, DP_NULL_POINTER, "VideoPostProcessor is nullptr.");
    result_ = DeferredVideoResult::Create();
    DP_CHECK_ERROR_RETURN_RET_LOG(result_ == nullptr, DP_NULL_POINTER, "DeferredVideoResult is nullptr.");
    initialized_.store(true);
    return DP_OK;
}

void DeferredVideoProcessor::AddVideo(const std::string& videoId, const std::shared_ptr<VideoInfo>& info)
{
    bool isProcess = ProcessCatchResults(videoId);
    DP_CHECK_RETURN(isProcess);
    DP_CHECK_ERROR_RETURN_LOG(repository_ == nullptr, "VideoJobRepository is nullptr.");
    repository_->AddVideoJob(videoId, info);
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
    result_->ResetCrashCount(videoId);
}

void DeferredVideoProcessor::RestoreVideo(const std::string& videoId)
{
    DP_DEBUG_LOG("DPS_VIDEO: videoId: %{public}s", videoId.c_str());
    DP_CHECK_ERROR_RETURN_LOG(repository_ == nullptr, "VideoJobRepository is nullptr.");
    repository_->RestoreVideoJob(videoId);
}

void DeferredVideoProcessor::ProcessVideo(const std::string& videoId)
{
    DP_DEBUG_LOG("DPS_VIDEO: videoId: %{public}s", videoId.c_str());
    DP_CHECK_ERROR_RETURN_LOG(repository_ == nullptr, "VideoJobRepository is nullptr.");
    bool isVideoIdValid = repository_->RequestJob(videoId);
    DP_CHECK_RETURN(isVideoIdValid);
    auto callback = GetCallback();
    DP_CHECK_EXECUTE(callback, callback->OnError(videoId, MapDpsErrorCode(DPS_ERROR_VIDEO_PROC_INVALID_VIDEO_ID)));
}

void DeferredVideoProcessor::CancelProcessVideo(const std::string& videoId)
{
    DP_DEBUG_LOG("DPS_VIDEO: videoId: %{public}s", videoId.c_str());
    DP_CHECK_ERROR_RETURN_LOG(repository_ == nullptr, "VideoJobRepository is nullptr.");
    repository_->CancelJob(videoId);
    if (repository_->IsRunningJob(videoId)) {
        DP_CHECK_ERROR_RETURN_LOG(postProcessor_ == nullptr, "VideoPostProcessor is nullptr.");
        postProcessor_->PauseRequest(videoId, SchedulerType::VIDEO_CANCEL_PROCESS_STATE);
    }
}

void DeferredVideoProcessor::DoProcess(const DeferredVideoJobPtr& job)
{
    DP_DEBUG_LOG("entered.");
    auto videoId = job->GetVideoId();
    DP_CHECK_ERROR_RETURN_LOG(repository_ == nullptr, "VideoJobRepository is nullptr.");
    repository_->SetJobRunning(videoId);

    DP_CHECK_ERROR_RETURN_LOG(postProcessor_ == nullptr, "VideoPostProcessor is nullptr.");
    auto streams = postProcessor_->PrepareStreams(job);
    for (const auto& item : streams) {
        DP_LOOP_CONTINUE_LOG(item.type != HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_VIDEO,
            "stream type: %{public}d", item.type);
        bool result = StartMpeg(videoId, job->GetInputFd(), item.width, item.height);
        DP_CHECK_EXECUTE_AND_RETURN(!result, HandleError(userId_, videoId, DPS_ERROR_VIDEO_PROC_FAILED));
    }

    uint32_t timerId = StartTimer(videoId);
    job->SetTimerId(timerId);
    postProcessor_->ProcessRequest(videoId, streams, mediaManagerProxy_);
    DfxVideoReport::GetInstance().ReportResumeVideoEvent(videoId);
}

void DeferredVideoProcessor::OnProcessSuccess(const int32_t userId, const std::string& videoId,
    std::unique_ptr<MediaUserInfo> userInfo)
{
    DP_INFO_LOG("DPS_VIDEO: userId: %{public}d, imageId: %{public}s", userId, videoId.c_str());
    StopTimer(videoId);
    DP_CHECK_EXECUTE(userInfo != nullptr && mediaManagerProxy_ != nullptr,
        mediaManagerProxy_->MpegAddUserMeta(std::move(userInfo)));
    auto jobPtr = repository_->GetJobUnLocked(videoId);
    auto result = StopMpeg(MediaResult::SUCCESS, jobPtr);
    DP_CHECK_EXECUTE_AND_RETURN(!result, HandleError(userId_, videoId, DPS_ERROR_VIDEO_PROC_FAILED));

    HandleSuccess(userId, videoId);
}

void DeferredVideoProcessor::OnProcessError(const int32_t userId, const std::string& videoId, DpsError error)
{
    DP_ERR_LOG("DPS_VIDEO: userId: %{public}d, videoId: %{public}s, dps error: %{public}d.",
        userId, videoId.c_str(), error);
    StopTimer(videoId);
    MediaResult resule = error == DPS_ERROR_VIDEO_PROC_INTERRUPTED ? MediaResult::PAUSE : MediaResult::FAIL;
    auto jobPtr = repository_->GetJobUnLocked(videoId);
    StopMpeg(resule, jobPtr);
    HandleError(userId, videoId, error);
}

void DeferredVideoProcessor::OnProcessProgress(const std::string& videoId, float progress)
{
    DP_INFO_LOG("DPS_VIDEO: videoId: %{public}s, progress: %{public}f", videoId.c_str(), progress);
    auto callback = GetCallback();
    DP_CHECK_EXECUTE(callback != nullptr, callback->OnProcessingProgress(videoId, progress));
}

void DeferredVideoProcessor::HandleSuccess(const int32_t userId, const std::string& videoId)
{
    DP_DEBUG_LOG("DPS_VIDEO: videoId: %{public}s", videoId.c_str());
    
    auto callback = GetCallback();
    DP_CHECK_EXECUTE_AND_RETURN(callback == nullptr, result_->RecordResult(videoId));

    callback->OnProcessVideoDone(videoId);
    repository_->SetJobCompleted(videoId);
    DfxVideoReport::GetInstance().ReportCompleteVideoEvent(videoId);
}

void DeferredVideoProcessor::HandleError(const int32_t userId, const std::string& videoId, DpsError error)
{
    bool isHighJob = repository_->IsHighJob(videoId);
    JobErrorType ret = result_->OnError(videoId, error, isHighJob);
    auto callback = GetCallback();
    DP_CHECK_EXECUTE_AND_RETURN(callback == nullptr, result_->RecordResult(videoId, error));

    bool needNotify = false;
    switch (ret) {
        case JobErrorType::RETRY:
            repository_->SetJobFailed(videoId);
            break;
        case JobErrorType::PAUSE:
            repository_->SetJobPause(videoId);
            break;
        case JobErrorType::FATAL_NOTIFY:
            repository_->SetJobError(videoId);
            needNotify = true;
            break;
        case JobErrorType::PAUSE_NOTIFY:
            repository_->SetJobPause(videoId);
            needNotify = true;
            break;
        case JobErrorType::HIGH_FAILED:
            repository_->SetJobFailed(videoId);
            needNotify = true;
            break;
        default:
            break;
    }
    DP_CHECK_RETURN(!needNotify);

    auto errorCode = MapDpsErrorCode(error);
    callback->OnError(videoId, errorCode);
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

bool DeferredVideoProcessor::HasRunningJob()
{
    DP_CHECK_ERROR_RETURN_RET_LOG(repository_ == nullptr, false, "VideoJobRepository is nullptr.");
    return repository_->HasRunningJob();
}

bool DeferredVideoProcessor::IsNeedStopJob()
{
    DP_CHECK_ERROR_RETURN_RET_LOG(repository_ == nullptr, false, "VideoJobRepository is nullptr.");
    return repository_->IsNeedStopJob();
}

uint32_t DeferredVideoProcessor::StartTimer(const std::string& videoId)
{
    uint32_t interval = MAX_PROC_TIME_MS;
    DP_CHECK_EXECUTE(mediaManagerProxy_ != nullptr,
        interval = std::max(mediaManagerProxy_->MpegGetDuration() * X10, interval));
    auto thisPtr = weak_from_this();
    uint32_t timerId = CameraTimer::GetInstance().Register(
        [thisPtr, videoId]() {
            auto process = thisPtr.lock();
            DP_CHECK_EXECUTE(process != nullptr, process->ProcessVideoTimeout(videoId));
        }, interval, true);
    DP_INFO_LOG("DPS_TIMER: Start videoId: %{public}s, timerId: %{public}u", videoId.c_str(), timerId);
    return timerId;
}

void DeferredVideoProcessor::StopTimer(const std::string& videoId)
{
    uint32_t timerId = repository_->GetJobTimerId(videoId);
    DP_INFO_LOG("DPS_TIMER: Stop videoId: %{public}s, timeId: %{public}u", videoId.c_str(), timerId);
    CameraTimer::GetInstance().Unregister(timerId);
}

void DeferredVideoProcessor::ProcessVideoTimeout(const std::string& videoId)
{
    DP_INFO_LOG("DPS_TIMER: Executed videoId: %{public}s", videoId.c_str());
    auto ret = DPS_SendCommand<VideoProcessTimeOutCommand>(userId_, videoId, DPS_ERROR_VIDEO_PROC_TIMEOUT);
    DP_CHECK_ERROR_RETURN_LOG(ret != DP_OK,
        "process photo timeout imageId: %{public}s failed. ret: %{public}d", videoId.c_str(), ret);
}

bool DeferredVideoProcessor::StartMpeg(const std::string& videoId, const DpsFdPtr& inputFd,
    int32_t width, int32_t height)
{
    mediaManagerProxy_ = MediaManagerProxy::CreateMediaManagerProxy();
    DP_CHECK_ERROR_RETURN_RET_LOG(mediaManagerProxy_ == nullptr, false, "MediaManagerProxy is nullptr.");
    int32_t ret = mediaManagerProxy_->MpegAcquire(videoId, inputFd, width, height);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != DP_OK, false, "MpegAcquire failed");

    auto isNeedNotifyProgress = repository_ != nullptr && repository_->IsHighJob(videoId);
    DP_CHECK_EXECUTE(isNeedNotifyProgress, {
        auto processNotifer = std::make_unique<MediaProgressNotifier>();
        progress_ = std::make_shared<MovieProgress>(videoId, weak_from_this());
        processNotifer->SetNotifyCallback(std::weak_ptr<ProgressCallback>(progress_));
        mediaManagerProxy_->MpegSetProgressNotifer(std::move(processNotifer));
    });
    return true;
}

bool DeferredVideoProcessor::StopMpeg(const MediaResult result, const DeferredVideoJobPtr& job)
{
    // LCOV_EXCL_START
    DP_CHECK_ERROR_RETURN_RET_LOG(mediaManagerProxy_ == nullptr, false, "MpegManager is nullptr");
    
    auto ret = mediaManagerProxy_->MpegUnInit(result);
    if (ret != DP_OK) {
        ReleaseMpeg();
        return false;
    }

    if (result != MediaResult::SUCCESS) {
        ReleaseMpeg();
        return true;
    }

    DP_CHECK_ERROR_RETURN_RET_LOG(job == nullptr, false, "job is nullptr");
    auto videoId = job->GetVideoId();
    auto resultFd = mediaManagerProxy_->MpegGetResultFd();
    if (resultFd == nullptr) {
        DP_ERR_LOG("Get video fd failed, videoId: %{public}s", videoId.c_str());
        ReleaseMpeg();
        return false;
    }

    auto tempFd = resultFd->GetFd();
    auto outFd = job->GetOutputFd()->GetFd();
    CopyFileByFd(tempFd, outFd);
    if (IsFileEmpty(outFd)) {
        DP_ERR_LOG("Video size is empty, videoId: %{public}s", videoId.c_str());
        ReleaseMpeg();
        return false;
    }

    DP_INFO_LOG("DPS_VIDEO: Video process done, videoId: %{public}s, tempFd: %{public}d, outFd: %{public}d",
        videoId.c_str(), tempFd, outFd);
    ReleaseMpeg();
    return true;
    // LCOV_EXCL_STOP
}

void DeferredVideoProcessor::ReleaseMpeg()
{
    DP_CHECK_ERROR_RETURN_LOG(mediaManagerProxy_ == nullptr, "mpegManager is nullptr");
    mediaManagerProxy_->MpegRelease();
    mediaManagerProxy_.reset();
}

void DeferredVideoProcessor::CopyFileByFd(const int srcFd, const int dstFd)
{
    // LCOV_EXCL_START
    struct stat buffer;
    DP_CHECK_ERROR_RETURN_LOG(fstat(srcFd, &buffer) == -1,
        "get out fd status failed, err: %{public}s", std::strerror(errno));

    off_t offset = 0;
    ssize_t bytesSent;
    while (offset < buffer.st_size) {
        bytesSent = sendfile(dstFd, srcFd, &offset, buffer.st_size - offset);
        DP_LOOP_BREAK_LOG(bytesSent == 0, "copy file complete");
        DP_CHECK_ERROR_RETURN_LOG(bytesSent == -1, "copy file failed, err: %{public}s", std::strerror(errno));
    }
    // LCOV_EXCL_STOP
}

sptr<IDeferredVideoProcessingSessionCallback> DeferredVideoProcessor::GetCallback()
{
    auto session = DPS_GetSessionManager();
    DP_CHECK_RETURN_RET(session == nullptr, nullptr);
    auto video = session->GetVideoInfo(userId_);
    DP_CHECK_RETURN_RET(video == nullptr, nullptr);
    return video->GetRemoteCallback();
}

bool DeferredVideoProcessor::ProcessCatchResults(const std::string& videoId)
{
    auto result = result_->GetCacheResult(videoId);
    DP_CHECK_RETURN_RET(result == DpsError::DPS_ERROR_UNKNOWN, false);
    auto callback = GetCallback();
    DP_CHECK_RETURN_RET(callback == nullptr, false);

    DP_INFO_LOG("DPS_VIDEO: ProcessCatchResults videoId: %{public}s", videoId.c_str());
    switch (result) {
        case DpsError::DPS_NO_ERROR:
            callback->OnProcessVideoDone(videoId);
            break;
        case DpsError::DPS_ERROR_VIDEO_PROC_INVALID_VIDEO_ID:
        case DpsError::DPS_ERROR_VIDEO_PROC_FAILED:
            callback->OnError(videoId, MapDpsErrorCode(result));
            break;
        default:
            break;
    }
    result_->DeRecordResult(videoId);
    return true;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS