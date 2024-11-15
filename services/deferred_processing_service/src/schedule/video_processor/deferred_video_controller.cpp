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

#include "deferred_video_controller.h"

#include "dp_power_manager.h"
#include "dp_timer.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredVideoController::StateListener : public IVideoStateChangeListener {
public:
    explicit StateListener(const std::weak_ptr<DeferredVideoController>& controller) : controller_(controller)
    {
        DP_DEBUG_LOG("entered.");
    }

    ~StateListener() override
    {
        DP_DEBUG_LOG("entered.");
    }

    void OnSchedulerChanged(const ScheduleType& type, const ScheduleInfo& scheduleInfo) override
    {
        auto controller = controller_.lock();
        DP_CHECK_ERROR_RETURN_LOG(controller == nullptr, "VideoController is nullptr.");
        controller->OnSchedulerChanged(type, scheduleInfo);
    }

private:
    std::weak_ptr<DeferredVideoController> controller_;
};

class DeferredVideoController::VideoJobRepositoryListener : public IVideoJobRepositoryListener {
public:
    explicit VideoJobRepositoryListener(const std::weak_ptr<DeferredVideoController>& controller)
        : controller_(controller)
    {
        DP_DEBUG_LOG("entered.");
    }

    ~VideoJobRepositoryListener()
    {
        DP_DEBUG_LOG("entered.");
    }

    void OnVideoJobChanged(const DeferredVideoJobPtr& jobPtr) override
    {
        auto controller = controller_.lock();
        DP_CHECK_ERROR_RETURN_LOG(controller == nullptr, "Video controller is nullptr.");
        controller->OnVideoJobChanged(jobPtr);
    }

private:
    std::weak_ptr<DeferredVideoController> controller_;
};

DeferredVideoController::DeferredVideoController(const int32_t userId,
    const std::shared_ptr<VideoJobRepository>& repository, const std::shared_ptr<DeferredVideoProcessor>& processor)
    : userId_(userId), videoProcessor_(processor), repository_(repository)
{
    DP_DEBUG_LOG("entered, userid: %{public}d", userId_);
}

DeferredVideoController::~DeferredVideoController()
{
    DP_DEBUG_LOG("entered.");
    StopSuspendLock();
}

void DeferredVideoController::Initialize()
{
    DP_DEBUG_LOG("entered.");
    videoJobChangeListener_ = std::make_shared<VideoJobRepositoryListener>(weak_from_this());
    repository_->RegisterJobListener(videoJobChangeListener_);
    videoStrategyCenter_ = CreateShared<VideoStrategyCenter>(userId_, repository_);
    videoStrategyCenter_->Initialize();
    videoStateChangeListener_ = std::make_shared<StateListener>(weak_from_this());
    videoStrategyCenter_->RegisterStateChangeListener(videoStateChangeListener_);
    videoProcessor_->Initialize();
}

void DeferredVideoController::HandleServiceDied()
{
    DP_DEBUG_LOG("entered.");
    auto running = repository_->GetRunningJobCounts();
    if (running > 0) {
        StopSuspendLock();
    }
}

void DeferredVideoController::HandleSuccess(const DeferredVideoWorkPtr& work)
{
    DP_CHECK_ERROR_RETURN_LOG(work == nullptr, "Video work is nullptr.");

    auto videoId = work->GetDeferredVideoJob()->GetVideoId();
    auto out = work->GetDeferredVideoJob()->GetOutputFd();
    DP_INFO_LOG("DPS_VIDEO: HandleSuccess videoId: %{public}s, outFd: %{public}d", videoId.c_str(), out->GetFd());
    HandleNormalSchedule(work);
    videoProcessor_->OnProcessDone(userId_, videoId, out);
}

void DeferredVideoController::HandleError(const DeferredVideoWorkPtr& work, DpsError errorCode)
{
    DP_CHECK_ERROR_RETURN_LOG(work == nullptr, "Video work is nullptr.");

    auto videoId = work->GetDeferredVideoJob()->GetVideoId();
    DP_INFO_LOG("DPS_VIDEO: HandleError videoId: %{public}s", videoId.c_str());
    if (errorCode == DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED) {
        StopSuspendLock();
    }
    HandleNormalSchedule(work);
    videoProcessor_->OnError(userId_, videoId, errorCode);
}

void DeferredVideoController::OnVideoJobChanged(const DeferredVideoJobPtr& jobPtr)
{
    DP_INFO_LOG("DPS_VIDEO: videoId: %{public}s", jobPtr->GetVideoId().c_str());
    TryDoSchedule();
}

void DeferredVideoController::OnSchedulerChanged(const ScheduleType& type, const ScheduleInfo& scheduleInfo)
{
    DP_INFO_LOG("DPS_VIDEO: Video isNeedStop: %{public}d, isCharging: %{public}d",
        scheduleInfo.isNeedStop, scheduleInfo.isCharging);
    if (scheduleInfo.isNeedStop) {
        PauseRequests(type);
    } else {
        TryDoSchedule();
    }
}

void DeferredVideoController::TryDoSchedule()
{
    DP_DEBUG_LOG("entered.");
    auto work = videoStrategyCenter_->GetWork();
    DP_INFO_LOG("DPS_VIDEO: strategy get work: %{public}d", work != nullptr);
    if (work == nullptr) {
        StopSuspendLock();
        return;
    }
    
    DP_CHECK_EXECUTE(work->IsSuspend(), StartSuspendLock());
    PostProcess(work);
}

void DeferredVideoController::PauseRequests(const ScheduleType& type)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_RETURN(repository_->GetRunningJobCounts() <= 0);
    videoProcessor_->PauseRequest(type);
}

void DeferredVideoController::PostProcess(const DeferredVideoWorkPtr& work)
{
    DP_DEBUG_LOG("entered");
    videoProcessor_->PostProcess(work);
}

void DeferredVideoController::SetDefaultExecutionMode()
{
    DP_DEBUG_LOG("entered");
    videoProcessor_->SetDefaultExecutionMode();
}

void DeferredVideoController::StartSuspendLock()
{
    DP_CHECK_RETURN(normalTimeId_ != INVALID_TIMEID);
    uint32_t processTime = static_cast<uint32_t>(
        std::min(videoStrategyCenter_->GetAvailableTime(), ONCE_PROCESS_TIME));
    normalTimeId_ = DpsTimer::GetInstance().StartTimer([&]() {OnTimerOut();}, processTime);
    DPSProwerManager::GetInstance().SetAutoSuspend(false, processTime + DELAY_TIME);
    DP_INFO_LOG("DpsTimer start: normal schedule timeId: %{public}d, processTime: %{public}d.",
        static_cast<int32_t>(normalTimeId_), processTime);
}

void DeferredVideoController::StopSuspendLock()
{
    DP_CHECK_RETURN(normalTimeId_ == INVALID_TIMEID);
    DPSProwerManager::GetInstance().SetAutoSuspend(true);
    DP_INFO_LOG("DpsTimer stop: normal schedule timeId: %{public}d.", normalTimeId_);
    DpsTimer::GetInstance().StopTimer(normalTimeId_);
}

void DeferredVideoController::HandleNormalSchedule(const DeferredVideoWorkPtr& work)
{
    DP_CHECK_RETURN(!work->IsSuspend());

    DP_INFO_LOG("DPS_VIDEO: HandleNormalSchedule videoId: %{public}s",
        work->GetDeferredVideoJob()->GetVideoId().c_str());
    auto usedTime = static_cast<int32_t>(work->GetExecutionTime());
    videoStrategyCenter_->UpdateAvailableTime(false, usedTime);
}

void DeferredVideoController::OnTimerOut()
{
    DP_INFO_LOG("DpsTimer end: normal schedule time out.");
    normalTimeId_ = INVALID_TIMEID;
    videoStrategyCenter_->UpdateSingleTime(false);
    PauseRequests(NORMAL_TIME_STATE);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS