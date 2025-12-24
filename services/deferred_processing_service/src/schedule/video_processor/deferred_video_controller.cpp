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

#include "camera_timer.h"
#include "dp_power_manager.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredVideoController::StateListener : public IStateChangeListener<SchedulerType, SchedulerInfo> {
public:
    explicit StateListener(const std::weak_ptr<DeferredVideoController>& controller) : controller_(controller)
    {
        DP_DEBUG_LOG("entered.");
    }

    ~StateListener() override
    {
        DP_DEBUG_LOG("entered.");
    }

    void OnSchedulerChanged(const SchedulerType& type, const SchedulerInfo& scheduleInfo) override
    {
        auto controller = controller_.lock();
        DP_CHECK_ERROR_RETURN_LOG(controller == nullptr, "VideoController is nullptr.");
        controller->OnSchedulerChanged(type, scheduleInfo);
    }

private:
    std::weak_ptr<DeferredVideoController> controller_;
};

DeferredVideoController::DeferredVideoController(const int32_t userId,
    const std::shared_ptr<DeferredVideoProcessor>& processor)
    : userId_(userId), videoProcessor_(processor)
{
    DP_DEBUG_LOG("entered, userid: %{public}d", userId_);
}

DeferredVideoController::~DeferredVideoController()
{
    DP_INFO_LOG("entered.");
    StopSuspendLock();
}

int32_t DeferredVideoController::Initialize()
{
    DP_CHECK_ERROR_RETURN_RET_LOG(videoProcessor_ == nullptr, DP_NULL_POINTER, "DeferredVideoProcessor is nullptr.");
    videoStrategyCenter_ = VideoStrategyCenter::Create(videoProcessor_->GetRepository());
    DP_CHECK_ERROR_RETURN_RET_LOG(videoStrategyCenter_ == nullptr, DP_NULL_POINTER, "VideoStrategyCenter is nullptr.");
    videoStateChangeListener_ = std::make_shared<StateListener>(weak_from_this());
    videoStrategyCenter_->RegisterStateChangeListener(videoStateChangeListener_);
    return DP_OK;
}

void DeferredVideoController::HandleServiceDied()
{
    DP_DEBUG_LOG("entered.");
    StopSuspendLock();
}

void DeferredVideoController::HandleSuccess(const std::string& videoId, std::unique_ptr<MediaUserInfo> userInfo)
{
    auto job = GetJob(videoId);
    DP_CHECK_ERROR_RETURN_LOG(job == nullptr, "Video job is nullptr.");
    DP_INFO_LOG("DPS_VIDEO: HandleSuccess videoId: %{public}s, outFd: %{public}d",
        videoId.c_str(), job->GetOutputFd()->GetFd());
    HandleNormalSchedule(job);
    DP_CHECK_EXECUTE(videoProcessor_, videoProcessor_->OnProcessSuccess(userId_, videoId, std::move(userInfo)));
}

void DeferredVideoController::HandleError(const std::string& videoId, DpsError errorCode)
{
    auto job = GetJob(videoId);
    DP_CHECK_ERROR_RETURN_LOG(job == nullptr, "Video job is nullptr.");
    DP_INFO_LOG("DPS_VIDEO: HandleError videoId: %{public}s", videoId.c_str());
    if (errorCode == DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED) {
        StopSuspendLock();
    }
    HandleNormalSchedule(job);
    DP_CHECK_EXECUTE(videoProcessor_, videoProcessor_->OnProcessError(userId_, videoId, errorCode));
}

void DeferredVideoController::OnVideoJobChanged()
{
    TryDoSchedule();
}

void DeferredVideoController::OnSchedulerChanged(const SchedulerType& type, const SchedulerInfo& scheduleInfo)
{
    DP_INFO_LOG("DPS_VIDEO: Video isNeedStop: %{public}d, isCharging: %{public}d",
        scheduleInfo.isNeedStop, scheduleInfo.isCharging);
    if (scheduleInfo.isNeedStop || scheduleInfo.isNeedInterrupt) {
        PauseRequests(type);
    } else {
        TryDoSchedule();
    }
}

void DeferredVideoController::TryDoSchedule()
{
    DP_CHECK_ERROR_RETURN_LOG(videoProcessor_ == nullptr || videoProcessor_->HasRunningJob(), "Not schedule job.");

    auto job = videoStrategyCenter_->GetJob();
    DP_INFO_LOG("DPS_VIDEO: strategy get job: %{public}d", job != nullptr);
    if (job == nullptr) {
        StopSuspendLock();
        return;
    }
    CameraDynamicLoader::LoadDynamiclibAsync(MEDIA_MANAGER_SO);
    DP_CHECK_EXECUTE(job->IsSuspend(), StartSuspendLock());
    DoProcess(job);
}

void DeferredVideoController::DoProcess(const DeferredVideoJobPtr& job)
{
    DP_CHECK_ERROR_RETURN_LOG(videoProcessor_ == nullptr, "DeferredVideoProcessor is nullptr.");
    videoProcessor_->DoProcess(job);
}

void DeferredVideoController::PauseRequests(const SchedulerType& type)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_LOG(videoProcessor_ == nullptr, "DeferredVideoProcessor is nullptr.");
    DP_CHECK_EXECUTE(videoProcessor_->IsNeedStopJob(), videoProcessor_->PauseRequest(type));
}

void DeferredVideoController::SetDefaultExecutionMode()
{
    DP_DEBUG_LOG("entered");
    DP_CHECK_ERROR_RETURN_LOG(videoProcessor_ == nullptr, "DeferredVideoProcessor is nullptr.");

    videoProcessor_->SetDefaultExecutionMode();
}

void DeferredVideoController::StartSuspendLock()
{
    DP_CHECK_RETURN(normalTimeId_ != INVALID_TIMERID);
    uint32_t processTime = static_cast<uint32_t>(videoStrategyCenter_->GetAvailableTime());
    auto thisPtr = weak_from_this();
    normalTimeId_ = CameraTimer::GetInstance().Register([thisPtr]() {
        auto controller = thisPtr.lock();
        DP_CHECK_EXECUTE(controller != nullptr, controller->OnTimerOut());
    }, processTime, true);
    DPSProwerManager::GetInstance().SetAutoSuspend(false, processTime + DELAY_TIME);
    DP_INFO_LOG("DpsTimer start: normal schedule timeId: %{public}u, processTime: %{public}u.",
        normalTimeId_, processTime);
}

void DeferredVideoController::StopSuspendLock()
{
    DP_CHECK_RETURN(normalTimeId_ == INVALID_TIMERID);
    DPSProwerManager::GetInstance().SetAutoSuspend(true);
    DP_INFO_LOG("DpsTimer stop: normal schedule timeId: %{public}d.", normalTimeId_);
    CameraTimer::GetInstance().Unregister(normalTimeId_);
    normalTimeId_ = INVALID_TIMERID;
}

void DeferredVideoController::HandleNormalSchedule(const DeferredVideoJobPtr& job)
{
    DP_CHECK_RETURN(!job->IsSuspend());
    DP_INFO_LOG("DPS_VIDEO: HandleNormalSchedule videoId: %{public}s", job->GetVideoId().c_str());
    auto usedTime = static_cast<int32_t>(job->GetExecutionTime());
    videoStrategyCenter_->UpdateAvailableTime(usedTime);
}

void DeferredVideoController::OnTimerOut()
{
    DP_INFO_LOG("DpsTimer end: normal schedule time out timeId: %{public}u", normalTimeId_);
    normalTimeId_ = INVALID_TIMERID;
    videoStrategyCenter_->UpdateSingleTime(false);
    PauseRequests(NORMAL_TIME_STATE);
}

DeferredVideoJobPtr DeferredVideoController::GetJob(const std::string& videoId)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(videoProcessor_ == nullptr, nullptr, "DeferredVideoProcessor is nullptr.");
    auto repository = videoProcessor_->GetRepository();
    return repository->GetJobUnLocked(videoId);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS