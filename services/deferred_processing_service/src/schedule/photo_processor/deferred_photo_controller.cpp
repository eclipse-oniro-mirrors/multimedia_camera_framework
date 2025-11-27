/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "deferred_photo_controller.h"

#include "dp_timer.h"
#include "dp_utils.h"
#include "dp_log.h"
#include "dps_event_report.h"
#include "events_monitor.h"
#include "parameters.h"
#include "camera_dynamic_loader.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredPhotoController::StateListener : public IStateChangeListener<SchedulerType, SchedulerInfo> {
public:
    explicit StateListener(const std::weak_ptr<DeferredPhotoController>& controller) : controller_(controller)
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
    std::weak_ptr<DeferredPhotoController> controller_;
};

DeferredPhotoController::DeferredPhotoController(const int32_t userId,
    const std::shared_ptr<DeferredPhotoProcessor>& processor)
    : userId_(userId), photoProcessor_(processor)
{
    DP_DEBUG_LOG("entered, userId: %{public}d", userId_);
}

DeferredPhotoController::~DeferredPhotoController()
{
    DP_INFO_LOG("entered, userId: %{public}d", userId_);
}

int32_t DeferredPhotoController::Initialize()
{
    DP_DEBUG_LOG("entered, userId: %{public}d", userId_);
    DP_CHECK_ERROR_RETURN_RET_LOG(photoProcessor_ == nullptr, DP_NULL_POINTER, "DeferredPhotoProcessor is nullptr.");

    photoStrategyCenter_ = PhotoStrategyCenter::Create(photoProcessor_->GetRepository());
    DP_CHECK_ERROR_RETURN_RET_LOG(photoStrategyCenter_ == nullptr, DP_NULL_POINTER, "PhotoStrategyCenter is nullptr.");

    photoStateChangeListener_ = std::make_shared<StateListener>(weak_from_this());
    photoStrategyCenter_->RegisterStateChangeListener(photoStateChangeListener_);
    return DP_OK;
}

std::shared_ptr<DeferredPhotoProcessor> DeferredPhotoController::GetPhotoProcessor()
{
    DP_DEBUG_LOG("entered");
    return photoProcessor_;
}

void DeferredPhotoController::OnPhotoJobChanged()
{
    TryDoSchedule();
}

void DeferredPhotoController::OnSchedulerChanged(const SchedulerType& type, const SchedulerInfo& scheduleInfo)
{
    DP_INFO_LOG("DPS_PHOTO: Photo isNeedStop: %{public}d, isNeedInterrupt: %{public}d",
        scheduleInfo.isNeedStop, scheduleInfo.isNeedInterrupt);

    if (photoProcessor_->HasRunningJob() && (scheduleInfo.isNeedInterrupt || scheduleInfo.isNeedStop)) {
        photoProcessor_->Interrupt();
    }

    if (scheduleInfo.isNeedStop) {
        if (type == PHOTO_CAMERA_STATE) {
            scheduleState_ = DpsStatus::DPS_SESSION_STATE_PREEMPTED;
            photoProcessor_->NotifyScheduleState(scheduleState_);
        }
        return;
    }

    TryDoSchedule();
}

void DeferredPhotoController::TryDoSchedule()
{
    auto job = photoStrategyCenter_->GetJob();
    DP_INFO_LOG("DPS_PHOTO: strategy get work: %{public}d", job != nullptr);
    NotifyScheduleState(job != nullptr);
    if (job == nullptr) {
        // 重置底层性能模式，避免功耗增加
        SetDefaultExecutionMode();
        return;
    }

    if (photoProcessor_->HasRunningJob()) {
        return;
    }

    DP_INFO_LOG("DPS_PHOTO: imageId: %{public}s, status: %{public}d, priority: %{public}d",
        job->GetImageId().c_str(), job->GetCurStatus(), job->GetCurPriority());
    DoProcess(job);
}

void DeferredPhotoController::DoProcess(const DeferredPhotoJobPtr& job)
{
    DP_CHECK_ERROR_RETURN_LOG(photoProcessor_ == nullptr, "DeferredPhotoProcessor is nullptr.");
    photoProcessor_->DoProcess(job);
}

void DeferredPhotoController::SetDefaultExecutionMode()
{
    DP_CHECK_ERROR_RETURN_LOG(photoProcessor_ == nullptr, "DeferredPhotoProcessor is nullptr.");
    photoProcessor_->SetDefaultExecutionMode();
}

void DeferredPhotoController::NotifyScheduleState(bool workAvailable)
{
    DpsStatus scheduleState = DpsStatus::DPS_SESSION_STATE_IDLE;
    if (workAvailable || photoProcessor_->HasRunningJob()) {
        scheduleState = DpsStatus::DPS_SESSION_STATE_RUNNING;
    } else {
        if (photoProcessor_->IsIdleState()) {
            scheduleState = DpsStatus::DPS_SESSION_STATE_IDLE;
            // if there have no job in dps, unload libcamera_dynamic_picture.z.so
            CameraDynamicLoader::FreeDynamicLibDelayed(PICTURE_SO, LIB_DELAYED_UNLOAD_TIME);
        } else {
            if (photoStrategyCenter_->GetHdiStatus() != HdiStatus::HDI_READY) {
                scheduleState = DpsStatus::DPS_SESSION_STATE_SUSPENDED;
            } else {
                scheduleState = DpsStatus::DPS_SESSION_STATE_RUNNABLE;
            }
        }
    }
    DP_INFO_LOG("entered, curScheduleState: %{public}d, newScheduleState: %{public}d", scheduleState_, scheduleState);
    if (scheduleState != scheduleState_) {
        scheduleState_ = scheduleState;
        photoProcessor_->NotifyScheduleState(scheduleState_);
    }
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS