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

#include "deferred_photo_controller.h"

#include "basic_definitions.h"
#include "dp_timer.h"
#include "dp_utils.h"
#include "dp_log.h"
#include "events_monitor.h"
#include "dps_event_report.h"

namespace OHOS {
namespace CameraStandard {

namespace {
    constexpr int32_t DURATIONMS_500 = 500;
}

namespace DeferredProcessing {

class DeferredPhotoController::EventsListener : public IEventsListener {
public:
    explicit EventsListener(const std::weak_ptr<DeferredPhotoController>& controller)
        : controller_(controller)
    {
        DP_DEBUG_LOG("entered");
    }
    ~EventsListener() = default;

    void OnEventChange(EventType event, int32_t value) override
    {
        DP_INFO_LOG("entered, event: %{public}d", event);
        auto controller = controller_.lock();
        DP_CHECK_ERROR_RETURN_LOG(controller == nullptr, "photo controller is nullptr.");
        switch (event) {
            case EventType::CAMERA_SESSION_STATUS_EVENT:
                controller->NotifyCameraStatusChanged(static_cast<CameraSessionStatus>(value));
                break;
            case EventType::PHOTO_HDI_STATUS_EVENT:
                controller->NotifyHdiStatusChanged(static_cast<HdiStatus>(value));
                break;
            case EventType::MEDIA_LIBRARY_STATUS_EVENT:
                controller->NotifyMediaLibStatusChanged(static_cast<MediaLibraryStatus>(value));
                break;
            case EventType::THERMAL_LEVEL_STATUS_EVENT:
                controller->NotifyPressureLevelChanged(ConvertPressureLevel(value));
                break;
            default:
                break;
        }
        DPSEventReport::GetInstance().SetEventType(event);
    }

private:
    std::weak_ptr<DeferredPhotoController> controller_;

    SystemPressureLevel ConvertPressureLevel(int32_t level)
    {
        if (level < LEVEL_0 || level > LEVEL_5) {
            return SystemPressureLevel::SEVERE;
        }
        SystemPressureLevel eventLevel = SystemPressureLevel::SEVERE;
        switch (level) {
            case LEVEL_0:
            case LEVEL_1:
                eventLevel = SystemPressureLevel::NOMINAL;
                break;
            case LEVEL_2:
            case LEVEL_3:
            case LEVEL_4:
                eventLevel = SystemPressureLevel::FAIR;
                break;
            default:
                eventLevel = SystemPressureLevel::SEVERE;
                break;
        }
        return eventLevel;
    }
};

class DeferredPhotoController::PhotoJobRepositoryListener : public IPhotoJobRepositoryListener {
public:
    explicit PhotoJobRepositoryListener(const std::weak_ptr<DeferredPhotoController>& controller)
        : controller_(controller)
    {
        DP_DEBUG_LOG("entered");
    }
    ~PhotoJobRepositoryListener() = default;

    void OnPhotoJobChanged(bool priorityChanged, bool statusChanged, DeferredPhotoJobPtr jobPtr) override
    {
        auto controller = controller_.lock();
        DP_CHECK_ERROR_RETURN_LOG(controller == nullptr, "photo controller is nullptr.");
        controller->OnPhotoJobChanged(priorityChanged, statusChanged, jobPtr);
    }

private:
    std::weak_ptr<DeferredPhotoController> controller_;
};

DeferredPhotoController::DeferredPhotoController(const int32_t userId,
    const std::shared_ptr<PhotoJobRepository>& repository, const std::shared_ptr<DeferredPhotoProcessor>& processor)
    : userId_(userId),
      photoJobRepository_(repository),
      photoProcessor_(processor)
{
    DP_DEBUG_LOG("entered, userid: %{public}d", userId_);
}

DeferredPhotoController::~DeferredPhotoController()
{
    DP_DEBUG_LOG("entered, userid: %{public}d", userId_);
}

void DeferredPhotoController::Initialize()
{
    DP_DEBUG_LOG("entered, userid: %{public}d", userId_);
    //创建策略
    userInitiatedStrategy_ = std::make_unique<UserInitiatedStrategy>(photoJobRepository_);
    backgroundStrategy_ = std::make_unique<BackgroundStrategy>(photoJobRepository_);
    //注册事件监听
    eventsListener_ = std::make_shared<EventsListener>(weak_from_this());
    EventsMonitor::GetInstance().RegisterEventsListener(userId_, {
        EventType::CAMERA_SESSION_STATUS_EVENT,
        EventType::PHOTO_HDI_STATUS_EVENT,
        EventType::MEDIA_LIBRARY_STATUS_EVENT,
        EventType::THERMAL_LEVEL_STATUS_EVENT},
        eventsListener_);
    //注册任务监听
    photoJobRepositoryListener_ = std::make_shared<PhotoJobRepositoryListener>(weak_from_this());
    photoJobRepository_->RegisterJobListener(photoJobRepositoryListener_);
    photoProcessor_->Initialize();
}

void DeferredPhotoController::TryDoSchedule()
{
    auto work = userInitiatedStrategy_->GetWork();
    DP_INFO_LOG("DPS_PHOTO: UserInitiated get work: %{public}d", work != nullptr);
    if (work != nullptr) {
        StopWaitForUser();
    }

    if (work == nullptr && timeId_ == INVALID_TIMEID) {
        work = backgroundStrategy_->GetWork();
        DP_INFO_LOG("DPS_PHOTO: Background get work: %{public}d", work != nullptr);
    }

    if (work == nullptr) {
        if (photoJobRepository_->GetRunningJobCounts() == 0) {
            // 重置底层性能模式，避免功耗增加
            SetDefaultExecutionMode();
        }
        return;
    }

    if ((photoJobRepository_->GetRunningJobCounts()) < (photoProcessor_->GetConcurrency(work->GetExecutionMode()))) {
        PostProcess(work);
    }
}

void DeferredPhotoController::PostProcess(std::shared_ptr<DeferredPhotoWork> work)
{
    DP_DEBUG_LOG("entered");
    photoProcessor_->PostProcess(work);
}

void DeferredPhotoController::SetDefaultExecutionMode()
{
    DP_DEBUG_LOG("entered");
    photoProcessor_->SetDefaultExecutionMode();
}

void DeferredPhotoController::NotifyPressureLevelChanged(SystemPressureLevel level)
{
    backgroundStrategy_->NotifyPressureLevelChanged(level);
    TryDoSchedule();
}

void DeferredPhotoController::NotifyHdiStatusChanged(HdiStatus status)
{
    userInitiatedStrategy_->NotifyHdiStatusChanged(status);
    backgroundStrategy_->NotifyHdiStatusChanged(status);
    TryDoSchedule();
}

void DeferredPhotoController::NotifyMediaLibStatusChanged(MediaLibraryStatus status)
{
    userInitiatedStrategy_->NotifyMediaLibStatusChanged(status);
    backgroundStrategy_->NotifyMediaLibStatusChanged(status);
    if (status == MediaLibraryStatus::MEDIA_LIBRARY_AVAILABLE) {
        TryDoSchedule();
    }
}

void DeferredPhotoController::NotifyCameraStatusChanged(CameraSessionStatus status)
{
    userInitiatedStrategy_->NotifyCameraStatusChanged(status);
    backgroundStrategy_->NotifyCameraStatusChanged(status);
    if (status == CameraSessionStatus::SYSTEM_CAMERA_OPEN || status == CameraSessionStatus::NORMAL_CAMERA_OPEN) {
        photoProcessor_->Interrupt();
    }
    if (status == CameraSessionStatus::SYSTEM_CAMERA_CLOSED || status == CameraSessionStatus::NORMAL_CAMERA_CLOSED) {
        TryDoSchedule();
    }
}

//来自任务仓库的事件
void DeferredPhotoController::OnPhotoJobChanged(bool priorityChanged, bool statusChanged, DeferredPhotoJobPtr jobPtr)
{
    DP_INFO_LOG("DPS_PHOTO: priorityChanged: %{public}d, statusChanged: %{public}d, imageId: %{public}s",
        priorityChanged, statusChanged, jobPtr->GetImageId().c_str());
    if (priorityChanged && statusChanged) {
        if (jobPtr->GetPrePriority() == PhotoJobPriority::HIGH && jobPtr->GetPreStatus() == PhotoJobStatus::RUNNING) {
            StartWaitForUser();
        }
    }
    TryDoSchedule();
}

void DeferredPhotoController::StartWaitForUser()
{
    timeId_ = DpsTimer::GetInstance().StartTimer([&]() {
        DP_INFO_LOG("DPS_TIMER: WaitForUser try do schedule, timeId: %{public}u", timeId_);
        timeId_ = INVALID_TIMEID;
        TryDoSchedule();
    }, DURATIONMS_500);
    DP_INFO_LOG("DPS_TIMER: StartWaitForUser timeId: %{public}u", timeId_);
}

void DeferredPhotoController::StopWaitForUser()
{
    DP_INFO_LOG("DPS_TIMER: StopWaitForUser timeId: %{public}u", timeId_);
    DpsTimer::GetInstance().StopTimer(timeId_);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS