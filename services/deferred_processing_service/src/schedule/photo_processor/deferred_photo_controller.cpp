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
    explicit EventsListener(DeferredPhotoController* controller)
        : controller_(controller)
    {
        DP_DEBUG_LOG("entered");
    }
    ~EventsListener()
    {
        DP_DEBUG_LOG("entered");
        controller_ = nullptr;
    }

    void OnEventChange(EventType event, int value) override
    {
        DP_INFO_LOG("entered, event: %d", event);
        switch (event) {
            case EventType::CAMERA_SESSION_STATUS_EVENT:
                controller_->NotifyCameraStatusChanged(static_cast<CameraSessionStatus>(value));
                break;
            case EventType::HDI_STATUS_EVENT:
                controller_->NotifyHdiStatusChanged(static_cast<HdiStatus>(value));
                break;
            case EventType::MEDIA_LIBRARY_STATUS_EVENT:
                controller_->NotifyMediaLibStatusChanged(static_cast<MediaLibraryStatus>(value));
                break;
            case EventType::SYSTEM_PRESSURE_LEVEL_EVENT:
                controller_->NotifyPressureLevelChanged(static_cast<SystemPressureLevel>(value));
                break;
            default:
                break;
        }
        DPSEventReport::GetInstance().SetEventType(event);
    }

private:
    DeferredPhotoController* controller_;
};

class DeferredPhotoController::PhotoJobRepositoryListener : public IPhotoJobRepositoryListener {
public:
    explicit PhotoJobRepositoryListener(DeferredPhotoController* controller)
        : controller_(controller)
    {
        DP_DEBUG_LOG("entered");
    }
    ~PhotoJobRepositoryListener()
    {
        DP_DEBUG_LOG("entered");
        controller_ = nullptr;
    }

    void OnPhotoJobChanged(bool priorityChanged, bool statusChanged, DeferredPhotoJobPtr jobPtr) override
    {
        controller_->OnPhotoJobChanged(priorityChanged, statusChanged, jobPtr);
    }

private:
    DeferredPhotoController* controller_;
};

DeferredPhotoController::DeferredPhotoController(int userId, std::shared_ptr<PhotoJobRepository> repository,
    std::shared_ptr<DeferredPhotoProcessor> processor)
    : userId_(userId),
      callbackHandle_(0),
      isWaitForUser_(false),
      scheduleState_(DpsStatus::DPS_SESSION_STATE_IDLE),
      photoJobRepository_(repository),
      photoProcessor_(processor),
      userInitiatedStrategy_(nullptr),
      backgroundStrategy_(nullptr),
      eventsListener_(nullptr),
      photoJobRepositoryListener_(nullptr)
{
    DP_DEBUG_LOG("entered, userid: %d", userId_);
    //创建策略
    userInitiatedStrategy_ = std::make_unique<UserInitiatedStrategy>(repository);
    backgroundStrategy_ = std::make_unique<BackgroundStrategy>(repository);
    //注册事件监听
    eventsListener_ = std::make_shared<EventsListener>(this);
    EventsMonitor::GetInstance().RegisterEventsListener(userId_, {EventType::CAMERA_SESSION_STATUS_EVENT,
        EventType::HDI_STATUS_EVENT, EventType::MEDIA_LIBRARY_STATUS_EVENT, EventType::SYSTEM_PRESSURE_LEVEL_EVENT},
        eventsListener_);
    //注册任务监听
    photoJobRepositoryListener_ = std::make_shared<PhotoJobRepositoryListener>(this);
    photoJobRepository_->RegisterJobListener(photoJobRepositoryListener_);
}

DeferredPhotoController::~DeferredPhotoController()
{
    DP_DEBUG_LOG("entered, userid: %d", userId_);
    photoProcessor_ = nullptr;
    photoJobRepository_ = nullptr;
    userInitiatedStrategy_ = nullptr;
    backgroundStrategy_ = nullptr;
    eventsListener_ = nullptr;
}

void DeferredPhotoController::Initialize()
{
    DP_DEBUG_LOG("entered, userid: %d", userId_);
}

void DeferredPhotoController::TryDoSchedule()
{
    DP_INFO_LOG("entered");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto work = userInitiatedStrategy_->GetWork();
    DP_INFO_LOG("userInitiatedStrategy_ get work: %d", work != nullptr);
    if (work != nullptr) {
        StopWaitForUser();
    }
    if (work == nullptr && !isWaitForUser_) {
        work = backgroundStrategy_->GetWork();
        DP_INFO_LOG("backgroundStrategy_ get work: %d", work != nullptr);
    }
    DP_INFO_LOG("all strategy get work: %d", work != nullptr);
    NotifyScheduleState(work != nullptr);
    if (work == nullptr) {
        return;
    }
    if ((photoJobRepository_->GetRunningJobCounts()) < (photoProcessor_->GetConcurrency(work->GetExecutionMode()))) {
        PostProcess(work);
    }
    return;
}

void DeferredPhotoController::PostProcess(std::shared_ptr<DeferredPhotoWork> work)
{
    DP_DEBUG_LOG("entered");
    photoProcessor_->PostProcess(work);
}

void DeferredPhotoController::NotifyPressureLevelChanged(SystemPressureLevel level)
{
    backgroundStrategy_->NotifyPressureLevelChanged(level);
    TryDoSchedule();
    return;
}

void DeferredPhotoController::NotifyHdiStatusChanged(HdiStatus status)
{
    backgroundStrategy_->NotifyHdiStatusChanged(status);
    TryDoSchedule();
    return;
}

void DeferredPhotoController::NotifyMediaLibStatusChanged(MediaLibraryStatus status)
{
    backgroundStrategy_->NotifyMediaLibStatusChanged(status);
    if (status == MediaLibraryStatus::MEDIA_LIBRARY_AVAILABLE) {
        TryDoSchedule();
    }
    return;
}

void DeferredPhotoController::NotifyCameraStatusChanged(CameraSessionStatus status)
{
    backgroundStrategy_->NotifyCameraStatusChanged(status);
    if (status == CameraSessionStatus::SYSTEM_CAMERA_OPEN || status == CameraSessionStatus::NORMAL_CAMERA_OPEN) {
        photoProcessor_->Interrupt();
    }
    if (status == CameraSessionStatus::SYSTEM_CAMERA_CLOSED || status == CameraSessionStatus::NORMAL_CAMERA_CLOSED) {
        TryDoSchedule();
    }
    return;
}

//来自任务仓库的事件
void DeferredPhotoController::OnPhotoJobChanged(bool priorityChanged, bool statusChanged, DeferredPhotoJobPtr jobPtr)
{
    DP_INFO_LOG("entered, priorityChanged: %d, statusChanged: %d , imageId: %s",
        priorityChanged, statusChanged, jobPtr->GetImageId().c_str());
    if (priorityChanged && statusChanged) {
        if (jobPtr->GetPrePriority() == PhotoJobPriority::HIGH && jobPtr->GetPreStatus() == PhotoJobStatus::RUNNING) {
            StartWaitForUser();
        }
    }
    TryDoSchedule();
    return;
}

void DeferredPhotoController::StartWaitForUser()
{
    DP_INFO_LOG("entered");
    isWaitForUser_ = true;
    GetGlobalWatchdog().StartMonitor(callbackHandle_, DURATIONMS_500, [this](uint32_t handle) {
        isWaitForUser_ = false;
        DP_INFO_LOG("DeferredPhotoController, wait for user ended, handle: %d, try do schedule",
            static_cast<int>(handle));
        TryDoSchedule();
    });
    DP_INFO_LOG("DeferredPhotoController, wait for user started, handle: %d", static_cast<int>(callbackHandle_));
}

void DeferredPhotoController::StopWaitForUser()
{
    DP_INFO_LOG("entered");
    isWaitForUser_ = false;
    GetGlobalWatchdog().StopMonitor(callbackHandle_);
}

void DeferredPhotoController::NotifyScheduleState(bool workAvailable)
{
    DP_INFO_LOG("entered, workAvailable: %d", workAvailable);
    DpsStatus scheduleState = DpsStatus::DPS_SESSION_STATE_IDLE;
    if (workAvailable || photoJobRepository_->GetRunningJobCounts() > 0) {
        scheduleState =  DpsStatus::DPS_SESSION_STATE_RUNNING;
    } else {
        if (photoJobRepository_->GetOfflineJobSize() == 0) {
            scheduleState =  DpsStatus::DPS_SESSION_STATE_IDLE;
        } else {
            if (backgroundStrategy_->GetHdiStatus() != HdiStatus::HDI_READY) {
                scheduleState =  DpsStatus::DPS_SESSION_STATE_SUSPENDED;
            } else {
                scheduleState =  DpsStatus::DPS_SESSION_STATE_RUNNALBE;
            }
        }
    }
    DP_INFO_LOG("entered, scheduleState_: %d, scheduleState: %d", scheduleState_, scheduleState);
    if (scheduleState != scheduleState_) {
        scheduleState_ = scheduleState;
        photoProcessor_->NotifyScheduleState(scheduleState_);
    }
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS