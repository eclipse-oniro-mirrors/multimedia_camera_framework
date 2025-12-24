/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "photo_strategy_center.h"

#include "dp_log.h"
#include "dps_event_report.h"
#include "events_info.h"
#include "events_monitor.h"
#include "interrupt_state.h"
#include "photo_cache_state.h"
#include "photo_camera_state.h"
#include "photo_hal_state.h"
#include "photo_media_library_state.h"
#include "photo_temperature_state.h"
#include "photo_trailing_state.h"
#include "state_factory.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
PhotoEventsListener::PhotoEventsListener(const std::weak_ptr<PhotoStrategyCenter>& strategyCenter)
    : strategyCenter_(strategyCenter)
{
    DP_DEBUG_LOG("entered");
}

void PhotoEventsListener::OnEventChange(EventType event, int32_t value)
{
    DP_DEBUG_LOG("entered, event: %{public}d", event);
    auto strategy = strategyCenter_.lock();
    DP_CHECK_ERROR_RETURN_LOG(strategy == nullptr, "PhotoStrategyCenter is nullptr.");
    strategy->HandleEventChanged(event, value);
    DPSEventReport::GetInstance().SetEventType(event);
}

PhotoStrategyCenter::PhotoStrategyCenter(const std::shared_ptr<PhotoJobRepository>& repository)
    : repository_(repository)
{
    DP_DEBUG_LOG("entered.");
}

PhotoStrategyCenter::~PhotoStrategyCenter()
{
    DP_INFO_LOG("entered.");
    eventHandlerList_.clear();
}

int32_t PhotoStrategyCenter::Initialize()
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(repository_ == nullptr, DP_NULL_POINTER, "PhotoRepository is nullptr");

    InitHandleEvent();
    eventsListener_ = std::make_shared<PhotoEventsListener>(weak_from_this());
    EventsMonitor::GetInstance().RegisterEventsListener({
        CAMERA_SESSION_STATUS_EVENT,
        TRAILING_STATUS_EVENT,
        PHOTO_HDI_STATUS_EVENT,
        MEDIA_LIBRARY_STATUS_EVENT,
        THERMAL_LEVEL_STATUS_EVENT,
        INTERRUPT_EVENT,
        PHOTO_CACHE_EVENT},
        eventsListener_);
    return DP_OK;
}

void PhotoStrategyCenter::InitHandleEvent()
{
    REGISTER_STATE(InterruptState, PHOTO_INTERRUPT_STATE, NO_INTERRUPT);
    REGISTER_STATE(PhotoCameraState, PHOTO_CAMERA_STATE, SYSTEM_CAMERA_CLOSED);
    REGISTER_STATE(PhotoHalState, PHOTO_HAL_STATE, HDI_DISCONNECTED);
    REGISTER_STATE(PhotoMediaLibraryState, PHOTO_MEDIA_LIBRARY_STATE, MEDIA_LIBRARY_DISCONNECTED);
    REGISTER_STATE(PhotoTemperatureState, PHOTO_THERMAL_LEVEL_STATE,
        ConvertPhotoThermalLevel(EventsInfo::GetInstance().GetThermalLevel()));
    REGISTER_STATE(PhotoTrailingState, PHOTO_TRAILING_STATE, CAMERA_ON_STOP_TRAILING);
    REGISTER_STATE(PhotoCacheState, PHOTO_CACHE_STATE, NO_CACHE);
    eventHandlerList_ = {
        {CAMERA_SESSION_STATUS_EVENT, [this](int32_t value){ HandleCameraEvent(value); }},
        {TRAILING_STATUS_EVENT, [this](int32_t value){ HandleTrailingEvent(value); }},
        {PHOTO_HDI_STATUS_EVENT, [this](int32_t value){ HandleHalEvent(value); }},
        {MEDIA_LIBRARY_STATUS_EVENT, [this](int32_t value){ HandleMedialLibraryEvent(value); }},
        {THERMAL_LEVEL_STATUS_EVENT, [this](int32_t value){ HandleTemperatureEvent(value); }},
        {INTERRUPT_EVENT, [this](int32_t value){ HandleInterruptEvent(value); }},
        {PHOTO_CACHE_EVENT, [this](int32_t value){ HandleCacheEvent(value); }}
    };
}

bool PhotoStrategyCenter::IsReady()
{
    DP_INFO_LOG("DPS_PHOTO: SchedulerOk is: %{public}d", !isNeedStop_);
    return !isNeedStop_;
}

void PhotoStrategyCenter::HandleEventChanged(EventType event, int32_t value)
{
    DP_DEBUG_LOG("DPS_EVENT: eventType: %{public}d, value: %{public}d", event, value);
    auto item = eventHandlerList_.find(event);
    if (item != eventHandlerList_.end()) {
        item->second(value);
    } else {
        DP_WARNING_LOG("not support handle event: %{public}d", event);
    }
}

void PhotoStrategyCenter::RegisterStateChangeListener(const std::weak_ptr<PhotoStateListener>& listener)
{
    photoStateChangeListener_ = listener;
}

DeferredPhotoJobPtr PhotoStrategyCenter::GetJob()
{
    auto jobPtr = repository_->GetJob();
    DP_CHECK_RETURN_RET(jobPtr == nullptr, nullptr);
    auto mode = GetExecutionMode(jobPtr->GetCurPriority());
    DP_CHECK_RETURN_RET(mode == ExecutionMode::DUMMY, nullptr);
    jobPtr->SetExecutionMode(mode);
    return jobPtr;
}

ExecutionMode PhotoStrategyCenter::GetExecutionMode(const JobPriority priority)
{
    if (priority == JobPriority::HIGH) {
        DP_CHECK_RETURN_RET(EventsInfo::GetInstance().GetCameraState() == CameraSessionStatus::SYSTEM_CAMERA_OPEN,
            ExecutionMode::DUMMY);
        return ExecutionMode::HIGH_PERFORMANCE;
    }
    DP_CHECK_RETURN_RET(!IsReady(), ExecutionMode::DUMMY);
    return ExecutionMode::LOAD_BALANCE;
}

void PhotoStrategyCenter::HandleCameraEvent(int32_t value)
{
    DP_DEBUG_LOG("CameraEvent value: %{public}d", value);
    int32_t trailingState = TrailingStatus::CAMERA_ON_STOP_TRAILING;
    switch (value) {
        case CameraSessionStatus::SYSTEM_CAMERA_CLOSED:
            trailingState = TrailingStatus::SYSTEM_CAMERA_OFF_START_TRAILING;
            break;
        case CameraSessionStatus::NORMAL_CAMERA_CLOSED:
            trailingState = TrailingStatus::NORMAL_CAMERA_OFF_START_TRAILING;
            break;
        default:
            break;
    }
    if (auto scheduleState = GetSchedulerState(PHOTO_TRAILING_STATE)) {
        scheduleState->UpdateSchedulerInfo(trailingState);
    }
    UpdateValue(PHOTO_CAMERA_STATE, value);
}

void PhotoStrategyCenter::HandleHalEvent(int32_t value)
{
    DP_DEBUG_LOG("HalEvent value: %{public}d", value);
    UpdateValue(PHOTO_HAL_STATE, value);
}

void PhotoStrategyCenter::HandleTrailingEvent(int32_t value)
{
    DP_DEBUG_LOG("TrailingEvent value: %{public}d", value);
    UpdateValue(PHOTO_TRAILING_STATE, value);
}

void PhotoStrategyCenter::HandleMedialLibraryEvent(int32_t value)
{
    DP_DEBUG_LOG("MedialLibraryEvent value: %{public}d", value);
    UpdateValue(PHOTO_MEDIA_LIBRARY_STATE, value);
}

void PhotoStrategyCenter::HandleTemperatureEvent(int32_t value)
{
    DP_DEBUG_LOG("TemperatureEvent value: %{public}d", value);
    auto level = ConvertPhotoThermalLevel(value);
    UpdateValue(PHOTO_THERMAL_LEVEL_STATE, level);
}

void PhotoStrategyCenter::HandleInterruptEvent(int32_t value)
{
    DP_DEBUG_LOG("InterruptEvent");
    UpdateValue(PHOTO_INTERRUPT_STATE, value);
}

void PhotoStrategyCenter::HandleCacheEvent(int32_t value)
{
    DP_DEBUG_LOG("PhotoCacheEvent");
    UpdateValue(PHOTO_CACHE_STATE, value);
}

void PhotoStrategyCenter::UpdateValue(SchedulerType type, int32_t value)
{
    auto scheduleState = GetSchedulerState(type);
    DP_CHECK_ERROR_RETURN_LOG(scheduleState == nullptr, "UpdatePhotoValue failed.");
    if (scheduleState->UpdateSchedulerInfo(value)) {
        auto info = ReevaluateSchedulerInfo();
        isNeedStop_ = info.isNeedStop;
        auto listener = photoStateChangeListener_.lock();
        DP_CHECK_ERROR_RETURN_LOG(listener == nullptr, "PhotoStateChangeListener is nullptr.");
        listener->OnSchedulerChanged(type, info);
    }
}

SchedulerInfo PhotoStrategyCenter::ReevaluateSchedulerInfo()
{
    SchedulerInfo cameraInfo = GetSchedulerInfo(PHOTO_CAMERA_STATE);
    SchedulerInfo halInfo = GetSchedulerInfo(PHOTO_HAL_STATE);
    SchedulerInfo mediaLibraryInfo = GetSchedulerInfo(PHOTO_MEDIA_LIBRARY_STATE);
    SchedulerInfo interruptInfo = GetSchedulerInfo(PHOTO_INTERRUPT_STATE);
    SchedulerInfo cacheInfo = GetSchedulerInfo(PHOTO_CACHE_STATE);
    bool isNeedStop = cameraInfo.isNeedStop || halInfo.isNeedStop || mediaLibraryInfo.isNeedStop
        || interruptInfo.isNeedInterrupt || cacheInfo.isNeedStop;
    bool isNeedInterrupt = cameraInfo.isNeedInterrupt || interruptInfo.isNeedInterrupt;
    SchedulerInfo result = {isNeedStop, isNeedInterrupt};
    DP_CHECK_RETURN_RET_LOG(isNeedStop, result,
        "DPS_EVENT: Photo stop schedule, hdi: %{public}d, mediaLibrary: %{public}d, "
        "camera: %{public}d, cache: %{public}d",
        halInfo.isNeedStop, mediaLibraryInfo.isNeedStop, cameraInfo.isNeedStop, cacheInfo.isNeedStop);

    SchedulerInfo trailingInfo = GetSchedulerInfo(PHOTO_TRAILING_STATE);
    DP_CHECK_RETURN_RET_LOG(!trailingInfo.isNeedStop, trailingInfo, "DPS_EVENT: Photo try do schedule in trailing.");

    DP_INFO_LOG("DPS_EVENT: Photo try do schedule in normal.");
    return GetSchedulerInfo(PHOTO_THERMAL_LEVEL_STATE);
}

SchedulerInfo PhotoStrategyCenter::GetSchedulerInfo(SchedulerType type)
{
    SchedulerInfo defaultInfo;
    auto scheduleState = GetSchedulerState(type);
    DP_CHECK_ERROR_RETURN_RET_LOG(scheduleState == nullptr, defaultInfo, "Not find SchedulerType: %{public}d", type);
    return scheduleState->GetSchedulerInfo();
}

std::shared_ptr<IState> PhotoStrategyCenter::GetSchedulerState(SchedulerType type)
{
    return StateFactory::Instance().GetState(type);
}

HdiStatus PhotoStrategyCenter::GetHdiStatus()
{
    auto halState = GetSchedulerState(PHOTO_HAL_STATE);
    DP_CHECK_ERROR_RETURN_RET_LOG(halState == nullptr, HDI_DISCONNECTED, "Not find HAL state.");
    return static_cast<HdiStatus>(halState->GetState());
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS