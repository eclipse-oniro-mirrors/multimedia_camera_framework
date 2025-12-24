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

#include "video_strategy_center.h"

#include "dps_event_report.h"
#include "events_info.h"
#include "events_monitor.h"
#include "interrupt_state.h"
#include "state_factory.h"
#include "video_battery_level_state.h"
#include "video_battery_state.h"
#include "video_camera_state.h"
#include "video_charging_state.h"
#include "video_hal_state.h"
#include "video_media_library_state.h"
#include "video_photo_process_state.h"
#include "video_process_time_state.h"
#include "video_screen_state.h"
#include "video_temperature_state.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr uint32_t TIME_OK = 0b0;
    constexpr uint32_t SINGLE_TIME_LIMIT = 0b1;
    constexpr uint32_t TOTAL_TIME_LIMIT = 0b10;
    constexpr int32_t DEFAULT_TIME = -1;
}

class VideoStrategyCenter::EventsListener : public IEventsListener {
public:
    explicit EventsListener(const std::weak_ptr<VideoStrategyCenter>& strategyCenter)
        : strategyCenter_(strategyCenter)
    {
        DP_DEBUG_LOG("entered");
    }

    ~EventsListener()
    {
        DP_DEBUG_LOG("entered");
    }

    void OnEventChange(EventType event, int32_t value) override
    {
        DP_DEBUG_LOG("entered, event: %{public}d", event);
        auto strategy = strategyCenter_.lock();
        DP_CHECK_ERROR_RETURN_LOG(strategy == nullptr, "VideoStrategyCenter is nullptr.");
        strategy->HandleEventChanged(event, value);
        DPSEventReport::GetInstance().SetEventType(event);
    }

private:
    std::weak_ptr<VideoStrategyCenter> strategyCenter_;
};

VideoStrategyCenter::VideoStrategyCenter(const std::shared_ptr<VideoJobRepository>& repository)
    : repository_(repository)
{
    DP_DEBUG_LOG("entered.");
}

VideoStrategyCenter::~VideoStrategyCenter()
{
    DP_INFO_LOG("entered.");
    eventHandlerList_.clear();
}

int32_t VideoStrategyCenter::Initialize()
{
    InitHandleEvent();
    auto state = EventsInfo::GetInstance().GetChargingState();
    isCharging_ = state == ChargingStatus::CHARGING;
    eventsListener_ = std::make_shared<EventsListener>(weak_from_this());
    EventsMonitor::GetInstance().RegisterEventsListener({
        CAMERA_SESSION_STATUS_EVENT,
        VIDEO_HDI_STATUS_EVENT,
        MEDIA_LIBRARY_STATUS_EVENT,
        THERMAL_LEVEL_STATUS_EVENT,
        SCREEN_STATUS_EVENT,
        BATTERY_STATUS_EVENT,
        BATTERY_LEVEL_STATUS_EVENT,
        CHARGING_STATUS_EVENT,
        PHOTO_PROCESS_STATUS_EVENT,
        INTERRUPT_EVENT},
        eventsListener_);
    return DP_OK;
}

void VideoStrategyCenter::InitHandleEvent()
{
    REGISTER_STATE(InterruptState, INTERRUPT_STATE, NO_INTERRUPT);
    REGISTER_STATE(VideoBatteryLevelState, BATTERY_LEVEL_STATE, EventsInfo::GetInstance().GetBatteryLevel());
    REGISTER_STATE(VideoBatteryState, BATTERY_STATE, EventsInfo::GetInstance().GetBatteryState());
    REGISTER_STATE(VideoCameraState, VIDEO_CAMERA_STATE, SYSTEM_CAMERA_CLOSED);
    REGISTER_STATE(VideoChargingState, CHARGING_STATE, EventsInfo::GetInstance().GetChargingState());
    REGISTER_STATE(VideoHalState, VIDEO_HAL_STATE, HDI_DISCONNECTED);
    REGISTER_STATE(VideoMediaLibraryState, VIDEO_MEDIA_LIBRARY_STATE, MEDIA_LIBRARY_DISCONNECTED);
    REGISTER_STATE(VideoPhotoProcessState, PHOTO_PROCESS_STATE, IDLE);
    REGISTER_STATE(VideoScreenState, SCREEN_STATE, EventsInfo::GetInstance().GetScreenState());
    REGISTER_STATE(VideoTemperatureState, VIDEO_THERMAL_LEVEL_STATE,
        ConvertVideoThermalLevel(EventsInfo::GetInstance().GetThermalLevel()));
    eventHandlerList_ = {
        {CAMERA_SESSION_STATUS_EVENT, [this](int32_t value){ HandleCameraEvent(value); }},
        {VIDEO_HDI_STATUS_EVENT, [this](int32_t value){ HandleHalEvent(value); }},
        {MEDIA_LIBRARY_STATUS_EVENT, [this](int32_t value){ HandleMedialLibraryEvent(value); }},
        {SCREEN_STATUS_EVENT, [this](int32_t value){ HandleScreenEvent(value); }},
        {CHARGING_STATUS_EVENT, [this](int32_t value){ HandleChargingEvent(value); }},
        {BATTERY_STATUS_EVENT, [this](int32_t value){ HandleBatteryEvent(value); }},
        {BATTERY_LEVEL_STATUS_EVENT, [this](int32_t value){ HandleBatteryLevelEvent(value); }},
        {THERMAL_LEVEL_STATUS_EVENT, [this](int32_t value){ HandleTemperatureEvent(value); }},
        {PHOTO_PROCESS_STATUS_EVENT, [this](int32_t value){ HandlePhotoProcessEvent(value); }},
        {INTERRUPT_EVENT, [this](int32_t value){ HandleInterruptEvent(value); }}
    };
}

void VideoStrategyCenter::HandleEventChanged(EventType event, int32_t value)
{
    DP_DEBUG_LOG("DPS_EVENT: eventType: %{public}d, value: %{public}d", event, value);
    auto item = eventHandlerList_.find(event);
    if (item != eventHandlerList_.end()) {
        item->second(value);
    } else {
        DP_WARNING_LOG("not support handle event: %{public}d", event);
    }
}

void VideoStrategyCenter::RegisterStateChangeListener(const std::weak_ptr<VideoStateListener>& listener)
{
    videoStateChangeListener_ = listener;
}

DeferredVideoJobPtr VideoStrategyCenter::GetJob()
{
    auto jobPtr = repository_->GetJob();
    DP_CHECK_RETURN_RET(jobPtr == nullptr, nullptr);
    ExecutionMode mode = GetExecutionMode(jobPtr->GetCurPriority());
    DP_CHECK_RETURN_RET(mode == ExecutionMode::DUMMY, nullptr);
    jobPtr->SetExecutionMode(mode);
    jobPtr->SetChargState(isCharging_);
    return jobPtr;
}

ExecutionMode VideoStrategyCenter::GetExecutionMode(const JobPriority priority)
{
    if (priority == JobPriority::HIGH) {
        DP_CHECK_RETURN_RET(EventsInfo::GetInstance().GetCameraState() <= CameraSessionStatus::NORMAL_CAMERA_OPEN,
            ExecutionMode::DUMMY);
        return ExecutionMode::LOAD_BALANCE;
    }
    if (isCharging_) {
        DP_CHECK_RETURN_RET(IsReady(), ExecutionMode::LOAD_BALANCE);
    } else {
        DP_CHECK_RETURN_RET(IsReady() && IsTimeReady(), ExecutionMode::LOAD_BALANCE);
    }
    return ExecutionMode::DUMMY;
}

void VideoStrategyCenter::HandleCameraEvent(int32_t value)
{
    DP_DEBUG_LOG("CameraEvent value: %{public}d", value);
    UpdateValue(VIDEO_CAMERA_STATE, value);
}

void VideoStrategyCenter::HandleHalEvent(int32_t value)
{
    DP_DEBUG_LOG("HalEvent value: %{public}d", value);
    UpdateValue(VIDEO_HAL_STATE, value);
}

void VideoStrategyCenter::HandleMedialLibraryEvent(int32_t value)
{
    DP_DEBUG_LOG("MedialLibraryEvent value: %{public}d", value);
    UpdateValue(VIDEO_MEDIA_LIBRARY_STATE, value);
}

void VideoStrategyCenter::HandleScreenEvent(int32_t value)
{
    DP_DEBUG_LOG("ScreenEvent value: %{public}d", value);
    DP_CHECK_EXECUTE(value == ScreenStatus::SCREEN_ON, UpdateSingleTime(true));
    UpdateValue(SCREEN_STATE, value);
}

void VideoStrategyCenter::HandleChargingEvent(int32_t value)
{
    DP_DEBUG_LOG("ChargingEvent value: %{public}d", value);
    isCharging_ = value == ChargingStatus::CHARGING;
    DP_CHECK_EXECUTE(isCharging_, UpdateAvailableTime());
    UpdateValue(CHARGING_STATE, value);
}

void VideoStrategyCenter::HandleBatteryEvent(int32_t value)
{
    DP_DEBUG_LOG("BatteryEvent value: %{public}d", value);
    UpdateValue(BATTERY_STATE, value);
}

void VideoStrategyCenter::HandleBatteryLevelEvent(int32_t value)
{
    DP_DEBUG_LOG("BatteryLevelEvent value: %{public}d", value);
    UpdateValue(BATTERY_LEVEL_STATE, value);
}

void VideoStrategyCenter::HandleTemperatureEvent(int32_t value)
{
    DP_DEBUG_LOG("TemperatureEvent value: %{public}d", value);
    auto level = ConvertVideoThermalLevel(value);
    UpdateValue(VIDEO_THERMAL_LEVEL_STATE, level);
}

void VideoStrategyCenter::HandlePhotoProcessEvent(int32_t value)
{
    DP_DEBUG_LOG("PhotoProcessEvent value: %{public}d", value);
    auto state = ConvertProcessState(value);
    UpdateValue(PHOTO_PROCESS_STATE, state);
}

void VideoStrategyCenter::HandleInterruptEvent(int32_t value)
{
    DP_DEBUG_LOG("InterruptEvent");
    UpdateValue(INTERRUPT_STATE, value);
}

void VideoStrategyCenter::UpdateValue(SchedulerType type, int32_t value)
{
    auto scheduleState = GetSchedulerState(type);
    DP_CHECK_ERROR_RETURN_LOG(scheduleState == nullptr, "UpdateVideoValue failed.");
    if (scheduleState->UpdateSchedulerInfo(value)) {
        auto info = ReevaluateSchedulerInfo();
        isNeedStop_ = info.isNeedStop;
        auto listener = videoStateChangeListener_.lock();
        DP_CHECK_ERROR_RETURN_LOG(listener == nullptr, "VideoStateChangeListener is nullptr.");
        listener->OnSchedulerChanged(type, info);
    }
}

void VideoStrategyCenter::UpdateSingleTime(bool isOk)
{
    isOk ? (isTimeOk_ &= ~SINGLE_TIME_LIMIT) : (isTimeOk_ |= SINGLE_TIME_LIMIT);
    DP_CHECK_EXECUTE(isOk, singleTime_ = ONCE_PROCESS_TIME);
    DP_INFO_LOG("DPS_VIDEO: Process time type: %{public}d", isTimeOk_);
}

void VideoStrategyCenter::UpdateAvailableTime(int32_t useTime)
{
    if (useTime == DEFAULT_TIME) {
        availableTime_ = TOTAL_PROCESS_TIME;
    } else {
        availableTime_ -= useTime;
        singleTime_ -= useTime;
    }

    availableTime_ > 0 ? (isTimeOk_ &= ~TOTAL_TIME_LIMIT) : (isTimeOk_ |= TOTAL_TIME_LIMIT);
    DP_CHECK_EXECUTE(availableTime_ < 0, availableTime_ = 0);
    DP_CHECK_EXECUTE(singleTime_ < 0, singleTime_ = 0);
    DP_INFO_LOG("DPS_VIDEO: Single processTime: %{public}d, Available processTime: %{public}d, type: %{public}d",
        singleTime_, availableTime_, isTimeOk_);
}

bool VideoStrategyCenter::IsReady()
{
    DP_INFO_LOG("DPS_VIDEO: SchedulerOk is: %{public}d",  !isNeedStop_);
    return !isNeedStop_;
}

bool VideoStrategyCenter::IsTimeReady()
{
    DP_INFO_LOG("DPS_VIDEO: TimeOk is: %{public}d", isTimeOk_);
    return isTimeOk_ == TIME_OK;
}

int32_t VideoStrategyCenter::GetAvailableTime()
{
    return std::min(singleTime_, availableTime_);
}

SchedulerInfo VideoStrategyCenter::ReevaluateSchedulerInfo()
{
    SchedulerInfo cameraInfo = GetSchedulerInfo(VIDEO_CAMERA_STATE);
    SchedulerInfo halInfo = GetSchedulerInfo(VIDEO_HAL_STATE);
    SchedulerInfo mediaLibraryInfo = GetSchedulerInfo(VIDEO_MEDIA_LIBRARY_STATE);
    SchedulerInfo screenInfo = GetSchedulerInfo(SCREEN_STATE);
    SchedulerInfo temperatureInfo = GetSchedulerInfo(VIDEO_THERMAL_LEVEL_STATE);
    SchedulerInfo photoProcessInfo = GetSchedulerInfo(PHOTO_PROCESS_STATE);
    SchedulerInfo chargingInfo = GetSchedulerInfo(CHARGING_STATE);
    SchedulerInfo interruptInfo = GetSchedulerInfo(INTERRUPT_STATE);
    bool isNeedStop = cameraInfo.isNeedStop || halInfo.isNeedStop || mediaLibraryInfo.isNeedStop
        || screenInfo.isNeedStop || temperatureInfo.isNeedStop || photoProcessInfo.isNeedStop
        || interruptInfo.isNeedInterrupt;
    SchedulerInfo result = {isNeedStop, interruptInfo.isNeedInterrupt, chargingInfo.isCharging};
    DP_CHECK_RETURN_RET_LOG(isNeedStop, result,
        "DPS_EVENT: Video stop schedule, hdi: %{public}d, mediaLibrary: %{public}d, camera: %{public}d, "
        "screen: %{public}d, temperature: %{public}d, photoRunning: %{public}d",
        halInfo.isNeedStop, mediaLibraryInfo.isNeedStop, cameraInfo.isNeedStop,
        screenInfo.isNeedStop, temperatureInfo.isNeedStop, photoProcessInfo.isNeedStop);

    if (chargingInfo.isCharging) {
        DP_CHECK_RETURN_RET_LOG(repository_->HasRunningJob(), chargingInfo, "Has video job running.");
        return GetSchedulerInfo(BATTERY_LEVEL_STATE);
    }

    return GetSchedulerInfo(BATTERY_STATE);
}

SchedulerInfo VideoStrategyCenter::GetSchedulerInfo(SchedulerType type)
{
    SchedulerInfo defaultInfo;
    auto scheduleState = GetSchedulerState(type);
    DP_CHECK_ERROR_RETURN_RET_LOG(scheduleState == nullptr, defaultInfo, "Not find SchedulerType: %{public}d", type);
    return scheduleState->GetSchedulerInfo();
}

std::shared_ptr<IState> VideoStrategyCenter::GetSchedulerState(SchedulerType type)
{
    return StateFactory::Instance().GetState(type);
}

} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS