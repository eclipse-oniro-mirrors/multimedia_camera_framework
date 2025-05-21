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
#include "state_factory.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr uint32_t SINGLE_TIME_LIMIT = 0b1;
    constexpr uint32_t TOTAL_TIME_LIMIT = 0b10;
    constexpr int32_t DEFAULT_TIME = 0;
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
    DP_DEBUG_LOG("entered.");
    eventHandlerList_.clear();
}

void VideoStrategyCenter::Initialize()
{
    DP_DEBUG_LOG("entered.");
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
        PHOTO_PROCESS_STATUS_EVENT},
        eventsListener_);
}

void VideoStrategyCenter::InitHandleEvent()
{
    DP_DEBUG_LOG("entered.");
    eventHandlerList_ = {
        {CAMERA_SESSION_STATUS_EVENT, [this](int32_t value){ HandleCameraEvent(value); }},
        {VIDEO_HDI_STATUS_EVENT, [this](int32_t value){ HandleHalEvent(value); }},
        {MEDIA_LIBRARY_STATUS_EVENT, [this](int32_t value){ HandleMedialLibraryEvent(value); }},
        {SCREEN_STATUS_EVENT, [this](int32_t value){ HandleScreenEvent(value); }},
        {CHARGING_STATUS_EVENT, [this](int32_t value){ HandleChargingEvent(value); }},
        {BATTERY_STATUS_EVENT, [this](int32_t value){ HandleBatteryEvent(value); }},
        {BATTERY_LEVEL_STATUS_EVENT, [this](int32_t value){ HandleBatteryLevelEvent(value); }},
        {THERMAL_LEVEL_STATUS_EVENT, [this](int32_t value){ HandleTemperatureEvent(value); }},
        {PHOTO_PROCESS_STATUS_EVENT, [this](int32_t value){ HandlePhotoProcessEvent(value); }}
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

DeferredVideoWorkPtr VideoStrategyCenter::GetWork()
{
    auto jobPtr = GetJob();
    ExecutionMode mode = GetExecutionMode();
    if ((jobPtr != nullptr) && (mode != ExecutionMode::DUMMY)) {
        return std::make_shared<DeferredVideoWork>(jobPtr, mode, isCharging_);
    }
    return nullptr;
}

DeferredVideoJobPtr VideoStrategyCenter::GetJob()
{
    return repository_->GetJob();
}

ExecutionMode VideoStrategyCenter::GetExecutionMode()
{
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
    DP_CHECK_EXECUTE(isCharging_, UpdateAvailableTime(true, DEFAULT_TIME));
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
    if (isOk) {
        isTimeOk_ &= ~SINGLE_TIME_LIMIT;
    } else {
        isTimeOk_ |= SINGLE_TIME_LIMIT;
    }
    DP_INFO_LOG("DPS_VIDEO: Process time type: 0x%{public}x", isTimeOk_);
}

void VideoStrategyCenter::UpdateAvailableTime(bool isNeedReset, int32_t useTime)
{
    if (isNeedReset) {
        availableTime_ = TOTAL_PROCESS_TIME;
    } else {
        availableTime_ -= useTime;
    }

    if (availableTime_ > 0) {
        isTimeOk_ &= ~TOTAL_TIME_LIMIT;
    } else {
        availableTime_ = 0;
        isTimeOk_ |= TOTAL_TIME_LIMIT;
    }
    DP_INFO_LOG("DPS_VIDEO: Available process time: %{public}d, type: 0x%{public}x", availableTime_, isTimeOk_);
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
    if (cameraInfo.isNeedStop || halInfo.isNeedStop || mediaLibraryInfo.isNeedStop ||
        screenInfo.isNeedStop || temperatureInfo.isNeedStop || photoProcessInfo.isNeedStop) {
        DP_INFO_LOG("DPS_EVENT: Video stop schedule, hdi: %{public}d, mediaLibrary: %{public}d, camera: %{public}d, "
            "screen: %{public}d, temperature: %{public}d, photoRunning: %{public}d",
            halInfo.isNeedStop, mediaLibraryInfo.isNeedStop, cameraInfo.isNeedStop,
            screenInfo.isNeedStop, temperatureInfo.isNeedStop, photoProcessInfo.isNeedStop);
        return {.isCharging = chargingInfo.isCharging};
    }

    if (chargingInfo.isCharging) {
        DP_CHECK_RETURN_RET_LOG(repository_->GetRunningJobCounts() > 0,
            chargingInfo, "Has video job running.");
        
        DP_INFO_LOG("DPS_EVENT: Video try do schedule in charging.");
        return GetSchedulerInfo(BATTERY_LEVEL_STATE);
    }

    DP_INFO_LOG("DPS_EVENT: Video try do schedule in normal.");
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