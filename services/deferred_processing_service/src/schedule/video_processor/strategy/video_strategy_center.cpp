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

#include "video_strategy_center.h"

#include "battery_level_strategy.h"
#include "dp_log.h"
#include "dps_event_report.h"
#include "events_info.h"
#include "events_monitor.h"
#include "ivideo_state_change_listener.h"
#include "video_battery_level_state.h"
#include "video_battery_state.h"
#include "video_camera_state.h"
#include "video_charging_state.h"
#include "video_hal_state.h"
#include "video_media_library_state.h"
#include "video_photo_process_state.h"
#include "video_screen_state.h"
#include "video_temperature_state.h"

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

VideoStrategyCenter::VideoStrategyCenter(const int32_t userId, const std::shared_ptr<VideoJobRepository>& repository)
    : userId_(userId), videoJobRepository_(repository)
{
    DP_INFO_LOG("entered");
}

VideoStrategyCenter::~VideoStrategyCenter()
{
    DP_INFO_LOG("entered");
    eventsListener_ = nullptr;
    eventHandlerList_.clear();
    scheduleStateList_.clear();
    videoJobRepository_ = nullptr;
}

void VideoStrategyCenter::Initialize()
{
    DP_INFO_LOG("entered");
    InitHandleEvent();
    InitScheduleState();
    eventsListener_ = std::make_shared<EventsListener>(weak_from_this());
    EventsMonitor::GetInstance().RegisterEventsListener(userId_, {
        EventType::CAMERA_SESSION_STATUS_EVENT,
        EventType::HDI_STATUS_EVENT,
        EventType::MEDIA_LIBRARY_STATUS_EVENT,
        EventType::THERMAL_LEVEL_STATUS_EVENT,
        EventType::SCREEN_STATUS_EVENT,
        EventType::BATTERY_STATUS_EVENT,
        EventType::BATTERY_LEVEL_STATUS_EVENT,
        EventType::CHARGING_STATUS_EVENT,
        EventType::PHOTO_PROCESS_STATUS_EVENT},
        eventsListener_);
}

void VideoStrategyCenter::InitHandleEvent()
{
    DP_INFO_LOG("entered");
    eventHandlerList_.insert({CAMERA_SESSION_STATUS_EVENT, [this](int32_t value){HandleCameraEvent(value);}});
    eventHandlerList_.insert({HDI_STATUS_EVENT, [this](int32_t value){HandleHalEvent(value);}});
    eventHandlerList_.insert({MEDIA_LIBRARY_STATUS_EVENT, [this](int32_t value){HandleMedialLibraryEvent(value);}});
    eventHandlerList_.insert({SCREEN_STATUS_EVENT, [this](int32_t value){HandleScreenEvent(value);}});
    eventHandlerList_.insert({CHARGING_STATUS_EVENT, [this](int32_t value){HandleChargingEvent(value);}});
    eventHandlerList_.insert({BATTERY_STATUS_EVENT, [this](int32_t value){HandleBatteryEvent(value);}});
    eventHandlerList_.insert({BATTERY_LEVEL_STATUS_EVENT, [this](int32_t value){HandleBatteryLevelEvent(value);}});
    eventHandlerList_.insert({THERMAL_LEVEL_STATUS_EVENT, [this](int32_t value){HandleTemperatureEvent(value);}});
    eventHandlerList_.insert({PHOTO_PROCESS_STATUS_EVENT, [this](int32_t value){HandlePhotoProcessEvent(value);}});
}

void VideoStrategyCenter::InitScheduleState()
{
    DP_INFO_LOG("entered");
    auto state = EventsInfo::GetInstance().GetChargingState();
    isCharging_ = state == ChargingStatus::CHARGING;
    scheduleStateList_.insert({CAMERA_STATE,
        std::make_shared<VideoCameraState>(CameraSessionStatus::SYSTEM_CAMERA_CLOSED)});
    scheduleStateList_.insert({HDI_STATE,
        std::make_shared<VideoHalState>(HdiStatus::HDI_READY)});
    scheduleStateList_.insert({MEDIA_LIBRARY_STATE,
        std::make_shared<VideoMediaLibraryState>(MediaLibraryStatus::MEDIA_LIBRARY_AVAILABLE)});
    scheduleStateList_.insert({SCREEN_STATE,
        std::make_shared<VideoScreenState>(EventsInfo::GetInstance().GetScreenState())});
    scheduleStateList_.insert({CHARGING_STATE,
        std::make_shared<VideoChargingState>(state)});
    scheduleStateList_.insert({BATTERY_STATE,
        std::make_shared<VideoBatteryState>(EventsInfo::GetInstance().GetBatteryState())});
    scheduleStateList_.insert({BATTERY_LEVEL_STATE,
        std::make_shared<VideoBatteryLevelState>(EventsInfo::GetInstance().GetBatteryLevel())});
    scheduleStateList_.insert({THERMAL_LEVEL_STATE,
        std::make_shared<VideoTemperatureState>(ConvertThermalLevel(EventsInfo::GetInstance().GetThermalLevel()))});
    scheduleStateList_.insert({PHOTO_PROCESS_STATE,
        std::make_shared<VideoPhotoProcessState>(PhotoProcessStatus::IDLE)});
    for (const auto& item : scheduleStateList_) {
        if (item.second == nullptr) {
            DP_ERR_LOG("schedule state init failed, type: %{public}d", item.first);
            continue;
        }
        item.second->Initialize();
    }
}

void VideoStrategyCenter::HandleEventChanged(EventType event, int32_t value)
{
    DP_INFO_LOG("entered, eventType: %{public}d, value: %{public}d", event, value);
    auto item = eventHandlerList_.find(event);
    if (item != eventHandlerList_.end()) {
        item->second(value);
    } else {
        DP_WARNING_LOG("not support handle event: %{public}d", event);
    }
}

void VideoStrategyCenter::RegisterStateChangeListener(const std::weak_ptr<IVideoStateChangeListener>& listener)
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
    return videoJobRepository_->GetJob();
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
    UpdateValue(ScheduleType::CAMERA_STATE, value);
}

void VideoStrategyCenter::HandleHalEvent(int32_t value)
{
    DP_DEBUG_LOG("HalEvent value: %{public}d", value);
    UpdateValue(ScheduleType::HDI_STATE, value);
}

void VideoStrategyCenter::HandleMedialLibraryEvent(int32_t value)
{
    DP_DEBUG_LOG("MedialLibraryEvent value: %{public}d", value);
    UpdateValue(ScheduleType::MEDIA_LIBRARY_STATE, value);
}

void VideoStrategyCenter::HandleScreenEvent(int32_t value)
{
    DP_DEBUG_LOG("ScreenEvent value: %{public}d", value);
    DP_CHECK_EXECUTE(value == ScreenStatus::SCREEN_ON, UpdateSingleTime(true));
    UpdateValue(ScheduleType::SCREEN_STATE, value);
}

void VideoStrategyCenter::HandleChargingEvent(int32_t value)
{
    DP_DEBUG_LOG("ChargingEvent value: %{public}d", value);
    isCharging_ = value == ChargingStatus::CHARGING;
    DP_CHECK_EXECUTE(isCharging_, UpdateAvailableTime(true, DEFAULT_TIME));
    UpdateValue(ScheduleType::CHARGING_STATE, value);
}
void VideoStrategyCenter::HandleBatteryEvent(int32_t value)
{
    DP_DEBUG_LOG("BatteryEvent value: %{public}d", value);
    UpdateValue(ScheduleType::BATTERY_STATE, value);
}

void VideoStrategyCenter::HandleBatteryLevelEvent(int32_t value)
{
    DP_DEBUG_LOG("BatteryLevelEvent value: %{public}d", value);
    UpdateValue(ScheduleType::BATTERY_LEVEL_STATE, value);
}

void VideoStrategyCenter::HandleTemperatureEvent(int32_t value)
{
    DP_DEBUG_LOG("TemperatureEvent value: %{public}d", value);
    auto level = ConvertThermalLevel(value);
    UpdateValue(ScheduleType::THERMAL_LEVEL_STATE, level);
}

void VideoStrategyCenter::HandlePhotoProcessEvent(int32_t value)
{
    DP_DEBUG_LOG("PhotoProcessEvent value: %{public}d", value);
    auto state = ConvertProcessState(value);
    UpdateValue(ScheduleType::PHOTO_PROCESS_STATE, state);
}

void VideoStrategyCenter::UpdateValue(ScheduleType type, int32_t value)
{
    auto scheduleState = GetScheduleState(type);
    DP_CHECK_ERROR_RETURN_LOG(scheduleState == nullptr, "UpdateValue failed.");
    if (scheduleState->UpdateSchedulerInfo(type, value)) {
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
    DP_INFO_LOG("process time type: 0x%{public}x", isTimeOk_);
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
    DP_INFO_LOG("available process time: %{public}d, type: 0x%{public}x", availableTime_, isTimeOk_);
}

ScheduleInfo VideoStrategyCenter::ReevaluateSchedulerInfo()
{
    ScheduleInfo cameraInfo = GetScheduleInfo(ScheduleType::CAMERA_STATE);
    ScheduleInfo halInfo = GetScheduleInfo(ScheduleType::HDI_STATE);
    ScheduleInfo mediaLibraryInfo = GetScheduleInfo(ScheduleType::MEDIA_LIBRARY_STATE);
    ScheduleInfo screenInfo = GetScheduleInfo(ScheduleType::SCREEN_STATE);
    ScheduleInfo temperatureInfo = GetScheduleInfo(ScheduleType::THERMAL_LEVEL_STATE);
    ScheduleInfo photoProcessInfo = GetScheduleInfo(ScheduleType::PHOTO_PROCESS_STATE);
    ScheduleInfo chargingInfo = GetScheduleInfo(ScheduleType::CHARGING_STATE);
    if (cameraInfo.isNeedStop || halInfo.isNeedStop || mediaLibraryInfo.isNeedStop ||
        screenInfo.isNeedStop || temperatureInfo.isNeedStop || photoProcessInfo.isNeedStop) {
        DP_INFO_LOG("video stop schedule, hdi : %{public}d, mediaLibrary: %{public}d, camear: %{public}d, "
            "screen: %{public}d, temperatureInfo: %{public}d, photoProcessInfo: %{public}d",
            halInfo.isNeedStop, mediaLibraryInfo.isNeedStop, cameraInfo.isNeedStop,
            screenInfo.isNeedStop, temperatureInfo.isNeedStop, photoProcessInfo.isNeedStop);
        return {true, chargingInfo.isCharging};
    }

    if (chargingInfo.isCharging) {
        DP_CHECK_RETURN_RET_LOG(videoJobRepository_->GetRunningJobCounts() > 0,
            chargingInfo, "has video job running.");
        
        DP_INFO_LOG("video try schedule in charging.");
        return GetScheduleInfo(ScheduleType::BATTERY_LEVEL_STATE);
    }

    DP_INFO_LOG("video try schedule in normal.");
    return GetScheduleInfo(ScheduleType::BATTERY_STATE);
}

ScheduleInfo VideoStrategyCenter::GetScheduleInfo(ScheduleType type)
{
    ScheduleInfo defaultInfo = {true, false};
    auto scheduleState = GetScheduleState(type);
    DP_CHECK_ERROR_RETURN_RET_LOG(scheduleState == nullptr, defaultInfo, "not find schedule type: %{public}d", type);
    return scheduleState->GetScheduleInfo(type);
}

std::shared_ptr<ISchedulerVideoState> VideoStrategyCenter::GetScheduleState(ScheduleType type)
{
    auto item = scheduleStateList_.find(type);
    DP_CHECK_ERROR_RETURN_RET_LOG(item == scheduleStateList_.end(), nullptr,
        "can not find ScheduleState by ScheduleType: %{public}d", type);

    auto scheduleState = item->second;
    DP_CHECK_ERROR_PRINT_LOG(scheduleState == nullptr, "ScheduleState get by EventType: %{public}d is nullptr", type);
    return scheduleState;
}

} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS