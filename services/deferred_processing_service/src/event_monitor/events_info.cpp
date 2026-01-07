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

#include "events_info.h"

#include "basic_definitions.h"
#include "dp_log.h"
#include "parameters.h"
#ifdef CAMERA_USE_BATTERY
#include "battery_srv_client.h"
#include "battery_info.h"
#endif
#ifdef CAMERA_USE_THERMAL
#include "thermal_mgr_client.h"
#endif
#ifdef CAMERA_USE_POWER
#include "power_mgr_client.h"
#endif
#ifdef MEMMGR_OVERRID
#include "mem_mgr_client.h"
#endif

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr int32_t BATTERY_THRESHOLD = 50;
    constexpr int32_t DEFAULT_MEMORY_SIZE = 0;
}

EventsInfo::EventsInfo()
{
    DP_DEBUG_LOG("entered.");
}

EventsInfo::~EventsInfo()
{
    DP_DEBUG_LOG("entered.");
}

ScreenStatus EventsInfo::GetScreenState()
{
#ifdef CAMERA_USE_POWER
    auto& power = PowerMgr::PowerMgrClient::GetInstance();
    if (power.IsScreenOn()) {
        screenState_ = ScreenStatus::SCREEN_ON;
    } else {
        screenState_ = ScreenStatus::SCREEN_OFF;
    }
#endif
    return screenState_;
}

BatteryStatus EventsInfo::GetBatteryState()
{
    DP_CHECK_ERROR_RETURN_RET_LOG(system::GetBoolParameter(IGNORE_BATTERY, false), BATTERY_OKAY,
        "ignore GetBatteryState");
#ifdef CAMERA_USE_BATTERY
    auto& battery = PowerMgr::BatterySrvClient::GetInstance();
    auto level = battery.GetCapacityLevel();
    DP_INFO_LOG("GetBatteryState: %{public}d", level);
    switch (level) {
        case PowerMgr::BatteryCapacityLevel::LEVEL_NORMAL:
        case PowerMgr::BatteryCapacityLevel::LEVEL_HIGH:
        case PowerMgr::BatteryCapacityLevel::LEVEL_FULL:
            batteryState_ = BatteryStatus::BATTERY_OKAY;
            break;
        default:
            batteryState_ = BatteryStatus::BATTERY_LOW;
            break;
    }
#endif
    return batteryState_;
}

ChargingStatus EventsInfo::GetChargingState()
{
#ifdef CAMERA_USE_BATTERY
    auto& battery = PowerMgr::BatterySrvClient::GetInstance();
    auto status = battery.GetChargingStatus();
    DP_INFO_LOG("GetChargingState: %{public}d", status);
    switch (status) {
        case PowerMgr::BatteryChargeState::CHARGE_STATE_ENABLE:
        case PowerMgr::BatteryChargeState::CHARGE_STATE_FULL:
            chargingState_ = ChargingStatus::CHARGING;
            break;
        default:
            chargingState_ = ChargingStatus::DISCHARGING;
            break;
    }
#endif
    return chargingState_;
}

BatteryLevel EventsInfo::GetBatteryLevel()
{
    DP_CHECK_ERROR_RETURN_RET_LOG(system::GetBoolParameter(IGNORE_BATTERY_LEVEL, false), BATTERY_LEVEL_OKAY,
        "ignore GetBatteryLevel");
#ifdef CAMERA_USE_BATTERY
    auto& battery = PowerMgr::BatterySrvClient::GetInstance();
    auto capacity = battery.GetCapacity();
    DP_INFO_LOG("GetBatteryLevel: %{public}d", capacity);
    if (capacity <= BATTERY_THRESHOLD) {
        batteryLevel_ = BatteryLevel::BATTERY_LEVEL_LOW;
    } else {
        batteryLevel_ = BatteryLevel::BATTERY_LEVEL_OKAY;
    }
#endif
    return batteryLevel_;
}

ThermalLevel EventsInfo::GetThermalLevel()
{
    DP_CHECK_ERROR_RETURN_RET_LOG(system::GetBoolParameter(IGNORE_TEMPERATURE, false), LEVEL_0,
        "ignore GetThermalLevel");
#ifdef CAMERA_USE_THERMAL
    auto& thermal = OHOS::PowerMgr::ThermalMgrClient::GetInstance();
    thermalLevel_ = static_cast<ThermalLevel>(thermal.GetThermalLevel());
    DP_INFO_LOG("GetThermalLevel: %{public}d", thermalLevel_);
#endif
    return thermalLevel_;
}

CameraSessionStatus EventsInfo::GetCameraState()
{
    std::lock_guard lock(mutex_);
    return cameraState_;
}

void EventsInfo::SetCameraState(CameraSessionStatus state)
{
    std::lock_guard lock(mutex_);
    cameraState_ = state;
}

bool EventsInfo::IsCameraOpen()
{
    std::lock_guard lock(mutex_);
    DP_INFO_LOG("IsCameraOpen: %{public}d", cameraState_);
    return cameraState_ == CameraSessionStatus::NORMAL_CAMERA_OPEN
        || cameraState_ == CameraSessionStatus::SYSTEM_CAMERA_OPEN;
}

int32_t EventsInfo::GetAvailableMemory()
{
#ifdef MEMMGR_OVERRID
    int32_t size = Memory::MemMgrClient::GetInstance().GetAvailableMemory();
    return size;
#endif
    return DEFAULT_MEMORY_SIZE;
}

void EventsInfo::SetMediaLibraryState(MediaLibraryStatus state)
{
    std::lock_guard lock(mediaStateMutex_);
    mediaState_ = state;
}

bool EventsInfo::IsMediaBusy()
{
    std::lock_guard lock(mediaStateMutex_);
    return mediaState_ == MediaLibraryStatus::MEDIA_LIBRARY_BUSY;
}

void EventsInfo::SetCurrentUser(const int32_t userId)
{
    std::lock_guard lock(userMutex_);
    userId_ = userId;
}

int32_t EventsInfo::GetCurrentUser()
{
    std::lock_guard lock(userMutex_);
    return userId_;
}

bool EventsInfo::IsAllowedToSchedule(const int32_t userId)
{
    std::lock_guard lock(userMutex_);
    return userId == userId_;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS