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

#include "events_info.h"

#include "basic_definitions.h"
#include "dp_log.h"
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

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr int32_t BATTERY_THRESHOLD = 50;
}

EventsInfo::EventsInfo()
{
    DP_DEBUG_LOG("entered.");
}

EventsInfo::~EventsInfo()
{
    DP_DEBUG_LOG("entered.");
}

void EventsInfo::Initialize()
{
    DP_DEBUG_LOG("Initialize enter.");
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
#ifdef CAMERA_USE_THERMAL
    auto& thermal = OHOS::PowerMgr::ThermalMgrClient::GetInstance();
    thermalLevel_ = static_cast<ThermalLevel>(thermal.GetThermalLevel());
    DP_INFO_LOG("GetThermalLevel: %{public}d", thermalLevel_);
#endif
    return thermalLevel_;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS