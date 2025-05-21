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

#include "photo_temperature_state.h"

#include "dp_log.h"
#include "events_info.h"
#include "state_factory.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
REGISTER_STATE(PhotoTemperatureState, PHOTO_THERMAL_LEVEL_STATE,
    ConvertPhotoThermalLevel(EventsInfo::GetInstance().GetThermalLevel()));

PhotoTemperatureState::PhotoTemperatureState(SchedulerType type, int32_t stateValue)
    : IState(type, stateValue)
{
    DP_DEBUG_LOG("entered.");
}

SchedulerInfo PhotoTemperatureState::ReevaluateSchedulerInfo()
{
    DP_DEBUG_LOG("PhotoTemperatureState: %{public}d", stateValue_);
    bool isNeedStop = stateValue_ != SystemPressureLevel::NOMINAL;
    return {isNeedStop};
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS