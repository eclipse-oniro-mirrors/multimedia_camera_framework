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

#include "photo_trailing_state.h"

#include "basic_definitions.h"
#include "camera_timer.h"
#include "dp_log.h"
#include "events_monitor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr uint32_t DURATIONMS_25_SEC = 25 * 1000;
}

PhotoTrailingState::PhotoTrailingState(SchedulerType type, int32_t stateValue)
    : IState(type, stateValue)
{
    DP_DEBUG_LOG("entered.");
}

SchedulerInfo PhotoTrailingState::ReevaluateSchedulerInfo()
{
    DP_DEBUG_LOG("PhotoTrailingState: %{public}d", stateValue_);
    if (stateValue_ == TrailingStatus::SYSTEM_CAMERA_OFF_START_TRAILING) {
        StartTrailing(DURATIONMS_25_SEC);
    } else if (stateValue_ == TrailingStatus::NORMAL_CAMERA_OFF_START_TRAILING) {
        StartTrailing(DEFAULT_TRAILING_TIME);
    } else if (stateValue_ == TrailingStatus::CAMERA_ON_STOP_TRAILING) {
        StopTrailing();
    }
    return {!isTrailing_};
}

void PhotoTrailingState::StartTrailing(uint32_t duration)
{
    DP_CHECK_EXECUTE(isTrailing_, StopTrailing());
    remainingTrailingTime_ = std::max(duration, remainingTrailingTime_);
    DP_CHECK_RETURN(remainingTrailingTime_ == 0);

    startTime_ = GetSteadyNow();
    isTrailing_ = true;
    DP_INFO_LOG("DPS_PHOTO: StartTrailing time: %{public}u, state: %{public}d", remainingTrailingTime_, isTrailing_);
    auto thisPtr = weak_from_this();
    timerId_ = CameraTimer::GetInstance().Register([thisPtr]() {
        auto trailingState = thisPtr.lock();
        DP_CHECK_EXECUTE(trailingState != nullptr, trailingState->OnTimerOut());
    }, remainingTrailingTime_, true);
}

void PhotoTrailingState::StopTrailing()
{
    DP_CHECK_RETURN(!isTrailing_);
    DP_INFO_LOG("DPS_PHOTO: StopTrailing state: %{public}d", isTrailing_);
    CameraTimer::GetInstance().Unregister(timerId_);
    timerId_ = INVALID_TIMERID;
    isTrailing_ = false;
    auto useTime = static_cast<uint32_t>(GetDiffTime<Milli>(startTime_));
    remainingTrailingTime_ = remainingTrailingTime_ > useTime ?
        remainingTrailingTime_ - useTime : DEFAULT_TRAILING_TIME;
}

void PhotoTrailingState::OnTimerOut()
{
    DP_INFO_LOG("DPS_PHOTO: TrailingTimeOut");
    EventsMonitor::GetInstance().NotifyTrailingStatus(TrailingStatus::CAMERA_ON_STOP_TRAILING);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS