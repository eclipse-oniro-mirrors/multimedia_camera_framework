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

#include "dp_log.h"
#include "dp_timer.h"
#include "dp_utils.h"
#include "events_monitor.h"
#include "state_factory.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
REGISTER_STATE(PhotoTrailingState, PHOTO_TRAILING_STATE, CAMERA_ON_STOP_TRAILING);

namespace {
    constexpr int32_t DURATIONMS_25_SEC = 25 * 1000;
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
    } else if (stateValue_ == TrailingStatus::CAMERA_ON_STOP_TRAILING) {
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

    startTimer_ = GetSteadyNow();
    isTrailing_ = true;
    DP_INFO_LOG("DPS_PHOTO: StartTrailing time: %{public}u, state: %{public}d",
        remainingTrailingTime_, isTrailing_);
    timerId_ = DpsTimer::GetInstance().StartTimer([&]() {OnTimerOut();}, remainingTrailingTime_);
}

void PhotoTrailingState::StopTrailing()
{
    DP_CHECK_RETURN(!isTrailing_);
    DP_INFO_LOG("DPS_PHOTO: StopTrailing state: %{public}d", isTrailing_);
    DpsTimer::GetInstance().StopTimer(timerId_);
    isTrailing_ = false;
    remainingTrailingTime_ -= static_cast<uint32_t>(GetDiffTime<Milli>(startTimer_));
    remainingTrailingTime_ = std::max(DEFAULT_TRAILING_TIME, remainingTrailingTime_);
}

void PhotoTrailingState::OnTimerOut()
{
    DP_INFO_LOG("DPS_PHOTO: TrailingTimeOut");
    EventsMonitor::GetInstance().NotifyTrailingStatus(TrailingStatus::CAMERA_ON_STOP_TRAILING);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS