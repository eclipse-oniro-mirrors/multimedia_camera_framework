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

#include "video_process_time_state.h"

#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr uint32_t TIME_LIMIT = 0b11;
    constexpr uint32_t SINGLE_TIME_LIMIT = 0b1;
    constexpr uint32_t TOTAL_TIME_LIMIT = 0b10;
}

VideoProcessTimeState::VideoProcessTimeState(SchedulerType type, int32_t stateValue)
    : IState(type, stateValue)
{
    DP_DEBUG_LOG("entered.");
}

bool VideoProcessTimeState::UpdateSchedulerInfo(int32_t newValue)
{
    return false;
}

void VideoProcessTimeState::UpdateAvailableTime(bool isSingle, int32_t useTime)
{
    if (isSingle) {
        UpdateSingleTime(useTime);
    } else {
        UpdateTotalTime(useTime);
    }
    stateValue_ = (isTimeOk_ & TIME_LIMIT) ? UNAVAILABLE_TIME : AVAILABLE_TIME;
    DP_INFO_LOG("DPS_VIDEO: Single processTime: %{public}d, Available processTime: %{public}d, type: %{public}d",
        singleTime_, availableTime_, isTimeOk_);
}

void VideoProcessTimeState::UpdateSingleTime(int32_t useTime)
{
    isTimeOk_ = (useTime == -1) ? isTimeOk_ & ~SINGLE_TIME_LIMIT : isTimeOk_ | SINGLE_TIME_LIMIT;
    DP_CHECK_EXECUTE(useTime == -1, singleTime_ = ONCE_PROCESS_TIME);
}

void VideoProcessTimeState::UpdateTotalTime(int32_t useTime)
{
    if (useTime > 0) {
        availableTime_ -= useTime;
        singleTime_ -= useTime;
    }
    DP_CHECK_EXECUTE(useTime == -1, availableTime_ = TOTAL_PROCESS_TIME);
    availableTime_ = std::max(availableTime_, 0);
    singleTime_ = std::max(singleTime_, 0);
    isTimeOk_ = (availableTime_ > 0) ? (isTimeOk_ & ~TOTAL_TIME_LIMIT) : (isTimeOk_ | TOTAL_TIME_LIMIT);
}

int32_t VideoProcessTimeState::GetAvailableTime()
{
    return std::min(singleTime_, availableTime_);
}

SchedulerInfo VideoProcessTimeState::ReevaluateSchedulerInfo()
{
    DP_DEBUG_LOG("InterruptState");
    bool isNeedStop = stateValue_ == UNAVAILABLE_TIME;
    return {isNeedStop};
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS