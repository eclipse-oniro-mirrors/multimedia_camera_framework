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

#include "ischeduler_video_state.h"

#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
ISchedulerVideoState::ISchedulerVideoState(int32_t stateValue)
    : stateValue_(stateValue),
      scheduleInfo_({true, false})
{
    DP_DEBUG_LOG("entered.");
}

ISchedulerVideoState::~ISchedulerVideoState()
{
    DP_DEBUG_LOG("entered.");
}

int32_t ISchedulerVideoState::Initialize()
{
    DP_DEBUG_LOG("entered.");
    scheduleInfo_ = ReevaluateSchedulerInfo();
    return DP_OK;
}

ISchedulerVideoState::VideoSchedulerInfo ISchedulerVideoState::GetScheduleInfo(ScheduleType type)
{
    DP_DEBUG_LOG("entered, type:%{public}d.", type);
    return scheduleInfo_;
}

bool ISchedulerVideoState::UpdateSchedulerInfo(ScheduleType type, int32_t stateValue)
{
    int32_t preStateValue = stateValue_;
    stateValue_ = stateValue;
    auto info = ReevaluateSchedulerInfo();
    DP_CHECK_ERROR_RETURN_RET_LOG(scheduleInfo_ == info, false,
        "VideoSchedulerInfo(%{public}d) state : %{public}d is not change.", type, stateValue);

    DP_INFO_LOG("VideoSchedulerInfo(%{public}d) state from %{public}d to %{public}d", type, preStateValue, stateValue);
    scheduleInfo_ = info;
    return true;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS