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

#include "video_screen_state.h"

#include "dp_log.h"
#include "events_info.h"
#include "parameters.h"
#include "state_factory.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
REGISTER_STATE(VideoScreenState, SCREEN_STATE, EventsInfo::GetInstance().GetScreenState());

VideoScreenState::VideoScreenState(SchedulerType type, int32_t stateValue)
    : IState(type, stateValue)
{
    DP_DEBUG_LOG("entered.");
}

SchedulerInfo VideoScreenState::ReevaluateSchedulerInfo()
{
    bool ignore = system::GetBoolParameter(IGNORE_SCREEN, false);
    DP_CHECK_ERROR_RETURN_RET_LOG(ignore, {false}, "ignore VideoScreenState: %{public}d", stateValue_);

    DP_DEBUG_LOG("VideoScreenState: %{public}d", stateValue_);
    bool isNeedStop = stateValue_ == ScreenStatus::SCREEN_ON;
    return {isNeedStop};
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS