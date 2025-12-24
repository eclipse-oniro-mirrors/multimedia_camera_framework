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

#include "interrupt_state.h"

#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
InterruptState::InterruptState(SchedulerType type, int32_t stateValue)
    : IState(type, stateValue)
{
    DP_DEBUG_LOG("entered.");
}

SchedulerInfo InterruptState::GetSchedulerInfo()
{
    SchedulerInfo info = currentInfo_;
    DP_CHECK_EXECUTE(stateValue_ == IS_INTERRUPT, {
        DP_DEBUG_LOG("Reset InterruptState");
        stateValue_ = NO_INTERRUPT;
        currentInfo_ = {false};
    });
    return info;
}

SchedulerInfo InterruptState::ReevaluateSchedulerInfo()
{
    DP_DEBUG_LOG("InterruptState");
    bool isNeedInterrupt = stateValue_ == IS_INTERRUPT;
    return {false, isNeedInterrupt};
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS