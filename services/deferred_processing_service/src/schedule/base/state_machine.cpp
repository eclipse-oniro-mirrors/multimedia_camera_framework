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

#include "state_machine.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
void StateMachine::ChangeStateTo(const std::shared_ptr<State> &targetState)
{
    DP_CHECK_RETURN_LOG(targetState == nullptr, "targetState is null");
    DP_CHECK_RETURN_LOG(currState_ == targetState, "already is type: %{public}d", currState_->GetState());

    std::shared_ptr<State> lastState = currState_;
    currState_ = targetState;
    if (lastState == nullptr) {
        DP_DEBUG_LOG("change to %{public}d", currState_->GetState());
    } else {
        DP_DEBUG_LOG("from %{public}d to %{public}d", lastState->GetState(), currState_->GetState());
        lastState->OnStateExited();
    }
    currState_->OnStateEntered();
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS