/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *PhotoSchedulerInfo
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_CAMERA_DPS_STATE_MACHINE_H
#define OHOS_CAMERA_DPS_STATE_MACHINE_H

#include <memory>

#include "basic_definitions.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class State {
public:
    explicit State(const JobState state) : state_(state) {}
    virtual ~State() = default;

    inline JobState GetState() const
    {
        return state_;
    }

protected:
    virtual void OnStateEntered() {};
    virtual void OnStateExited() {};

    friend class StateMachine;
    JobState state_;
};

class StateMachine {
public:
    StateMachine() = default;
    virtual ~StateMachine() = default;

protected:
    void ChangeStateTo(const std::shared_ptr<State>& targetState);

    std::shared_ptr<State> currState_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_STATE_MACHINE_H