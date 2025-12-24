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

#ifndef OHOS_CAMERA_DPS_PHOTO_TRAILING_STATE_H
#define OHOS_CAMERA_DPS_PHOTO_TRAILING_STATE_H

#include "dp_utils.h"
#include "istate.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class PhotoTrailingState : public IState, public std::enable_shared_from_this<PhotoTrailingState> {
public:
    explicit PhotoTrailingState(SchedulerType type, int32_t stateValue);

protected:
    SchedulerInfo ReevaluateSchedulerInfo() override;

private:
    void StartTrailing(uint32_t duration);
    void StopTrailing();
    void OnTimerOut();

    bool isTrailing_ {false};
    uint32_t timerId_ {INVALID_TIMERID};
    SteadyTimePoint startTime_;
    uint32_t remainingTrailingTime_ {DEFAULT_TRAILING_TIME};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_PHOTO_TRAILING_STATE_H