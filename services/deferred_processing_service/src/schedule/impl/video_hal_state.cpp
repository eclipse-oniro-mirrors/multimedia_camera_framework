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

#include "video_hal_state.h"

#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
VideoHalState::VideoHalState(int32_t stateValue) : ISchedulerVideoState(stateValue)
{
    DP_DEBUG_LOG("entered.");
}

VideoHalState::~VideoHalState()
{
    DP_DEBUG_LOG("entered.");
}

VideoHalState::VideoSchedulerInfo VideoHalState::ReevaluateSchedulerInfo()
{
    DP_DEBUG_LOG("VideoHalState: %{public}d", stateValue_);
    bool isNeedStop = !(
        stateValue_ == HdiStatus::HDI_READY ||
        stateValue_ == HdiStatus::HDI_READY_SPACE_LIMIT_REACHED);
    return {isNeedStop, false};
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS