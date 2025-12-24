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

#ifndef OHOS_CAMERA_DPS_VIDEO_PROCESS_TIME_STATE_H
#define OHOS_CAMERA_DPS_VIDEO_PROCESS_TIME_STATE_H

#include "istate.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class VideoProcessTimeState : public IState {
public:
    explicit VideoProcessTimeState(SchedulerType type, int32_t stateValue);
    bool UpdateSchedulerInfo(int32_t newValue) override;
    void UpdateAvailableTime(bool isSingle, int32_t useTime = -1);
    int32_t GetAvailableTime();

protected:
    SchedulerInfo ReevaluateSchedulerInfo() override;

private:
    void UpdateSingleTime(int32_t useTime);
    void UpdateTotalTime(int32_t useTime);

    uint32_t isTimeOk_ {0};
    int32_t availableTime_ {TOTAL_PROCESS_TIME};
    int32_t singleTime_ {ONCE_PROCESS_TIME};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_VIDEO_PROCESS_TIME_STATE_H