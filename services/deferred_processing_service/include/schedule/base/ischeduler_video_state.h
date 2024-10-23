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

#ifndef OHOS_CAMERA_DPS_I_SCHEDULER_STATE_H
#define OHOS_CAMERA_DPS_I_SCHEDULER_STATE_H

#include "basic_definitions.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
const std::string IGNORE_BATTERY_LEVEL = "ohos.dps.ignore_battery_level";
const std::string IGNORE_BATTERY = "ohos.dps.ignore_battery";
const std::string IGNORE_SCREEN = "ohos.dps.ignore_screen";
const std::string IGNORE_TEMPERATURE = "ohos.dps.ignore_temperature";

class ISchedulerVideoState {
public:
    struct VideoSchedulerInfo {
        bool isNeedStop;
        bool isCharging;

        bool operator==(const VideoSchedulerInfo& info) const
        {
            return isNeedStop == info.isNeedStop && isCharging == info.isCharging;
        }
    };
    
    explicit ISchedulerVideoState(int32_t stateValue);
    virtual ~ISchedulerVideoState();

    int32_t Initialize();
    VideoSchedulerInfo GetScheduleInfo(ScheduleType type);
    bool UpdateSchedulerInfo(ScheduleType type, int32_t stateValue);

protected:
    virtual VideoSchedulerInfo ReevaluateSchedulerInfo() = 0;

    int32_t stateValue_;
    VideoSchedulerInfo scheduleInfo_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_I_SCHEDULER_STATE_H