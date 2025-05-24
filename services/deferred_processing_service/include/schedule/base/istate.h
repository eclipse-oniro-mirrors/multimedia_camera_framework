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

#ifndef OHOS_CAMERA_DPS_I_STATE_H
#define OHOS_CAMERA_DPS_I_STATE_H

#include "basic_definitions.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
const std::string IGNORE_BATTERY_LEVEL = "ohos.dps.ignore_battery_level";
const std::string IGNORE_BATTERY = "ohos.dps.ignore_battery";
const std::string IGNORE_SCREEN = "ohos.dps.ignore_screen";
const std::string IGNORE_TEMPERATURE = "ohos.dps.ignore_temperature";

struct SchedulerInfo {
    bool isNeedStop {true};
    bool isNeedInterrupt {false};
    bool isCharging {false};

    bool operator==(const SchedulerInfo& info) const
    {
        return isNeedStop == info.isNeedStop &&
            isNeedInterrupt == info.isNeedInterrupt &&
            isCharging == info.isCharging;
    }
};

class IState {
public:
    explicit IState(SchedulerType type, int32_t initValue) : type_(type), stateValue_(initValue)
    {
        DP_DEBUG_LOG("entered.");
    }
    virtual ~IState() = default;

    int32_t Initialize()
    {
        currentInfo_ = ReevaluateSchedulerInfo();
        return DoInitialize();
    }

    virtual SchedulerInfo GetSchedulerInfo()
    {
        return currentInfo_;
    }

    bool UpdateSchedulerInfo(int32_t newValue)
    {
        DP_CHECK_RETURN_RET_LOG(stateValue_ == newValue, false,
            "DPS_EVENT: SchedulerInfo[%{public}d] is not change, state: %{public}d", type_, stateValue_);

        stateValue_ = newValue;
        currentInfo_ = ReevaluateSchedulerInfo();
        DP_INFO_LOG("DPS_EVENT: SchedulerInfo[%{public}d] state set: %{public}d", type_, stateValue_);
        return true;
    }

    inline SchedulerType GetSchedulerType() const
    {
        return type_;
    }

    inline int32_t GetState() const
    {
        return stateValue_;
    }

protected:
    virtual SchedulerInfo ReevaluateSchedulerInfo() = 0;
    virtual int32_t DoInitialize()
    {
        return DP_OK;
    }

    const SchedulerType type_;
    int32_t stateValue_;
    SchedulerInfo currentInfo_ {true, false, false};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_I_STATE_H