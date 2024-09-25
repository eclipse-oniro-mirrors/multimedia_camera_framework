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

#include "basic_definitions.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

SystemPressureLevel MapEventThermalLevel(int32_t level)
{
    if (level < LEVEL_0 || level > LEVEL_5) {
        return SystemPressureLevel::SEVERE;
    }
    SystemPressureLevel eventLevel = eventLevel = SystemPressureLevel::SEVERE;
    switch (level) {
        case LEVEL_0:
        case LEVEL_1:
            eventLevel = SystemPressureLevel::NOMINAL;
            break;
        case LEVEL_2:
        case LEVEL_3:
        case LEVEL_4:
            eventLevel = SystemPressureLevel::FAIR;
            break;
        default:
            eventLevel = SystemPressureLevel::SEVERE;
            break;
    }
    return eventLevel;
}

} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
