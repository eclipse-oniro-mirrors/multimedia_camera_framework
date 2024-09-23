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

#ifndef OHOS_CAMERA_DPS_EVENT_STATUS_CHANGE_COMMAND_H
#define OHOS_CAMERA_DPS_EVENT_STATUS_CHANGE_COMMAND_H

#include "basic_definitions.h"
#include "command.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class EventStatusChangeCommand : public Command {
    DECLARE_CMD_CLASS(EventStatusChangeCommand);

public:
    EventStatusChangeCommand(const int32_t userId, const EventType event, const int value);
    ~EventStatusChangeCommand() override;

protected:
    int32_t Executing() override;

private:
    const int32_t userId_;
    const EventType eventId_;
    const int32_t value_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_EVENT_STATUS_CHANGE_COMMAND_H