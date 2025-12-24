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

#ifndef OHOS_CAMERA_DPS_NOTIFY_JOB_CHANGED_COMMAND_H
#define OHOS_CAMERA_DPS_NOTIFY_JOB_CHANGED_COMMAND_H

#include "command.h"
#include "deferred_photo_controller.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class NotifyJobChangedCommand : public Command {
    DECLARE_CMD_CLASS(NotifyJobChangedCommand);
public:
    NotifyJobChangedCommand(const int32_t userId);
    ~NotifyJobChangedCommand() = default;

protected:
    int32_t Initialize();
    int32_t Executing() override;

    const int32_t userId_;
    std::atomic<bool> initialized_ {false};
    std::shared_ptr<DeferredPhotoController> controller_ {nullptr};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_NOTIFY_JOB_CHANGED_COMMAND_H