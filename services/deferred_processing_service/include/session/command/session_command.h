/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
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

#ifndef OHOS_CAMERA_DPS_SESSION_COMMAND_H
#define OHOS_CAMERA_DPS_SESSION_COMMAND_H

#include "command.h"
#include "scheduler_manager.h"
#include "session_manager.h"
#include "video_session_info.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

class SessionCommand : public Command {
public:
    SessionCommand(const sptr<VideoSessionInfo>& sessionInfo);
    ~SessionCommand() override;

protected:
    int32_t Initialize();

    std::atomic<bool> initialized_ {false};
    std::shared_ptr<SessionManager> sessionManager_ {nullptr};
    sptr<VideoSessionInfo> sessionInfo_;
};

class AddVideoSessionCommand : public SessionCommand {
    DECLARE_CMD_CLASS(AddVideoSessionCommand)
public:
    using SessionCommand::SessionCommand;

protected:
    int32_t Executing() override;
};

class DeleteVideoSessionCommand : public SessionCommand {
    DECLARE_CMD_CLASS(DeleteVideoSessionCommand)
public:
    using SessionCommand::SessionCommand;

protected:
    int32_t Executing() override;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_SESSION_COMMAND_H