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

#ifndef OHOS_CAMERA_DPS_DPS_H
#define OHOS_CAMERA_DPS_DPS_H

#include "command_server.h"
#include "session_manager.h"
#include "scheduler_manager.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
int32_t DPS_Initialize();
void DPS_Destroy();

std::shared_ptr<CommandServer> DPS_GetCommandServer();
std::shared_ptr<SessionManager> DPS_GetSessionManager();
std::shared_ptr<SchedulerManager> DPS_GetSchedulerManager();

template <typename Command, typename Func, typename... Args>
int32_t SendCommandHelp(Func&& func, Args&& ...args)
{
    auto cmd = std::make_shared<Command>(std::forward<Args>(args)...);
    if (cmd) {
        auto server = DPS_GetCommandServer();
        if (server) {
            return (server.get()->*func)(cmd);
        }
        return DP_NULL_POINTER;
    }
    return DP_SEND_COMMAND_FAILED;
}

/**
 * @brief Create the cmd and send.
 *
 * @param [IN] args: Parameter list for cmd.
 *
 * @return The DSP_OK status indicates successful execution of the command,
 *         while other statuses indicate failure.
 */
template <typename Command, typename... Args>
int32_t DPS_SendCommand(Args&& ...args)
{
    return SendCommandHelp<Command>(&CommandServer::SendCommand, std::forward<Args>(args)...);
}

/**
 * @brief Create the cmd and send it urgently.
 *
 * @param [IN] args: Parameter list for cmd.
 *
 * @return The DSP_OK status indicates successful execution of the command,
 *         while other statuses indicate failure.
 */
template <typename Command, typename... Args>
int32_t DPS_SendUrgentCommand(Args&& ...args)
{
    return SendCommandHelp<Command>(&CommandServer::SendUrgentCommand, std::forward<Args>(args)...);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DPS_H