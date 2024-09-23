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

#ifndef OHOS_CAMERA_DPS_COMMAND_SERVER_H
#define OHOS_CAMERA_DPS_COMMAND_SERVER_H

#include "command.h"
#include "command_server_impl.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
using CmdSharedPtr = std::shared_ptr<Command>;
class CommandServer {
public:
    CommandServer();
    ~CommandServer();
    
    /**
     * @brief Initialize
     *
     * Must be called before use
     *
     * @param [IN] cmdServerName
     *
     * @return The DSP_OK status indicates successful execution of the command,
     *         while other statuses indicate failure.
     */
    int32_t Initialize(const std::string& cmdServerName = "DpsCmdServer");

    /**
     * @brief Send a command and execute it sequentially after it is added.
     *
     * @param [IN] cmd
     *
     * @return The DSP_OK status indicates successful execution of the command,
     *         while other statuses indicate failure.
     */
    int32_t SendCommand(const CmdSharedPtr& cmd);

    /**
     * @brief Send an emergency command, and immediately invoke the command
     *        after the execution of the command that is being executed.
     *
     * @param [IN] cmd
     *
     * @return The DSP_OK status indicates successful execution of the command,
     *         while other statuses indicate failure.
     */
    int32_t SendUrgentCommand(const CmdSharedPtr& cmd);

    /**
     * @brief Set CommandServer priority
     *
     * @param [IN] priority
     *
     * @return void
     *
     */
    void SetThreadPriority(int priority);

    /**
     * @brief Get CommandServer priority
     *
     * @return priority
     *
     */
    int32_t GetThreadPriority() const;

private:
    std::shared_ptr<CommandServerImpl> server_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_COMMAND_SERVER_H
