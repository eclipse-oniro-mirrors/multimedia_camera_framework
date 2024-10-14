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

#ifndef OHOS_CAMERA_DPS_COMMAND_H
#define OHOS_CAMERA_DPS_COMMAND_H

#include <cstdint>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

#define DECLARE_CMD_CLASS(name) \
    public:                     \
        const char* GetCommandName() const override { return #name; }

class Command {
public:
    Command();
    virtual ~Command();

    /**
     * @brief Get Command Name
     *
     * @return Command Name
     */
    virtual const char* GetCommandName() const = 0;

    /**
     * @brief Provided for the invocation of Command by the CommandServer,
     *        driving its operation.
     *
     * @return The DSP_OK status indicates successful execution of the command,
     *         while other statuses indicate failure.
     */
    int32_t Do();

protected:
    /**
     * @brief The action executed by Command needs to be overridden by a derived class.
     *
     * @return The DSP_OK status indicates successful execution of the command,
     *         while other statuses indicate failure.
     */
    virtual int32_t Executing() = 0;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_COMMAND_H
