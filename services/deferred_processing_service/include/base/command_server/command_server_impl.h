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

#ifndef OHOS_CAMERA_DPS_COMMAND_SERVER_IMPL_H
#define OHOS_CAMERA_DPS_COMMAND_SERVER_IMPL_H

#include "command.h"
#include "thread_pool.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
using CmdSharedPtr = std::shared_ptr<Command>;

class CommandServerImpl
    : public std::enable_shared_from_this<CommandServerImpl> {
public:
    explicit CommandServerImpl(const std::string& cmdServerName);
    ~CommandServerImpl();

    int32_t AddCommand(const CmdSharedPtr& cmd);
    int32_t AddUrgentCommand(const CmdSharedPtr& cmd);

    void SetThreadPriority(int priority);
    int32_t GetThreadPriority() const;

private:
    std::string commandServerName_;
    std::mutex mutexMsg_;
    std::unique_ptr<ThreadPool> threadPool_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_COMMAND_SERVER_IMPL_H
