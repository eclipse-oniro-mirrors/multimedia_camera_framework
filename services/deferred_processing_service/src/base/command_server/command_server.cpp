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

#include "command_server.h"

#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
CommandServer::CommandServer() : server_(nullptr)
{
    DP_DEBUG_LOG("entered.");
}

CommandServer::~CommandServer()
{
    DP_DEBUG_LOG("entered.");
    server_ = nullptr;
}

int32_t CommandServer::Initialize(const std::string& cmdServerName)
{
    if (server_ == nullptr) {
        server_ = std::make_shared<CommandServerImpl>(cmdServerName);
    }
    return DP_OK;
}

int32_t CommandServer::SendCommand(const CmdSharedPtr& cmd)
{
    DP_CHECK_RETURN_RET(server_ != nullptr, server_->AddCommand(cmd));
    return DP_INIT_FAIL;
}

int32_t CommandServer::SendUrgentCommand(const CmdSharedPtr& cmd)
{
    DP_CHECK_RETURN_RET(server_ != nullptr, server_->AddUrgentCommand(cmd));
    return DP_INIT_FAIL;
}

void CommandServer::SetThreadPriority(int priority)
{
    DP_CHECK_EXECUTE(server_ != nullptr, server_->SetThreadPriority(priority));
}

int32_t CommandServer::GetThreadPriority() const
{
    DP_CHECK_RETURN_RET(server_ != nullptr, server_->GetThreadPriority());
    return DP_INIT_FAIL;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS