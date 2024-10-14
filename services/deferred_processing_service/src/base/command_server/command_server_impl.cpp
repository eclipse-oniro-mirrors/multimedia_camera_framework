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

#include "command_server_impl.h"

#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr uint32_t MAX_THREAD_NUM = 1;
    constexpr int32_t DEFAULT_PRIORITY = 0;
}

CommandServerImpl::CommandServerImpl(const std::string& cmdServerName)
    : commandServerName_(cmdServerName)
{
    DP_DEBUG_LOG("entered.");
    threadPool_ = ThreadPool::Create(commandServerName_, MAX_THREAD_NUM);
}

CommandServerImpl::~CommandServerImpl()
{
    DP_DEBUG_LOG("entered.");
    threadPool_.reset();
}

int32_t CommandServerImpl::AddCommand(const CmdSharedPtr& cmd)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(threadPool_ == nullptr, DP_NOT_AVAILABLE, "threadPool is nullptr.");
    if (threadPool_->Submit([cmd]() {cmd->Do();})) {
        return DP_OK;
    }
    DP_ERR_LOG("dps command server not start.");
    return DP_NOT_AVAILABLE;
}

int32_t CommandServerImpl::AddUrgentCommand(const CmdSharedPtr& cmd)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(threadPool_ == nullptr, DP_NOT_AVAILABLE, "threadPool is nullptr.");
    if (threadPool_->Submit([cmd]() {cmd->Do();}, true)) {
        return DP_OK;
    }
    DP_ERR_LOG("dps command server not start.");
    return DP_NOT_AVAILABLE;
}

void CommandServerImpl::SetThreadPriority(int32_t priority)
{
    DP_CHECK_ERROR_RETURN_LOG(threadPool_ == nullptr, "threadPool is nullptr.");
    threadPool_->SetThreadPoolPriority(priority);
}

int32_t CommandServerImpl::GetThreadPriority() const
{
    DP_CHECK_ERROR_RETURN_RET_LOG(threadPool_ == nullptr, DEFAULT_PRIORITY, "threadPool is nullptr.");
    return threadPool_->GetThreadPoolPriority();
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS