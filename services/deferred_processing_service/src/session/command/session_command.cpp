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

#include "session_command.h"

#include "dps.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

SessionCommand::SessionCommand(const sptr<VideoSessionInfo>& sessionInfo) : sessionInfo_(sessionInfo)
{
    DP_DEBUG_LOG("entered.");
}

SessionCommand::~SessionCommand()
{
    DP_DEBUG_LOG("entered.");
    sessionManager_ = nullptr;
    sessionInfo_ = nullptr;
}

int32_t SessionCommand::Initialize()
{
    DP_CHECK_RETURN_RET(initialized_.load(), DP_OK);

    sessionManager_ = DPS_GetSessionManager();
    DP_CHECK_ERROR_RETURN_RET_LOG(sessionManager_ == nullptr, DP_NULL_POINTER, "SessionManager is nullptr.");
    initialized_.store(true);
    return DP_OK;
}

int32_t AddVideoSessionCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }
    
    auto coordinator = sessionManager_->GetSessionCoordinator();
    DP_CHECK_ERROR_RETURN_RET_LOG(coordinator == nullptr, DP_NULL_POINTER, "SessionCoordinator is nullptr.");
    auto schedulerManager = DPS_GetSchedulerManager();
    DP_CHECK_ERROR_RETURN_RET_LOG(schedulerManager == nullptr, DP_NULL_POINTER, "SchedulerManager is nullptr");
    schedulerManager->CreateVideoProcessor(sessionInfo_->GetUserId(), coordinator->GetVideoProcCallbacks());
    coordinator->AddSession(sessionInfo_);
    return DP_OK;
}

int32_t DeleteVideoSessionCommand::Executing()
{
    if (int32_t ret = Initialize() != DP_OK) {
        return ret;
    }
    
    auto coordinator = sessionManager_->GetSessionCoordinator();
    DP_CHECK_ERROR_RETURN_RET_LOG(coordinator == nullptr, DP_NULL_POINTER, "SessionCoordinator is nullptr.");
    coordinator->DeleteSession(sessionInfo_->GetUserId());
    return DP_OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS