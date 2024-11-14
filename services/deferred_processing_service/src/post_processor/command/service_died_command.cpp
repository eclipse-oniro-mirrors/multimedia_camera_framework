/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "service_died_command.h"

#include "basic_definitions.h"
#include "dps.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

ServiceDiedCommand::ServiceDiedCommand(const int32_t userId) : userId_(userId)
{
    DP_DEBUG_LOG("entered.");
}

ServiceDiedCommand::~ServiceDiedCommand()
{
    DP_DEBUG_LOG("entered.");
}

int32_t ServiceDiedCommand::Executing()
{
    auto schedulerManager = DPS_GetSchedulerManager();
    DP_CHECK_ERROR_RETURN_RET_LOG(schedulerManager == nullptr, DP_NULL_POINTER, "SchedulerManager is nullptr.");
    auto videoPostProcessor = schedulerManager->GetVideoPostProcessor(userId_);
    DP_CHECK_ERROR_RETURN_RET_LOG(videoPostProcessor == nullptr, DP_NULL_POINTER, "VideoPostProcessor is nullptr.");
    auto controller = schedulerManager->GetVideoController(userId_);
    DP_CHECK_ERROR_RETURN_RET_LOG(controller == nullptr, DP_NULL_POINTER, "VideoController is nullptr.");

    videoPostProcessor->OnSessionDied();
    controller->HandleServiceDied();
    return DP_OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS