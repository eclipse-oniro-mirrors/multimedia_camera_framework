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

#include "scheduler_coordinator.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
SchedulerCoordinator::SchedulerCoordinator()
{
    DP_DEBUG_LOG("entered");
}

SchedulerCoordinator::~SchedulerCoordinator()
{
    DP_DEBUG_LOG("entered");
}

void SchedulerCoordinator::Initialize()
{
    DP_DEBUG_LOG("entered");
}

void SchedulerCoordinator::UserRequestReceived(int userId)
{
    DP_DEBUG_LOG("entered");
}

void SchedulerCoordinator::AttachController(int userId, std::shared_ptr<DeferredPhotoController>)
{
    DP_DEBUG_LOG("entered");
}

void SchedulerCoordinator::DetachController(int userId)
{
    DP_DEBUG_LOG("entered");
}

void SchedulerCoordinator::SwitchController()
{
    DP_DEBUG_LOG("entered");
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS