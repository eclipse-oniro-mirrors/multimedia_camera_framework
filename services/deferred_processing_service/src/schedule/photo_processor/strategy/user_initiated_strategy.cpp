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
#include <vector>
#include <shared_mutex>
#include <iostream>

#include "user_initiated_strategy.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
UserInitiatedStrategy::UserInitiatedStrategy(std::shared_ptr<PhotoJobRepository> photoJobRepository)
    : photoJobRepository_(photoJobRepository)
{
    DP_DEBUG_LOG("entered");
}

UserInitiatedStrategy::~UserInitiatedStrategy()
{
    DP_DEBUG_LOG("entered");
    photoJobRepository_ = nullptr;
}

DeferredPhotoWorkPtr UserInitiatedStrategy::GetWork()
{
    DP_INFO_LOG("entered");
    DeferredPhotoJobPtr jobPtr = GetJob();
    ExecutionMode mode = GetExecutionMode();
    if ((jobPtr != nullptr) && (mode != ExecutionMode::DUMMY)) {
        return std::make_shared<DeferredPhotoWork>(jobPtr, mode);
    }
    return nullptr;
}

DeferredPhotoJobPtr UserInitiatedStrategy::GetJob()
{
    return photoJobRepository_->GetHighPriorityJob();
}

ExecutionMode UserInitiatedStrategy::GetExecutionMode()
{
    return ExecutionMode::HIGH_PERFORMANCE;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS