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

#include "scheduler_manager.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
SchedulerManager::SchedulerManager()
    : photoProcessors_(),
      photoController_(),
      schedulerCoordinator_(nullptr)
{
    DP_DEBUG_LOG("entered");
}

SchedulerManager::~SchedulerManager()
{
    DP_DEBUG_LOG("entered");
    photoController_.clear();
    photoProcessors_.clear();
    schedulerCoordinator_ = nullptr;
}

void SchedulerManager::Initialize()
{
    DP_DEBUG_LOG("entered");
    schedulerCoordinator_ = std::make_unique<SchedulerCoordinator>();
    schedulerCoordinator_->Initialize();
    return;
}

std::shared_ptr<DeferredPhotoProcessor> SchedulerManager::GetPhotoProcessor(int userId, TaskManager* taskManager,
    std::shared_ptr<IImageProcessCallbacks> callbacks)
{
    DP_INFO_LOG("entered");
    if (photoProcessors_.count(userId) == 0) {
        CreatePhotoProcessor(userId, taskManager, callbacks);
    }
    return photoProcessors_[userId];
}


void SchedulerManager::CreatePhotoProcessor(int userId, TaskManager* taskManager,
    std::shared_ptr<IImageProcessCallbacks> callbacks)
{
    DP_INFO_LOG("entered");
    auto photoRepository = std::make_shared<PhotoJobRepository>(userId);
    auto photoProcessor = std::make_shared<DeferredPhotoProcessor>(userId, taskManager, photoRepository, callbacks);
    auto photoController = std::make_shared<DeferredPhotoController>(userId, photoRepository, photoProcessor);
    photoController->Initialize();
    photoProcessor->Initialize();
    photoProcessors_[userId] = photoProcessor;
    photoController_[userId] = photoController;
    return;
}

} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS