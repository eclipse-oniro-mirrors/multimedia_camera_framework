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

#include "deferred_processing_service.h"

#include "dp_log.h"
#include "events_monitor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
DeferredProcessingService& DeferredProcessingService::GetInstance()
{
    static DeferredProcessingService dpsService;
    return dpsService;
}

DeferredProcessingService::DeferredProcessingService()
    : initialized_(false),
      sessionManager_(nullptr),
      schedulerManager_(nullptr),
      photoTaskManagerMap_()
{
    DP_DEBUG_LOG("enter.");
}

DeferredProcessingService::~DeferredProcessingService()
{
    DP_DEBUG_LOG("enter.");
    if (!initialized_) {
        return;
    }
    initialized_ = false;
    sessionManager_ = nullptr;
    schedulerManager_ = nullptr;
    photoTaskManagerMap_.clear();
}

void DeferredProcessingService::Initialize()
{
    if (initialized_) {
        DP_DEBUG_LOG("already initialized.");
        return;
    }
    DP_DEBUG_LOG("entered.");
    sessionManager_ = SessionManager::Create();
    schedulerManager_ = std::make_unique<SchedulerManager>();
    schedulerManager_->Initialize();
    EventsMonitor::GetInstance().Initialize();
    initialized_ = true;
}

void DeferredProcessingService::Start()
{
    DP_INFO_LOG("entered.");
}

void DeferredProcessingService::Stop()
{
    DP_INFO_LOG("entered.");
}

sptr<IDeferredPhotoProcessingSession> DeferredProcessingService::CreateDeferredPhotoProcessingSession(
    const int32_t userId, const sptr<IDeferredPhotoProcessingSessionCallback> callbacks)
{
    DP_INFO_LOG("DeferredProcessingService::CreateDeferredPhotoProcessingSession create session, userId: %{public}d",
        userId);
    TaskManager* taskManager = GetPhotoTaskManager(userId);
    std::shared_ptr<IImageProcessCallbacks> sessionImageProcCallbacks = sessionManager_->GetImageProcCallbacks();
    auto processor = schedulerManager_->GetPhotoProcessor(userId, taskManager, sessionImageProcCallbacks);
    sptr<IDeferredPhotoProcessingSession> session = sessionManager_->CreateDeferredPhotoProcessingSession(userId,
        callbacks, processor, taskManager);
    return session;
}

TaskManager* DeferredProcessingService::GetPhotoTaskManager(const int32_t userId)
{
    std::lock_guard<std::mutex> lock(taskManagerMutex_);
    DP_INFO_LOG("entered, userId: %{public}d", userId);
    if (photoTaskManagerMap_.count(userId) == 0) {
        constexpr uint32_t numThreads = 1;
        std::shared_ptr<TaskManager> taskManager =
            std::make_shared<TaskManager>("PhotoProcTaskManager_userid_" + std::to_string(userId),
            numThreads, true);
        EventsMonitor::GetInstance().RegisterTaskManager(userId, taskManager.get());
        photoTaskManagerMap_[userId] = taskManager;
    }
    return photoTaskManagerMap_[userId].get();
}

void DeferredProcessingService::NotifyCameraSessionStatus(const int32_t userId, const std::string& cameraId,
    bool running, bool isSystemCamera)
{
    DP_INFO_LOG("entered, userId: %{public}d, cameraId: %s, running: %{public}d, isSystemCamera: %{public}d: ",
        userId, cameraId.c_str(), running, isSystemCamera);
    EventsMonitor::GetInstance().NotifyCameraSessionStatus(userId, cameraId, running, isSystemCamera);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS