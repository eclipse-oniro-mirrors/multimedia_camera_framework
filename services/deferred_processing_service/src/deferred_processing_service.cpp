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

#include "deferred_processing_service.h"

#include "events_info.h"
#include "events_monitor.h"
#include "dp_log.h"
#include "dps.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
DeferredProcessingService::DeferredProcessingService()
{
    DP_DEBUG_LOG("entered.");
}

DeferredProcessingService::~DeferredProcessingService()
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_RETURN(!initialized_.load());

    photoTaskManagerMap_.clear();
    DPS_Destroy();
}

void DeferredProcessingService::Initialize()
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_RETURN(initialized_.load());

    DPS_Initialize();
    EventsMonitor::GetInstance().Initialize();
    EventsInfo::GetInstance().Initialize();
    initialized_.store(true);
}

void DeferredProcessingService::Start()
{
    DP_DEBUG_LOG("entered.");
}

void DeferredProcessingService::Stop()
{
    DP_DEBUG_LOG("entered.");
}

void DeferredProcessingService::NotifyLowQualityImage(const int32_t userId, const std::string& imageId,
    std::shared_ptr<Media::Picture> picture)
{
    DP_INFO_LOG("entered.");
    auto sessionManager = DPS_GetSessionManager();
    if (sessionManager != nullptr && sessionManager->GetCallback(userId) != nullptr) {
        sessionManager->GetCallback(userId)->OnDeliveryLowQualityImage(imageId, picture);
    } else {
        DP_INFO_LOG("DeferredPhotoProcessingSessionCallback::NotifyLowQualityImage not set!, Discarding callback");
    }
}

sptr<IDeferredPhotoProcessingSession> DeferredProcessingService::CreateDeferredPhotoProcessingSession(
    const int32_t userId, const sptr<IDeferredPhotoProcessingSessionCallback> callbacks)
{
    DP_INFO_LOG("DeferredProcessingService::CreateDeferredPhotoProcessingSession create session, userId: %{public}d",
        userId);
    TaskManager* taskManager = GetPhotoTaskManager(userId);
    auto schedulerManager = DPS_GetSchedulerManager();
    auto sessionManager = DPS_GetSessionManager();
    if (schedulerManager == nullptr || sessionManager == nullptr) {
        DP_ERR_LOG("schedulerManager or sessionManager is nullptr.");
        return nullptr;
    }
    std::shared_ptr<IImageProcessCallbacks> sessionImageProcCallbacks = sessionManager->GetImageProcCallbacks();
    auto processor = schedulerManager->GetPhotoProcessor(userId, taskManager, sessionImageProcCallbacks);
    sptr<IDeferredPhotoProcessingSession> session = sessionManager->CreateDeferredPhotoProcessingSession(userId,
        callbacks, processor, taskManager);
    return session;
}

sptr<IDeferredVideoProcessingSession> DeferredProcessingService::CreateDeferredVideoProcessingSession(
    const int32_t userId, const sptr<IDeferredVideoProcessingSessionCallback> callbacks)
{
    DP_INFO_LOG("create video session, userId: %{public}d", userId);
    auto sessionManager = DPS_GetSessionManager();
    DP_CHECK_ERROR_RETURN_RET_LOG(sessionManager == nullptr, nullptr,
        "SessionManager is null, userId: %{public}d", userId);
    return sessionManager->CreateDeferredVideoProcessingSession(userId, callbacks);
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