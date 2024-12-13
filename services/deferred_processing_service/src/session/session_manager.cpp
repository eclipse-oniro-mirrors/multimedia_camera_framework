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

#include "session_manager.h"

#include "dp_log.h"
#include "dps.h"
#include "session_command.h"
#include "session_coordinator.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

std::shared_ptr<SessionManager> SessionManager::Create()
{
    DP_DEBUG_LOG("entered.");
    auto sessionManager = CreateShared<SessionManager>();
    if (sessionManager) {
        sessionManager->Initialize();
    }
    return sessionManager;
}

SessionManager::SessionManager()
    : initialized_(false),
      photoSessionInfos_(),
      coordinator_(std::make_shared<SessionCoordinator>())
{
    DP_DEBUG_LOG("entered.");
}

SessionManager::~SessionManager()
{
    DP_DEBUG_LOG("entered.");
    initialized_ = false;
    coordinator_ = nullptr;
    photoSessionInfos_.clear();
    videoSessionInfos_.clear();
}

void SessionManager::Initialize()
{
    coordinator_->Initialize();
    initialized_ = true;
    return;
}

void SessionManager::Start()
{
    coordinator_->Start();
    return;
}

void SessionManager::Stop()
{
    coordinator_->Stop();
    return;
}

sptr<IDeferredPhotoProcessingSession> SessionManager::CreateDeferredPhotoProcessingSession(const int32_t userId,
    const sptr<IDeferredPhotoProcessingSessionCallback>& callback, std::shared_ptr<DeferredPhotoProcessor> processor,
    TaskManager* taskManager)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(!initialized_.load(), nullptr, "failed due to uninitialized.");

    DP_INFO_LOG("SessionManager::CreateDeferredPhotoProcessingSession create session for userId: %{public}d", userId);
    for (auto it = photoSessionInfos_.begin(); it != photoSessionInfos_.end(); ++it) {
        DP_DEBUG_LOG("dump photoSessionInfos_ userId: %{public}d", it->first);
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = photoSessionInfos_.find(userId);
    if (iter != photoSessionInfos_.end()) {
        DP_INFO_LOG("SessionManager::CreateDeferredPhotoProcessorSession failed due to photoSession already existed");
        sptr<SessionInfo> sessionInfo = iter->second;
        sessionInfo->SetCallback(callback);
        coordinator_->NotifySessionCreated(userId, callback, taskManager);
        return sessionInfo->GetDeferredPhotoProcessingSession();
    }
    sptr<SessionInfo> sessionInfo(new SessionInfo(userId, callback, this));
    sessionInfo->CreateDeferredPhotoProcessingSession(userId, processor, taskManager, callback);
    coordinator_->NotifySessionCreated(userId, callback, taskManager);
    photoSessionInfos_[userId] = sessionInfo;
    return sessionInfo->GetDeferredPhotoProcessingSession();
}

std::shared_ptr<IImageProcessCallbacks> SessionManager::GetImageProcCallbacks()
{
    DP_INFO_LOG("SessionManager::GetImageProcCallbacks enter.");
    return coordinator_->GetImageProcCallbacks();
}

sptr<IDeferredPhotoProcessingSessionCallback> SessionManager::GetCallback(const int32_t userId)
{
    auto iter = photoSessionInfos_.find(userId);
    if (iter != photoSessionInfos_.end()) {
        DP_INFO_LOG("SessionManager::GetCallback");
        sptr<SessionInfo> sessionInfo = iter->second;
        return sessionInfo->GetRemoteCallback();
    }
    return nullptr;
}

sptr<IDeferredVideoProcessingSession> SessionManager::CreateDeferredVideoProcessingSession(const int32_t userId,
    const sptr<IDeferredVideoProcessingSessionCallback>& callback)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(!initialized_.load(), nullptr, "failed due to uninitialized.");

    DP_INFO_LOG("Create DeferredVideoProcessingSession for userId: %{public}d", userId);
    std::lock_guard<std::mutex> lock(videoSessionMutex_);
    auto sessionInfo = GetSessionInfo(userId);
    if (sessionInfo == nullptr) {
        DP_INFO_LOG("DeferredVideoProcessingSession susses");
        sessionInfo = sptr<VideoSessionInfo>::MakeSptr(userId, callback);
        videoSessionInfos_.emplace(userId, sessionInfo);
    } else {
        DP_INFO_LOG("DeferredVideoProcessingSession already existed");
        sessionInfo->SetCallback(callback);
    }
    auto ret = DPS_SendUrgentCommand<AddVideoSessionCommand>(sessionInfo);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != DP_OK, nullptr, "AddVideoSession failed, ret: %{public}d", ret);

    return sessionInfo->GetDeferredVideoProcessingSession();
}

sptr<VideoSessionInfo> SessionManager::GetSessionInfo(const int32_t userId)
{
    auto it = videoSessionInfos_.find(userId);
    DP_CHECK_ERROR_RETURN_RET_LOG(it == videoSessionInfos_.end(), nullptr,
        "Not find VideoSessionInfo for userId: %{public}d", userId);
    
    return it->second;
}

std::shared_ptr<SessionCoordinator> SessionManager::GetSessionCoordinator()
{
    return coordinator_;
}

void SessionManager::OnCallbackDied(const int32_t userId)
{
    if (photoSessionInfos_.count(userId) != 0) {
        coordinator_->NotifyCallbackDestroyed(userId);
    }
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
