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

SessionManager::SessionManager() : coordinator_(CreateShared<SessionCoordinator>())
{
    DP_DEBUG_LOG("entered.");
}

SessionManager::~SessionManager()
{
    DP_INFO_LOG("entered.");
    photoSessionInfos_.clear();
    videoSessionInfos_.clear();
}

void SessionManager::Initialize()
{
    DP_CHECK_EXECUTE(coordinator_ != nullptr, coordinator_->Initialize());
    initialized_.store(true);
}

void SessionManager::Start()
{
    DP_CHECK_EXECUTE(coordinator_ != nullptr, coordinator_->Start());
}

void SessionManager::Stop()
{
    DP_CHECK_EXECUTE(coordinator_ != nullptr, coordinator_->Stop());
}

sptr<IDeferredPhotoProcessingSession> SessionManager::CreateDeferredPhotoProcessingSession(const int32_t userId,
    const sptr<IDeferredPhotoProcessingSessionCallback>& callback)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(!initialized_.load(), nullptr, "failed due to uninitialized.");

    DP_INFO_LOG("Create photo session for userId: %{public}d", userId);
    std::lock_guard<std::mutex> lock(photoSessionMutex_);
    auto sessionInfo = GetPhotoInfo(userId);
    if (sessionInfo == nullptr) {
        DP_INFO_LOG("Photo session creat susses");
        sessionInfo = sptr<PhotoSessionInfo>::MakeSptr(userId, callback);
        photoSessionInfos_.emplace(userId, sessionInfo);
    } else {
        DP_DEBUG_LOG("Photo session already existed");
        sessionInfo->SetCallback(callback);
    }
    auto ret = DPS_SendUrgentCommand<AddPhotoSessionCommand>(sessionInfo);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != DP_OK, nullptr, "AddPhotoSession failed, ret: %{public}d", ret);
    
    return sessionInfo->GetDeferredPhotoProcessingSession();
}

sptr<PhotoSessionInfo> SessionManager::GetPhotoInfo(const int32_t userId)
{
    auto it = photoSessionInfos_.find(userId);
    DP_CHECK_ERROR_RETURN_RET_LOG(it == photoSessionInfos_.end(), nullptr,
        "Not find PhotoSessionInfo for userId: %{public}d", userId);
    
    return it->second;
}

std::shared_ptr<IImageProcessCallbacks> SessionManager::GetImageProcCallbacks()
{
    DP_INFO_LOG("SessionManager::GetImageProcCallbacks enter.");
    return coordinator_->GetImageProcCallbacks();
}

sptr<IDeferredPhotoProcessingSessionCallback> SessionManager::GetCallback(const int32_t userId)
{
    auto sessionInfo = GetPhotoInfo(userId);
    if (sessionInfo) {
        return sessionInfo->GetRemoteCallback();
    }
    return nullptr;
}

sptr<IDeferredVideoProcessingSession> SessionManager::CreateDeferredVideoProcessingSession(const int32_t userId,
    const sptr<IDeferredVideoProcessingSessionCallback>& callback)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(!initialized_.load(), nullptr, "failed due to uninitialized.");

    DP_INFO_LOG("Create video session for userId: %{public}d", userId);
    std::lock_guard<std::mutex> lock(videoSessionMutex_);
    auto sessionInfo = GetVideoInfo(userId);
    if (sessionInfo == nullptr) {
        DP_INFO_LOG("Video session creat susses");
        sessionInfo = sptr<VideoSessionInfo>::MakeSptr(userId, callback);
        videoSessionInfos_.emplace(userId, sessionInfo);
    } else {
        DP_DEBUG_LOG("Video session already existed");
        sessionInfo->SetCallback(callback);
    }
    auto ret = DPS_SendUrgentCommand<AddVideoSessionCommand>(sessionInfo);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != DP_OK, nullptr, "AddVideoSession failed, ret: %{public}d", ret);

    return sessionInfo->GetDeferredVideoProcessingSession();
}

sptr<VideoSessionInfo> SessionManager::GetVideoInfo(const int32_t userId)
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
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
