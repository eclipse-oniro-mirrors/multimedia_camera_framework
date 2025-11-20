/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
SessionManager::SessionManager()
{
    DP_DEBUG_LOG("entered.");
}

SessionManager::~SessionManager()
{
    DP_INFO_LOG("entered.");
    std::lock_guardstd::mutex lock(photoSessionMutex_);
    photoSessionInfos_.clear();
    videoSessionInfos_.clear();
}

int32_t SessionManager::Initialize()
{
    coordinator_ = SessionCoordinator::Create();
    DP_CHECK_ERROR_RETURN_RET_LOG(coordinator_ == nullptr, DP_INIT_FAIL, "SessionCoordinator init failed.");

    initialized_.store(true);
    return DP_OK;
}

void SessionManager::Start()
{
    coordinator_->Start();
}

void SessionManager::Stop()
{
    coordinator_->Stop();
}

sptr<IDeferredPhotoProcessingSession> SessionManager::CreateDeferredPhotoProcessingSession(const int32_t userId,
    const sptr<IDeferredPhotoProcessingSessionCallback>& callback)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(!initialized_.load(), nullptr, "failed due to uninitialized.");

    DP_INFO_LOG("Create photo session for userId: %{public}d", userId);
    auto sessionInfo = GetPhotoInfo(userId);
    if (sessionInfo == nullptr) {
        DP_INFO_LOG("Photo session creat susses");
        sessionInfo = sptr<PhotoSessionInfo>::MakeSptr(userId, callback);
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
    std::lock_guard<std::mutex> lock(photoSessionMutex_);
    auto it = photoSessionInfos_.find(userId);
    DP_CHECK_ERROR_RETURN_RET_LOG(it == photoSessionInfos_.end(), nullptr,
        "Not find PhotoSessionInfo for userId: %{public}d", userId);
    DP_INFO_LOG("DPS_PHOTO: Photo user count: %{public}zu", photoSessionInfos_.size());
    return it->second;
}

void SessionManager::AddPhotoSession(const sptr<PhotoSessionInfo>& sessionInfo)
{
    std::lock_guard<std::mutex> lock(photoSessionMutex_);
    int32_t userId = sessionInfo->GetUserId();
    DP_INFO_LOG("Add photo session userId: %{public}d", userId);
    photoSessionInfos_[userId] = sessionInfo;
}

void SessionManager::DeletePhotoSession(const int32_t userId)
{
    std::lock_guard<std::mutex> lock(photoSessionMutex_);
    if (photoSessionInfos_.erase(userId) > 0) {
        DP_INFO_LOG("Delete photo session userId: %{public}d", userId);
    }
}

sptr<IDeferredPhotoProcessingSessionCallback> SessionManager::GetCallback(const int32_t userId)
{
    if (auto sessionInfo = GetPhotoInfo(userId)) {
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
