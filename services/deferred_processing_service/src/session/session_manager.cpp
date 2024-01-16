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
#include "session_manager.h"
#include "system_ability_definition.h"
#include "session_info.h"
#include "dp_log.h"
#include "dp_utils.h"

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
      coordinator_(std::make_unique<SessionCoordinator>())
{
    DP_DEBUG_LOG("entered.");
}

SessionManager::~SessionManager()
{
    DP_DEBUG_LOG("entered.");
    initialized_ = false;
    coordinator_ = nullptr;
    photoSessionInfos_.clear();
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

sptr<IDeferredPhotoProcessingSession> SessionManager::CreateDeferredPhotoProcessingSession(int userId,
    const sptr<IDeferredPhotoProcessingSessionCallback> callback, std::shared_ptr<DeferredPhotoProcessor> processor,
    TaskManager* taskManager)
{
    DP_INFO_LOG("SessionManager::CreateDeferredPhotoProcessingSession create session for userId: %d", userId);
    if (initialized_.load() == false) {
        DP_ERR_LOG("failed due to uninitialized.");
        return nullptr;
    }

    auto iter = photoSessionInfos_.find(userId);
    if (iter != photoSessionInfos_.end()) {
        DP_INFO_LOG("SessionManager::CreateDeferredPhotoProcessorSession failed due to photoSession already existed");
        sptr<SessionInfo> sessionInfo = iter->second;
        sessionInfo->SetCallback(callback);
        coordinator_->NotifySessionCreated(userId, callback);
        return sessionInfo->GetDeferredPhotoProcessingSession();
    }
    sptr<SessionInfo> sessionInfo(new SessionInfo(userId, callback, this));
    sessionInfo->CreateDeferredPhotoProcessingSession(userId, processor, taskManager, callback);
    coordinator_->NotifySessionCreated(userId, callback);
    photoSessionInfos_[userId] = sessionInfo;
    return sessionInfo->GetDeferredPhotoProcessingSession();
}

std::shared_ptr<IImageProcessCallbacks> SessionManager::GetImageProcCallbacks()
{
    DP_INFO_LOG("SessionManager::GetImageProcCallbacks enter.");
    return coordinator_->GetImageProcCallbacks();
}

void SessionManager::OnCallbackDied(int userId)
{
    if (photoSessionInfos_.count(userId) != 0) {
        coordinator_->NotifyCallbackDestroyed(userId);
    }
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
