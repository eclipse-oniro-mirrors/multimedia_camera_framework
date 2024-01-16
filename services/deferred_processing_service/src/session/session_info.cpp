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
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "session_info.h"
#include "session_manager.h"
#include "utils/dp_log.h"
#include "ideferred_photo_processing_session.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
extern sptr<IDeferredPhotoProcessingSession> CreateDeferredProcessingSession(int userId,
    std::shared_ptr<DeferredPhotoProcessor> processor, TaskManager* taskManager,
    sptr<IDeferredPhotoProcessingSessionCallback> callback);

class SessionInfo::CallbackDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit CallbackDeathRecipient(SessionInfo* sessionInfo)
        : sessionInfo_(sessionInfo)
    {
    }
    ~CallbackDeathRecipient()
    {
        sessionInfo_ = nullptr;
    }
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override
    {
        DP_ERR_LOG("Remote died, do clean works.");
        if (sessionInfo_ == nullptr) {
            return;
        }
        sessionInfo_->OnCallbackDied();
    }
private:
    SessionInfo* sessionInfo_;
};

SessionInfo::SessionInfo(int userId, const sptr<IDeferredPhotoProcessingSessionCallback>& callback,
    SessionManager* sessionManager)
    : userId_(userId),
      callback_(callback),
      sessionManager_(sessionManager)
{
    DP_DEBUG_LOG("userId: %d.", userId_);
    callbackDeathRecipient_ = sptr<CallbackDeathRecipient>::MakeSptr(this);
    SetCallback(callback);
}

SessionInfo::~SessionInfo()
{
    DP_DEBUG_LOG("entered.");
    callback_ = nullptr;
    sessionManager_ = nullptr;
}

sptr<IDeferredPhotoProcessingSession> SessionInfo::CreateDeferredPhotoProcessingSession(int userId,
    std::shared_ptr<DeferredPhotoProcessor> processor, TaskManager* taskManager,
    sptr<IDeferredPhotoProcessingSessionCallback> callback)
{
    DP_INFO_LOG("SessionInfo::CreateDeferredPhotoProcessingSession enter.");
    session_ = CreateDeferredProcessingSession(userId, processor, taskManager, callback);
    return session_;
}

sptr<IDeferredPhotoProcessingSession> SessionInfo::GetDeferredPhotoProcessingSession()
{
    return session_;
}

sptr<IDeferredPhotoProcessingSessionCallback> SessionInfo::GetRemoteCallback()
{
    return callback_;
}

void SessionInfo::OnCallbackDied()
{
    if (sessionManager_ == nullptr) {
        DP_ERR_LOG("SessionInfo::sessionManager_ is null.");
        return;
    }
    sessionManager_->OnCallbackDied(userId_);
}

void SessionInfo::SetCallback(const sptr<IDeferredPhotoProcessingSessionCallback>& callback)
{
    DP_INFO_LOG("reset callback");
    callback_ = callback;
    sptr<IRemoteObject> object = callback_->AsObject();
    auto result = object->AddDeathRecipient(callbackDeathRecipient_);
    if (!result) {
        DP_ERR_LOG("AddDeathRecipient for Callback failed.");
    }
    return;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
