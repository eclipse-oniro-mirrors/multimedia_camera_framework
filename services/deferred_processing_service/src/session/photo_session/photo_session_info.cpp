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

#include "photo_session_info.h"

#include "dp_log.h"
#include "dps.h"
#include "ideferred_photo_processing_session.h"
#include "session_command.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class PhotoSessionInfo::CallbackDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit CallbackDeathRecipient(const wptr<PhotoSessionInfo>& sessionInfo)
        : sessionInfo_(sessionInfo)
    {
        DP_DEBUG_LOG("entered.");
    }
    ~CallbackDeathRecipient() = default;

    int32_t Initialize(const sptr<IDeferredPhotoProcessingSessionCallback>& callback)
    {
        DP_DEBUG_LOG("entered.");
        sptr<IRemoteObject> object = callback->AsObject();
        auto result = object->AddDeathRecipient(this);
        DP_CHECK_ERROR_RETURN_RET_LOG(!result, DP_INIT_FAIL,
            "Add photo DeathRecipient for Callback failed.");
        return DP_OK;
    }

    int32_t Destroy(const sptr<IDeferredPhotoProcessingSessionCallback>& callback)
    {
        DP_DEBUG_LOG("entered.");
        sptr<IRemoteObject> object = callback->AsObject();
        auto result = object->RemoveDeathRecipient(this);
        DP_CHECK_ERROR_RETURN_RET_LOG(!result, DP_INIT_FAIL,
            "Remove photo DeathRecipient for Callback failed.");
        return DP_OK;
    }

    void OnRemoteDied(const wptr<IRemoteObject> &remote) override
    {
        DP_ERR_LOG("Photo remote died.");
        auto info = sessionInfo_.promote();
        DP_CHECK_RETURN_LOG(info == nullptr, "PhotoSessionInfo is nullptr.");
        info->OnCallbackDied();
    }
private:
    wptr<PhotoSessionInfo> sessionInfo_;
};

PhotoSessionInfo::PhotoSessionInfo(const int32_t userId, const sptr<IDeferredPhotoProcessingSessionCallback>& callback)
    : userId_(userId),
      callback_(callback)
{
    DP_DEBUG_LOG("entered. userId: %{public}d.", userId_);
    Initialize();
}

PhotoSessionInfo::~PhotoSessionInfo()
{
    DP_INFO_LOG("entered. userId: %{public}d.", userId_);
    DP_CHECK_EXECUTE(callback_ != nullptr && deathRecipient_ != nullptr, deathRecipient_->Destroy(callback_));
}

int32_t PhotoSessionInfo::Initialize()
{
    DP_CHECK_ERROR_RETURN_RET_LOG(callback_ == nullptr, DP_NULL_POINTER,
        "PhotoSessionInfo init failed, callback is nullptr.");

    session_ = sptr<DeferredPhotoProcessingSession>::MakeSptr(userId_);
    deathRecipient_ = sptr<CallbackDeathRecipient>::MakeSptr(this);

    auto ret = deathRecipient_->Initialize(callback_);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != DP_OK, ret, "Set photo DeathRecipient failed.");
    return DP_OK;
}

sptr<IDeferredPhotoProcessingSession> PhotoSessionInfo::GetDeferredPhotoProcessingSession()
{
    return session_;
}

sptr<IDeferredPhotoProcessingSessionCallback> PhotoSessionInfo::GetRemoteCallback()
{
    std::lock_guard lock(callbackMutex_);
    return callback_;
}

void PhotoSessionInfo::OnCallbackDied()
{
    auto ret = DPS_SendUrgentCommand<DeletePhotoSessionCommand>(this);
    DP_CHECK_ERROR_PRINT_LOG(ret != DP_OK, "DeletePhotoSession failed.");
}

void PhotoSessionInfo::SetCallback(const sptr<IDeferredPhotoProcessingSessionCallback>& callback)
{
    DP_INFO_LOG("Reset phot callback.");
    std::lock_guard lock(callbackMutex_);
    isCreate_ = false;
    callback_ = callback;
    auto ret = deathRecipient_->Initialize(callback_);
    DP_CHECK_ERROR_PRINT_LOG(ret != DP_OK, "Set photo DeathRecipient failed.");
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
