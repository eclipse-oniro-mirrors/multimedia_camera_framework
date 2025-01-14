/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "video_session_info.h"

#include "deferred_video_processing_session.h"
#include "dp_log.h"
#include "dps.h"
#include "session_command.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class VideoSessionInfo::CallbackDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit CallbackDeathRecipient(const wptr<VideoSessionInfo>& sessionInfo)
        : sessionInfo_(sessionInfo)
    {
        DP_DEBUG_LOG("entered.");
    }
    virtual ~CallbackDeathRecipient() = default;

    int32_t Initialize(const sptr<IDeferredVideoProcessingSessionCallback>& callback)
    {
        DP_DEBUG_LOG("entered.");
        sptr<IRemoteObject> object = callback->AsObject();
        auto result = object->AddDeathRecipient(this);
        DP_CHECK_ERROR_RETURN_RET_LOG(!result, DP_INIT_FAIL,
            "Add video DeathRecipient for Callback failed.");
        return DP_OK;
    }

    int32_t Destroy(const sptr<IDeferredVideoProcessingSessionCallback>& callback)
    {
        DP_DEBUG_LOG("entered.");
        sptr<IRemoteObject> object = callback->AsObject();
        auto result = object->RemoveDeathRecipient(this);
        DP_CHECK_ERROR_RETURN_RET_LOG(!result, DP_INIT_FAIL,
            "Remove video DeathRecipient for Callback failed.");
        return DP_OK;
    }

    void OnRemoteDied(const wptr<IRemoteObject> &remote) override
    {
        DP_ERR_LOG("Video remote died.");
        auto info = sessionInfo_.promote();
        DP_CHECK_RETURN_LOG(info == nullptr, "VideoSessionInfo is nullptr.");
        info->OnCallbackDied();
    }

private:
    wptr<VideoSessionInfo> sessionInfo_;
};

VideoSessionInfo::VideoSessionInfo(const int32_t userId, const sptr<IDeferredVideoProcessingSessionCallback>& callback)
    : userId_(userId), callback_(callback), deathRecipient_(nullptr)
{
    DP_DEBUG_LOG("entered. userId: %{public}d.", userId_);
    Initialize();
}

VideoSessionInfo::~VideoSessionInfo()
{
    DP_INFO_LOG("entered. userId: %{public}d.", userId_);
    DP_CHECK_EXECUTE(callback_ != nullptr && deathRecipient_ != nullptr, deathRecipient_->Destroy(callback_));
}

int32_t VideoSessionInfo::Initialize()
{
    DP_CHECK_ERROR_RETURN_RET_LOG(callback_ == nullptr, DP_NULL_POINTER,
        "VideoSessionInfo init failed, callback is nullptr.");

    session_ = sptr<DeferredVideoProcessingSession>::MakeSptr(userId_);
    deathRecipient_ = sptr<CallbackDeathRecipient>::MakeSptr(this);

    auto ret = deathRecipient_->Initialize(callback_);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != DP_OK, ret, "set video DeathRecipient failed.");
    return DP_OK;
}

sptr<IDeferredVideoProcessingSession> VideoSessionInfo::GetDeferredVideoProcessingSession()
{
    return session_;
}

sptr<IDeferredVideoProcessingSessionCallback> VideoSessionInfo::GetRemoteCallback()
{
    std::lock_guard lock(callbackMutex_);
    return callback_;
}

void VideoSessionInfo::OnCallbackDied()
{
    auto ret = DPS_SendUrgentCommand<DeleteVideoSessionCommand>(this);
    DP_CHECK_ERROR_PRINT_LOG(ret != DP_OK, "DeleteVideoSession failed.");
}

void VideoSessionInfo::SetCallback(const sptr<IDeferredVideoProcessingSessionCallback>& callback)
{
    DP_INFO_LOG("Reset video callback.");
    std::lock_guard lock(callbackMutex_);
    isCreate_ = false;
    callback_ = callback;
    auto ret = deathRecipient_->Initialize(callback_);
    DP_CHECK_ERROR_PRINT_LOG(ret != DP_OK, "Set video DeathRecipient failed.");
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
