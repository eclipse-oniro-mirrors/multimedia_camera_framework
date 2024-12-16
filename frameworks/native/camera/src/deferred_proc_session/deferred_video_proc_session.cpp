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

#include "deferred_proc_session/deferred_video_proc_session.h"
#include "camera_log.h"
#include "camera_util.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace CameraStandard {

int32_t DeferredVideoProcessingSessionCallback::OnProcessVideoDone(const std::string& videoId,
    const sptr<IPCFileDescriptor>& ipcFileDescriptor)
{
    MEDIA_INFO_LOG("DeferredVideoProcessingSessionCallback::OnProcessVideoDone() is called!");
    if (deferredVideoProcSession_ != nullptr && deferredVideoProcSession_->GetCallback() != nullptr) {
        deferredVideoProcSession_->GetCallback()->OnProcessVideoDone(videoId, ipcFileDescriptor);
    } else {
        MEDIA_INFO_LOG("DeferredVideoProcessingSessionCallback::OnProcessVideoDone not set!, Discarding callback");
    }
    return ERR_OK;
}

int32_t DeferredVideoProcessingSessionCallback::OnError(const std::string& videoId,
    int32_t errorCode)
{
    MEDIA_INFO_LOG("DeferredVideoProcessingSessionCallback::OnError() is called, errorCode: %{public}d", errorCode);
    if (deferredVideoProcSession_ != nullptr && deferredVideoProcSession_->GetCallback() != nullptr) {
        deferredVideoProcSession_->GetCallback()->OnError(videoId, DpsErrorCode(errorCode));
    } else {
        MEDIA_INFO_LOG("DeferredVideoProcessingSessionCallback::OnError not set!, Discarding callback");
    }
    return ERR_OK;
}

int32_t DeferredVideoProcessingSessionCallback::OnStateChanged(int32_t status)
{
    MEDIA_INFO_LOG("DeferredVideoProcessingSessionCallback::OnStateChanged() is called, status:%{public}d", status);
    if (deferredVideoProcSession_ != nullptr && deferredVideoProcSession_->GetCallback() != nullptr) {
        deferredVideoProcSession_->GetCallback()->OnStateChanged(DpsStatusCode(status));
    } else {
        MEDIA_INFO_LOG("DeferredVideoProcessingSessionCallback::OnStateChanged not set!, Discarding callback");
    }
    return ERR_OK;
}

DeferredVideoProcSession::DeferredVideoProcSession(int userId,
    std::shared_ptr<IDeferredVideoProcSessionCallback> callback)
{
    MEDIA_INFO_LOG("enter.");
    userId_ = userId;
    callback_ = callback;
}

DeferredVideoProcSession::~DeferredVideoProcSession()
{
    MEDIA_INFO_LOG("DeferredVideoProcSession::DeferredVideoProcSession Destructor!");
    if (remoteSession_ != nullptr) {
        (void)remoteSession_->AsObject()->RemoveDeathRecipient(deathRecipient_);
        remoteSession_ = nullptr;
    }
}

void DeferredVideoProcSession::BeginSynchronize()
{
    if (remoteSession_ == nullptr) {
        MEDIA_ERR_LOG("DeferredVideoProcSession::BeginSynchronize failed due to binder died.");
    } else {
        MEDIA_INFO_LOG("DeferredVideoProcSession:BeginSynchronize() enter.");
        auto ret = remoteSession_->BeginSynchronize();
        CHECK_ERROR_PRINT_LOG(ret != ERR_OK, "EndSynchronize failed errorCode: %{public}d", ret);
    }
}

void DeferredVideoProcSession::EndSynchronize()
{
    if (remoteSession_ == nullptr) {
        MEDIA_ERR_LOG("DeferredVideoProcSession::EndSynchronize failed due to binder died.");
    } else {
        MEDIA_INFO_LOG("DeferredVideoProcSession::EndSynchronize() enter.");
        auto ret = remoteSession_->EndSynchronize();
        CHECK_ERROR_PRINT_LOG(ret != ERR_OK, "EndSynchronize failed errorCode: %{public}d", ret);
    }
}

void DeferredVideoProcSession::AddVideo(const std::string& videoId, const sptr<IPCFileDescriptor> srcFd,
    const sptr<IPCFileDescriptor> dstFd)
{
    if (remoteSession_ == nullptr) {
        MEDIA_ERR_LOG("DeferredVideoProcSession::AddVideo failed due to binder died.");
    } else {
        MEDIA_INFO_LOG("DeferredVideoProcSession::AddVideo() enter.");
        auto ret = remoteSession_->AddVideo(videoId, srcFd, dstFd);
        CHECK_ERROR_PRINT_LOG(ret != ERR_OK, "AddVideo failed errorCode: %{public}d", ret);
    }
}

void DeferredVideoProcSession::RemoveVideo(const std::string& videoId, const bool restorable)
{
    if (remoteSession_ == nullptr) {
        MEDIA_ERR_LOG("DeferredVideoProcSession::RemoveVideo failed due to binder died.");
    } else {
        MEDIA_INFO_LOG("DeferredVideoProcSession RemoveVideo() enter.");
        auto ret = remoteSession_->RemoveVideo(videoId, restorable);
        CHECK_ERROR_PRINT_LOG(ret != ERR_OK, "RemoveVideo failed errorCode: %{public}d", ret);
    }
}

void DeferredVideoProcSession::RestoreVideo(const std::string& videoId)
{
    if (remoteSession_ == nullptr) {
        MEDIA_ERR_LOG("DeferredVideoProcSession::RestoreVideo failed due to binder died.");
    } else {
        MEDIA_INFO_LOG("DeferredVideoProcSession RestoreVideo() enter.");
        auto ret = remoteSession_->RestoreVideo(videoId);
        CHECK_ERROR_PRINT_LOG(ret != ERR_OK, "RestoreVideo failed errorCode: %{public}d", ret);
    }
}

int32_t DeferredVideoProcSession::SetDeferredVideoSession(
    sptr<DeferredProcessing::IDeferredVideoProcessingSession>& session)
{
    remoteSession_ = session;
    sptr<IRemoteObject> object = remoteSession_->AsObject();
    pid_t pid = 0;
    deathRecipient_ = new(std::nothrow) CameraDeathRecipient(pid);
    CHECK_ERROR_RETURN_RET_LOG(deathRecipient_ == nullptr, CAMERA_ALLOC_ERROR, "failed to new CameraDeathRecipient.");

    deathRecipient_->SetNotifyCb(std::bind(&DeferredVideoProcSession::CameraServerDied, this, std::placeholders::_1));
    bool result = object->AddDeathRecipient(deathRecipient_);
    if (!result) {
        MEDIA_ERR_LOG("failed to add deathRecipient");
        return -1;  // return error
    }
    return ERR_OK;
}

void DeferredVideoProcSession::CameraServerDied(pid_t pid)
{
    MEDIA_ERR_LOG("camera server has died, pid:%{public}d!", pid);
    if (remoteSession_ != nullptr) {
        (void)remoteSession_->AsObject()->RemoveDeathRecipient(deathRecipient_);
        remoteSession_ = nullptr;
    }
    deathRecipient_ = nullptr;
    ReconnectDeferredProcessingSession();
    if (callback_ != nullptr) {
        MEDIA_INFO_LOG("Reconnect session successful, send sync requestion.");
        callback_->OnError("", DpsErrorCode::ERROR_SESSION_SYNC_NEEDED);
    }
}

void DeferredVideoProcSession::ReconnectDeferredProcessingSession()
{
    MEDIA_INFO_LOG("DeferredVideoProcSession::ReconnectDeferredProcessingSession, enter.");
    ConnectDeferredProcessingSession();
    if (remoteSession_ == nullptr) {
        MEDIA_INFO_LOG("Reconnecting deferred processing session failed.");
        ReconnectDeferredProcessingSession();
    }
}

void DeferredVideoProcSession::ConnectDeferredProcessingSession()
{
    MEDIA_INFO_LOG("DeferredVideoProcSession::ConnectDeferredProcessingSession, enter.");
    CHECK_ERROR_RETURN_LOG(remoteSession_ != nullptr, "remoteSession_ is not null");
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_ERROR_RETURN_LOG(samgr == nullptr, "Failed to get System ability manager");
    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_ERROR_RETURN_LOG(object == nullptr, "object is null");
    serviceProxy_ = iface_cast<ICameraService>(object);
    CHECK_ERROR_RETURN_LOG(serviceProxy_ == nullptr, "serviceProxy_ is null");
    sptr<DeferredProcessing::IDeferredVideoProcessingSession> session = nullptr;
    sptr<DeferredProcessing::IDeferredVideoProcessingSessionCallback> remoteCallback = nullptr;
    sptr<DeferredVideoProcSession> deferredVideoProcSession = nullptr;
    deferredVideoProcSession = new(std::nothrow) DeferredVideoProcSession(userId_, callback_);
    CHECK_ERROR_RETURN(deferredVideoProcSession == nullptr);
    remoteCallback = new(std::nothrow) DeferredVideoProcessingSessionCallback(deferredVideoProcSession);
    CHECK_ERROR_RETURN(remoteCallback == nullptr);
    serviceProxy_->CreateDeferredVideoProcessingSession(userId_, remoteCallback, session);
    if (session) {
        SetDeferredVideoSession(session);
    }
}

std::shared_ptr<IDeferredVideoProcSessionCallback> DeferredVideoProcSession::GetCallback()
{
    return callback_;
}

} // namespace CameraStandard
} // namespace OHOS