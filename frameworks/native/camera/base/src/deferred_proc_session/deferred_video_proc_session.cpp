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

int32_t DeferredVideoProcessingSessionCallback::OnProcessVideoDone(const std::string& videoId)
{
    MEDIA_INFO_LOG("DeferredVideoProcessingSessionCallback::OnProcessVideoDone() is called!");
    bool isCallbackSet = deferredVideoProcSession_ != nullptr && deferredVideoProcSession_->GetCallback() != nullptr;
    if (isCallbackSet) {
        deferredVideoProcSession_->GetCallback()->OnProcessVideoDone(videoId);
    } else {
        MEDIA_INFO_LOG("DeferredVideoProcessingSessionCallback::OnProcessVideoDone not set!, Discarding callback");
    }
    return ERR_OK;
}

int32_t DeferredVideoProcessingSessionCallback::OnError(const std::string& videoId,
    DeferredProcessing::ErrorCode errorCode)
{
    MEDIA_INFO_LOG("DeferredVideoProcessingSessionCallback::OnError() is called, errorCode: %{public}d", errorCode);
    bool isCallbackSet = deferredVideoProcSession_ != nullptr && deferredVideoProcSession_->GetCallback() != nullptr;
    if (isCallbackSet) {
        deferredVideoProcSession_->GetCallback()->OnError(videoId, DpsErrorCode(errorCode));
    } else {
        MEDIA_INFO_LOG("DeferredVideoProcessingSessionCallback::OnError not set!, Discarding callback");
    }
    return ERR_OK;
}

int32_t DeferredVideoProcessingSessionCallback::OnStateChanged(DeferredProcessing::StatusCode status)
{
    MEDIA_INFO_LOG("DeferredVideoProcessingSessionCallback::OnStateChanged() is called, status:%{public}d", status);
    bool isCallbackSet = deferredVideoProcSession_ != nullptr && deferredVideoProcSession_->GetCallback() != nullptr;
    if (isCallbackSet) {
        deferredVideoProcSession_->GetCallback()->OnStateChanged(DpsStatusCode(status));
    } else {
        MEDIA_INFO_LOG("DeferredVideoProcessingSessionCallback::OnStateChanged not set!, Discarding callback");
    }
    return ERR_OK;
}

int32_t DeferredVideoProcessingSessionCallback::OnProcessingProgress(const std::string& videoId, float progress)
{
    MEDIA_DEBUG_LOG("DeferredVideoProcessingSessionCallback::OnProcessingProgress() is called, progress:%{public}f",
        progress);
    bool isCallbackSet = deferredVideoProcSession_ != nullptr && deferredVideoProcSession_->GetCallback() != nullptr;
    if (isCallbackSet) {
        deferredVideoProcSession_->GetCallback()->OnProcessingProgress(videoId, progress);
    } else {
        MEDIA_INFO_LOG("DeferredVideoProcessingSessionCallback::OnProcessingProgress not set!, Discarding callback");
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
    CHECK_RETURN(remoteSession_ == nullptr || remoteSession_->AsObject() == nullptr);
    (void)remoteSession_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    remoteSession_ = nullptr;
}

void DeferredVideoProcSession::BeginSynchronize()
{
    CHECK_RETURN_ELOG(remoteSession_ == nullptr, "BeginSynchronize failed due to binder died.");
    MEDIA_INFO_LOG("DeferredVideoProcSession:BeginSynchronize() enter.");
    auto ret = remoteSession_->BeginSynchronize();
    CHECK_PRINT_ELOG(ret != ERR_OK, "EndSynchronize failed errorCode: %{public}d", ret);
}

void DeferredVideoProcSession::EndSynchronize()
{
    CHECK_RETURN_ELOG(remoteSession_ == nullptr, "EndSynchronize failed due to binder died.");
    MEDIA_INFO_LOG("DeferredVideoProcSession::EndSynchronize() enter.");
    auto ret = remoteSession_->EndSynchronize();
    CHECK_PRINT_ELOG(ret != ERR_OK, "EndSynchronize failed errorCode: %{public}d", ret);
}

void DeferredVideoProcSession::AddVideo(const std::string& videoId, const sptr<IPCFileDescriptor> srcFd,
    const sptr<IPCFileDescriptor> dstFd)
{
    CHECK_RETURN_ELOG(remoteSession_ == nullptr, "AddVideo failed due to binder died.");
    MEDIA_INFO_LOG("DeferredVideoProcSession::AddVideo() enter.");
    auto ret = remoteSession_->AddVideo(videoId, srcFd, dstFd);
    CHECK_PRINT_ELOG(ret != ERR_OK, "AddVideo failed errorCode: %{public}d", ret);
}

void DeferredVideoProcSession::RemoveVideo(const std::string& videoId, const bool restorable)
{
    CHECK_RETURN_ELOG(remoteSession_ == nullptr, "RemoveVideo failed due to binder died.");
    MEDIA_INFO_LOG("DeferredVideoProcSession RemoveVideo() enter.");
    auto ret = remoteSession_->RemoveVideo(videoId, restorable);
    CHECK_PRINT_ELOG(ret != ERR_OK, "RemoveVideo failed errorCode: %{public}d", ret);
}

void DeferredVideoProcSession::RestoreVideo(const std::string& videoId)
{
    CHECK_RETURN_ELOG(remoteSession_ == nullptr, "RestoreVideo failed due to binder died.");
    MEDIA_INFO_LOG("DeferredVideoProcSession RestoreVideo() enter.");
    auto ret = remoteSession_->RestoreVideo(videoId);
    CHECK_PRINT_ELOG(ret != ERR_OK, "RestoreVideo failed errorCode: %{public}d", ret);
}

void DeferredVideoProcSession::AddVideo(const std::string& videoId, const std::vector<sptr<IPCFileDescriptor>>& fds)
{
    CHECK_RETURN_ELOG(remoteSession_ == nullptr, "AddMovieVideo failed due to binder died.");
    MEDIA_INFO_LOG("DeferredVideoProcSession AddMovieVideo() enter.");
    auto ret = remoteSession_->AddVideo(videoId, fds);
    CHECK_PRINT_ELOG(ret != ERR_OK, "AddMovieVideo failed errorCode: %{public}d", ret);
}

void DeferredVideoProcSession::ProcessVideo(const std::string& appName, const std::string& videoId)
{
    CHECK_RETURN_ELOG(remoteSession_ == nullptr, "ProcessVideo failed due to binder died.");
    MEDIA_INFO_LOG("DeferredVideoProcSession ProcessVideo() enter.");
    auto ret = remoteSession_->ProcessVideo(appName, videoId);
    CHECK_PRINT_ELOG(ret != ERR_OK, "ProcessVideo failed errorCode: %{public}d", ret);
}

void DeferredVideoProcSession::CancelProcessVideo(const std::string& videoId)
{
    CHECK_RETURN_ELOG(remoteSession_ == nullptr, "CancelProcessVideo failed due to binder died.");
    MEDIA_INFO_LOG("DeferredVideoProcSession CancelProcessVideo() enter.");
    auto ret = remoteSession_->CancelProcessVideo(videoId);
    CHECK_PRINT_ELOG(ret != ERR_OK, "CancelProcessVideo failed errorCode: %{public}d", ret);
}

int32_t DeferredVideoProcSession::SetDeferredVideoSession(
    sptr<DeferredProcessing::IDeferredVideoProcessingSession>& session)
{
    remoteSession_ = session;
    sptr<IRemoteObject> object = remoteSession_->AsObject();
    pid_t pid = 0;
    deathRecipient_ = new(std::nothrow) CameraDeathRecipient(pid);
    CHECK_RETURN_RET_ELOG(deathRecipient_ == nullptr, CAMERA_ALLOC_ERROR, "failed to new CameraDeathRecipient.");

    deathRecipient_->SetNotifyCb(std::bind(&DeferredVideoProcSession::CameraServerDied, this, std::placeholders::_1));
    bool result = object->AddDeathRecipient(deathRecipient_);
    CHECK_RETURN_RET_ELOG(!result, -1, "failed to add deathRecipient");
    return ERR_OK;
}

void DeferredVideoProcSession::CameraServerDied(pid_t pid)
{
    MEDIA_ERR_LOG("camera server has died, pid:%{public}d!", pid);
    if (remoteSession_ != nullptr && remoteSession_->AsObject() != nullptr) {
        (void)remoteSession_->AsObject()->RemoveDeathRecipient(deathRecipient_);
        remoteSession_ = nullptr;
    }
    deathRecipient_ = nullptr;
    ReconnectDeferredProcessingSession();
    CHECK_RETURN(callback_ == nullptr);
    MEDIA_INFO_LOG("Reconnect session successful, send sync requestion.");
    callback_->OnError("", DpsErrorCode::ERROR_SESSION_SYNC_NEEDED);
}

void DeferredVideoProcSession::ReconnectDeferredProcessingSession()
{
    MEDIA_INFO_LOG("DeferredVideoProcSession::ReconnectDeferredProcessingSession, enter.");
    ConnectDeferredProcessingSession();
    CHECK_RETURN(remoteSession_ != nullptr);
    MEDIA_INFO_LOG("Reconnecting deferred processing session failed.");
    ReconnectDeferredProcessingSession();
}

void DeferredVideoProcSession::ConnectDeferredProcessingSession()
{
    MEDIA_INFO_LOG("DeferredVideoProcSession::ConnectDeferredProcessingSession, enter.");
    CHECK_RETURN_ELOG(remoteSession_ != nullptr, "remoteSession_ is not null");
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(samgr == nullptr, "Failed to get System ability manager");
    sptr<IRemoteObject> object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(object == nullptr, "object is null");
    serviceProxy_ = iface_cast<ICameraService>(object);
    CHECK_RETURN_ELOG(serviceProxy_ == nullptr, "serviceProxy_ is null");
    auto deferredVideoProcSession = sptr<DeferredVideoProcSession>::MakeSptr(userId_, callback_);
    CHECK_RETURN(deferredVideoProcSession == nullptr);
    sptr<DeferredProcessing::IDeferredVideoProcessingSessionCallback> remoteCallback = 
        sptr<DeferredVideoProcessingSessionCallback>::MakeSptr(deferredVideoProcSession);
    CHECK_RETURN(remoteCallback == nullptr);
    sptr<DeferredProcessing::IDeferredVideoProcessingSession> session = nullptr;
    serviceProxy_->CreateDeferredVideoProcessingSession(userId_, remoteCallback, session);
    CHECK_EXECUTE(session, SetDeferredVideoSession(session));
}

std::shared_ptr<IDeferredVideoProcSessionCallback> DeferredVideoProcSession::GetCallback()
{
    return callback_;
}

} // namespace CameraStandard
} // namespace OHOS