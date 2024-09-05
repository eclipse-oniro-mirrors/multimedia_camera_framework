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

#include <sys/mman.h>
#include "deferred_proc_session/deferred_photo_proc_session.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "camera_log.h"
#include "camera_util.h"
#include "system_ability_definition.h"
#include "camera_error_code.h"
#include "picture.h"

namespace OHOS {
namespace CameraStandard {

int32_t DeferredPhotoProcessingSessionCallback::OnProcessImageDone(const std::string &imageId,
    const sptr<IPCFileDescriptor> ipcFileDescriptor, const long bytes)
{
    MEDIA_INFO_LOG("DeferredPhotoProcessingSessionCallback::OnProcessImageDone() is called!");
    if (ipcFileDescriptor == nullptr) {
        return CAMERA_INVALID_ARG;
    }
    int fd = ipcFileDescriptor->GetFd();
    void* addr = mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (deferredPhotoProcSession_ != nullptr && deferredPhotoProcSession_->GetCallback() != nullptr) {
        if (addr == MAP_FAILED) {
            MEDIA_ERR_LOG("DeferredPhotoProcessingSessionCallback::OnProcessImageDone() mmap failed");
            deferredPhotoProcSession_->GetCallback()->OnError(imageId, ERROR_IMAGE_PROC_FAILED);
            return 0;
        } else {
            deferredPhotoProcSession_->GetCallback()->OnProcessImageDone(imageId, static_cast<uint8_t*>(addr), bytes);
        }
    } else {
        MEDIA_INFO_LOG("DeferredPhotoProcessingSessionCallback::OnProcessImageDone not set!, Discarding callback");
    }
    munmap(addr, bytes);
    return 0;
}

int32_t DeferredPhotoProcessingSessionCallback::OnError(const std::string &imageId,
    const DeferredProcessing::ErrorCode errorCode)
{
    MEDIA_INFO_LOG("DeferredPhotoProcessingSessionCallback::OnError() is called, errorCode: %{public}d", errorCode);
    if (deferredPhotoProcSession_ != nullptr && deferredPhotoProcSession_->GetCallback() != nullptr) {
        deferredPhotoProcSession_->GetCallback()->OnError(imageId, DpsErrorCode(errorCode));
    } else {
        MEDIA_INFO_LOG("DeferredPhotoProcessingSessionCallback::OnError not set!, Discarding callback");
    }
    return 0;
}

int32_t DeferredPhotoProcessingSessionCallback::OnStateChanged(const DeferredProcessing::StatusCode status)
{
    MEDIA_INFO_LOG("DeferredPhotoProcessingSessionCallback::OnStateChanged() is called, status:%{public}d", status);
    if (deferredPhotoProcSession_ != nullptr && deferredPhotoProcSession_->GetCallback() != nullptr) {
        deferredPhotoProcSession_->GetCallback()->OnStateChanged(DpsStatusCode(status));
    } else {
        MEDIA_INFO_LOG("DeferredPhotoProcessingSessionCallback::OnStateChanged not set!, Discarding callback");
    }
    return 0;
}

int32_t DeferredPhotoProcessingSessionCallback::OnProcessImageDone(const std::string &imageId,
    std::shared_ptr<Media::Picture> picture)
{
    MEDIA_INFO_LOG("DeferredPhotoProcessingSessionCallback::OnProcessImageDone() is"
        "called, status:%{public}s", imageId.c_str());
    if (picture != nullptr) {
        MEDIA_INFO_LOG("picture is not null");
    }
    if (deferredPhotoProcSession_ != nullptr && deferredPhotoProcSession_->GetCallback() != nullptr) {
        deferredPhotoProcSession_->GetCallback()->OnProcessImageDone(imageId, picture);
    } else {
        MEDIA_INFO_LOG("DeferredPhotoProcessingSessionCallback::OnProcessImageDone not set!, Discarding callback");
    }
    return 0;
}

int32_t DeferredPhotoProcessingSessionCallback::OnDeliveryLowQualityImage(const std::string &imageId,
    std::shared_ptr<Media::Picture> picture)
{
    MEDIA_INFO_LOG("DeferredPhotoProcessingSessionCallback::OnDeliveryLowQualityImage() is"
        "called, status:%{public}s", imageId.c_str());
    if (picture != nullptr) {
        MEDIA_INFO_LOG("picture is not null");
        deferredPhotoProcSession_->GetCallback()->OnDeliveryLowQualityImage(imageId, picture);
    }
    return 0;
}

DeferredPhotoProcSession::DeferredPhotoProcSession(int userId,
    std::shared_ptr<IDeferredPhotoProcSessionCallback> callback)
{
    MEDIA_INFO_LOG("enter.");
    userId_ = userId;
    callback_ = callback;
}

DeferredPhotoProcSession::~DeferredPhotoProcSession()
{
    MEDIA_INFO_LOG("DeferredPhotoProcSession::DeferredPhotoProcSession Destructor!");
    if (remoteSession_ != nullptr) {
        (void)remoteSession_->AsObject()->RemoveDeathRecipient(deathRecipient_);
        remoteSession_ = nullptr;
    }
}

void DeferredPhotoProcSession::BeginSynchronize()
{
    if (remoteSession_ == nullptr) {
        MEDIA_ERR_LOG("DeferredPhotoProcSession::BeginSynchronize failed due to binder died.");
    } else {
        MEDIA_INFO_LOG("DeferredPhotoProcSession:BeginSynchronize() enter.");
        remoteSession_->BeginSynchronize();
    }
    return;
}

void DeferredPhotoProcSession::EndSynchronize()
{
    if (remoteSession_ == nullptr) {
        MEDIA_ERR_LOG("DeferredPhotoProcSession::EndSynchronize failed due to binder died.");
    } else {
        MEDIA_INFO_LOG("DeferredPhotoProcSession::EndSynchronize() enter.");
        remoteSession_->EndSynchronize();
    }
    return;
}

void DeferredPhotoProcSession::AddImage(const std::string& imageId, DpsMetadata& metadata, const bool discardable)
{
    if (remoteSession_ == nullptr) {
        MEDIA_ERR_LOG("DeferredPhotoProcSession::AddImage failed due to binder died.");
    } else {
        MEDIA_INFO_LOG("DeferredPhotoProcSession::AddImage() enter.");
        remoteSession_->AddImage(imageId, metadata, discardable);
    }
    return;
}

void DeferredPhotoProcSession::RemoveImage(const std::string& imageId, const bool restorable)
{
    if (remoteSession_ == nullptr) {
        MEDIA_ERR_LOG("DeferredPhotoProcSession::RemoveImage failed due to binder died.");
    } else {
        MEDIA_INFO_LOG("DeferredPhotoProcSession RemoveImage() enter.");
        remoteSession_->RemoveImage(imageId, restorable);
    }
    return;
}

void DeferredPhotoProcSession::RestoreImage(const std::string& imageId)
{
    if (remoteSession_ == nullptr) {
        MEDIA_ERR_LOG("DeferredPhotoProcSession::RestoreImage failed due to binder died.");
    } else {
        MEDIA_INFO_LOG("DeferredPhotoProcSession RestoreImage() enter.");
        remoteSession_->RestoreImage(imageId);
    }
    return;
}

void DeferredPhotoProcSession::ProcessImage(const std::string& appName, const std::string& imageId)
{
    if (remoteSession_ == nullptr) {
        MEDIA_ERR_LOG("DeferredPhotoProcSession::ProcessImage failed due to binder died.");
    } else {
        MEDIA_INFO_LOG("DeferredPhotoProcSession::ProcessImage() enter.");
        remoteSession_->ProcessImage(appName, imageId);
    }
    return;
}

bool DeferredPhotoProcSession::CancelProcessImage(const std::string& imageId)
{
    if (remoteSession_ == nullptr) {
        MEDIA_ERR_LOG("DeferredPhotoProcSession::CancelProcessImage failed due to binder died.");
        return false;
    }
    MEDIA_INFO_LOG("DeferredPhotoProcSession:CancelProcessImage() enter.");
    remoteSession_->CancelProcessImage(imageId);
    return true;
}

int32_t DeferredPhotoProcSession::SetDeferredPhotoSession(
    sptr<DeferredProcessing::IDeferredPhotoProcessingSession>& session)
{
    remoteSession_ = session;
    sptr<IRemoteObject> object = remoteSession_->AsObject();
    pid_t pid = 0;
    deathRecipient_ = new(std::nothrow) CameraDeathRecipient(pid);
    CHECK_ERROR_RETURN_RET_LOG(deathRecipient_ == nullptr, CAMERA_ALLOC_ERROR, "failed to new CameraDeathRecipient.");

    deathRecipient_->SetNotifyCb([this](pid_t pid) { CameraServerDied(pid); });
    bool result = object->AddDeathRecipient(deathRecipient_);
    if (!result) {
        MEDIA_ERR_LOG("failed to add deathRecipient");
        return -1;  // return error
    }
    return 0;
}

void DeferredPhotoProcSession::CameraServerDied(pid_t pid)
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
    return;
}

void DeferredPhotoProcSession::ReconnectDeferredProcessingSession()
{
    MEDIA_INFO_LOG("DeferredPhotoProcSession::ReconnectDeferredProcessingSession, enter.");
    ConnectDeferredProcessingSession();
    if (remoteSession_ == nullptr) {
        MEDIA_INFO_LOG("Reconnecting deferred processing session failed.");
        ReconnectDeferredProcessingSession();
    }
    return;
}

void DeferredPhotoProcSession::ConnectDeferredProcessingSession()
{
    MEDIA_INFO_LOG("DeferredPhotoProcSession::ConnectDeferredProcessingSession, enter.");
    CHECK_ERROR_RETURN_LOG(remoteSession_ != nullptr, "remoteSession_ is not null");
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_ERROR_RETURN_LOG(samgr == nullptr, "Failed to get System ability manager");
    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_ERROR_RETURN_LOG(object == nullptr, "object is null");
    serviceProxy_ = iface_cast<ICameraService>(object);
    CHECK_ERROR_RETURN_LOG(serviceProxy_ == nullptr, "serviceProxy_ is null");
    sptr<DeferredProcessing::IDeferredPhotoProcessingSession> session = nullptr;
    sptr<DeferredProcessing::IDeferredPhotoProcessingSessionCallback> remoteCallback = nullptr;
    sptr<DeferredPhotoProcSession> deferredPhotoProcSession = nullptr;
    deferredPhotoProcSession = new(std::nothrow) DeferredPhotoProcSession(userId_, callback_);
    CHECK_ERROR_RETURN(deferredPhotoProcSession == nullptr);
    remoteCallback = new(std::nothrow) DeferredPhotoProcessingSessionCallback(deferredPhotoProcSession);
    CHECK_ERROR_RETURN(remoteCallback == nullptr);
    serviceProxy_->CreateDeferredPhotoProcessingSession(userId_, remoteCallback, session);
    if (session) {
        SetDeferredPhotoSession(session);
    }
    return;
}

std::shared_ptr<IDeferredPhotoProcSessionCallback> DeferredPhotoProcSession::GetCallback()
{
    return callback_;
}

} // namespace CameraStandard
} // namespace OHOS