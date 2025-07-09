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
#include "picture_proxy.h"
#include "iservice_registry.h"
#include "camera_log.h"
#include "camera_util.h"
#include "system_ability_definition.h"
#include "picture_interface.h"

namespace OHOS {
namespace CameraStandard {

int32_t DeferredPhotoProcessingSessionCallback::OnProcessImageDone(const std::string &imageId,
    const sptr<IPCFileDescriptor>& ipcFileDescriptor, int64_t bytes, uint32_t cloudImageEnhanceFlag)
{
    MEDIA_INFO_LOG("DeferredPhotoProcessingSessionCallback::OnProcessImageDone() is called!"
        "cloudImageEnhanceFlag: %{public}u", cloudImageEnhanceFlag);
    CHECK_RETURN_RET(ipcFileDescriptor == nullptr, CAMERA_INVALID_ARG);
    int fd = ipcFileDescriptor->GetFd();
    void* addr = mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (deferredPhotoProcSession_ != nullptr && deferredPhotoProcSession_->GetCallback() != nullptr) {
        if (addr == MAP_FAILED) {
            MEDIA_ERR_LOG("DeferredPhotoProcessingSessionCallback::OnProcessImageDone() mmap failed");
            deferredPhotoProcSession_->GetCallback()->OnError(imageId, DpsErrorCode::ERROR_IMAGE_PROC_FAILED);
            return 0;
        } else {
            deferredPhotoProcSession_->GetCallback()->OnProcessImageDone(imageId, static_cast<uint8_t*>(addr), bytes,
                cloudImageEnhanceFlag);
        }
    } else {
        MEDIA_INFO_LOG("DeferredPhotoProcessingSessionCallback::OnProcessImageDone not set!, Discarding callback");
    }
    munmap(addr, bytes);
    return 0;
}

int32_t DeferredPhotoProcessingSessionCallback::OnError(const std::string &imageId,
    DeferredProcessing::ErrorCode errorCode)
{
    MEDIA_INFO_LOG("DeferredPhotoProcessingSessionCallback::OnError() is called, errorCode: %{public}d", errorCode);
    if (deferredPhotoProcSession_ != nullptr && deferredPhotoProcSession_->GetCallback() != nullptr) {
        deferredPhotoProcSession_->GetCallback()->OnError(imageId, DpsErrorCode(errorCode));
    } else {
        MEDIA_INFO_LOG("DeferredPhotoProcessingSessionCallback::OnError not set!, Discarding callback");
    }
    return 0;
}

int32_t DeferredPhotoProcessingSessionCallback::OnStateChanged(DeferredProcessing::StatusCode status)
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
    const std::shared_ptr<PictureIntf>& pictureIntf, uint32_t cloudImageEnhanceFlag)
{
    MEDIA_INFO_LOG("DeferredPhotoProcessingSessionCallback::OnProcessImageDone() is"
        "called, status:%{public}s, cloudImageEnhanceFlag: %{public}u", imageId.c_str(), cloudImageEnhanceFlag);
    if (pictureIntf != nullptr) {
        MEDIA_INFO_LOG("picture is not null");
    }
    if (deferredPhotoProcSession_ != nullptr && deferredPhotoProcSession_->GetCallback() != nullptr) {
        deferredPhotoProcSession_->GetCallback()->OnProcessImageDone(imageId, pictureIntf, cloudImageEnhanceFlag);
    } else {
        MEDIA_INFO_LOG("DeferredPhotoProcessingSessionCallback::OnProcessImageDone not set!, Discarding callback");
    }
    return 0;
}

int32_t DeferredPhotoProcessingSessionCallback::OnDeliveryLowQualityImage(const std::string &imageId,
    const std::shared_ptr<PictureIntf>& pictureIntf)
{
    MEDIA_INFO_LOG("DeferredPhotoProcessingSessionCallback::OnDeliveryLowQualityImage() is"
        "called, status:%{public}s", imageId.c_str());
    auto callback = deferredPhotoProcSession_->GetCallback();
    if (pictureIntf != nullptr && callback != nullptr) {
        MEDIA_INFO_LOG("pictureIntf is not null");
        callback->OnDeliveryLowQualityImage(imageId, pictureIntf);
    }
    return 0;
}

int32_t DeferredPhotoProcessingSessionCallback::CallbackParcel([[maybe_unused]] uint32_t code,
    [[maybe_unused]] MessageParcel& data, [[maybe_unused]] MessageParcel& reply, [[maybe_unused]] MessageOption& option)
{
    MEDIA_DEBUG_LOG("start, code:%{public}u", code);
    if ((static_cast<DeferredProcessing::IDeferredPhotoProcessingSessionCallbackIpcCode>(code)
        != DeferredProcessing::IDeferredPhotoProcessingSessionCallbackIpcCode::COMMAND_ON_DELIVERY_LOW_QUALITY_IMAGE)
        && (static_cast<DeferredProcessing::IDeferredPhotoProcessingSessionCallbackIpcCode>(code)
        != DeferredProcessing::IDeferredPhotoProcessingSessionCallbackIpcCode::
        COMMAND_ON_PROCESS_IMAGE_DONE_IN_STRING_IN_SHARED_PTR_PICTUREINTF_IN_UNSIGNED_INT)) {
        return ERR_NONE;
    }
    CHECK_RETURN_RET(data.ReadInterfaceToken() != GetDescriptor(), ERR_TRANSACTION_FAILED);

    switch (static_cast<DeferredProcessing::IDeferredPhotoProcessingSessionCallbackIpcCode>(code)) {
        case DeferredProcessing::IDeferredPhotoProcessingSessionCallbackIpcCode::
            COMMAND_ON_DELIVERY_LOW_QUALITY_IMAGE: {
            MEDIA_INFO_LOG("HandleProcessLowQualityImage enter");
            std::string imageId = Str16ToStr8(data.ReadString16());
            int32_t size = data.ReadInt32();
            CHECK_RETURN_RET_ELOG(size == 0, ERR_INVALID_DATA, "Not an parcelable oject");
            std::shared_ptr<PictureProxy> picturePtr = PictureProxy::CreatePictureProxy();
            CHECK_RETURN_RET_ELOG(picturePtr == nullptr, ERR_INVALID_DATA, "picturePtr is nullptr");
            MEDIA_DEBUG_LOG("HandleProcessLowQualityImage Picture::Unmarshalling E");
            picturePtr->UnmarshallingPicture(data);
            MEDIA_DEBUG_LOG("HandleProcessLowQualityImage Picture::Unmarshalling X");
            ErrCode errCode = OnDeliveryLowQualityImage(imageId, picturePtr->GetPictureIntf());
            MEDIA_INFO_LOG("HandleProcessLowQualityImage result: %{public}d", errCode);
            CHECK_RETURN_RET_ELOG(!reply.WriteInt32(errCode), ERR_INVALID_VALUE,
                "OnDeliveryLowQualityImage faild");
            break;
        }
        case DeferredProcessing::IDeferredPhotoProcessingSessionCallbackIpcCode::
            COMMAND_ON_PROCESS_IMAGE_DONE_IN_STRING_IN_SHARED_PTR_PICTUREINTF_IN_UNSIGNED_INT: {
            MEDIA_INFO_LOG("HandleOnProcessPictureDone enter");
            std::string imageId = Str16ToStr8(data.ReadString16());
            int32_t size = data.ReadInt32();
            CHECK_RETURN_RET_ELOG(size == 0, ERR_INVALID_DATA, "Not an parcelable oject");
            std::shared_ptr<PictureProxy> picturePtr = PictureProxy::CreatePictureProxy();
            CHECK_RETURN_RET_ELOG(picturePtr == nullptr, IPC_STUB_INVALID_DATA_ERR, "picturePtr is nullptr");
            MEDIA_DEBUG_LOG("HandleOnProcessPictureDone Picture::Unmarshalling E");
            picturePtr->UnmarshallingPicture(data);
            MEDIA_DEBUG_LOG("HandleOnProcessPictureDone Picture::Unmarshalling X");
            uint32_t cloudImageEnhanceFlag = data.ReadUint32();
            ErrCode errCode = OnProcessImageDone(imageId, picturePtr->GetPictureIntf(), cloudImageEnhanceFlag);
            MEDIA_INFO_LOG("HandleOnProcessPictureDone result: %{public}d, cloudImageEnhanceFlag: %{public}u",
                errCode, cloudImageEnhanceFlag);
            CHECK_RETURN_RET_ELOG(!reply.WriteInt32(errCode), ERR_INVALID_VALUE, "OnProcessImageDone faild");
            break;
        }
        default:
            break;
    }
    return -1;
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
    CHECK_RETURN(remoteSession_ == nullptr);
    (void)remoteSession_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    remoteSession_ = nullptr;
}

void DeferredPhotoProcSession::BeginSynchronize()
{
    CHECK_RETURN_ELOG(
        remoteSession_ == nullptr, "DeferredPhotoProcSession::BeginSynchronize failed due to binder died.");

    MEDIA_INFO_LOG("DeferredPhotoProcSession:BeginSynchronize() enter.");
    remoteSession_->BeginSynchronize();
}

void DeferredPhotoProcSession::EndSynchronize()
{
    CHECK_RETURN_ELOG(
        remoteSession_ == nullptr, "DeferredPhotoProcSession::EndSynchronize failed due to binder died.");
    MEDIA_INFO_LOG("DeferredPhotoProcSession::EndSynchronize() enter.");
    remoteSession_->EndSynchronize();
}

void DeferredPhotoProcSession::AddImage(const std::string& imageId, DpsMetadata& metadata, const bool discardable)
{
    CHECK_RETURN_ELOG(remoteSession_ == nullptr, "DeferredPhotoProcSession::AddImage failed due to binder died.");
    MEDIA_INFO_LOG("DeferredPhotoProcSession::AddImage() enter.");
    remoteSession_->AddImage(imageId, metadata, discardable);
}

void DeferredPhotoProcSession::RemoveImage(const std::string& imageId, const bool restorable)
{
    CHECK_RETURN_ELOG(
        remoteSession_ == nullptr, "DeferredPhotoProcSession::RemoveImage failed due to binder died.");
    MEDIA_INFO_LOG("DeferredPhotoProcSession RemoveImage() enter.");
    remoteSession_->RemoveImage(imageId, restorable);
}

void DeferredPhotoProcSession::RestoreImage(const std::string& imageId)
{
    CHECK_RETURN_ELOG(
        remoteSession_ == nullptr, "DeferredPhotoProcSession::RestoreImage failed due to binder died.");
    MEDIA_INFO_LOG("DeferredPhotoProcSession RestoreImage() enter.");
    remoteSession_->RestoreImage(imageId);
}

void DeferredPhotoProcSession::ProcessImage(const std::string& appName, const std::string& imageId)
{
    CHECK_RETURN_ELOG(
        remoteSession_ == nullptr, "DeferredPhotoProcSession::ProcessImage failed due to binder died.");
    MEDIA_INFO_LOG("DeferredPhotoProcSession::ProcessImage() enter.");
    remoteSession_->ProcessImage(appName, imageId);
}

bool DeferredPhotoProcSession::CancelProcessImage(const std::string& imageId)
{
    CHECK_RETURN_RET_ELOG(
        remoteSession_ == nullptr, false, "DeferredPhotoProcSession::CancelProcessImage failed due to binder died.");
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
    CHECK_RETURN_RET_ELOG(deathRecipient_ == nullptr, CAMERA_ALLOC_ERROR, "failed to new CameraDeathRecipient.");

    deathRecipient_->SetNotifyCb([this](pid_t pid) { CameraServerDied(pid); });
    bool result = object->AddDeathRecipient(deathRecipient_);
    CHECK_RETURN_RET_ELOG(!result, -1, "failed to add deathRecipient");
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
        MEDIA_INFO_LOG("DeferredPhotoProcSession Reconnect session successful, send sync requestion.");
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
    CHECK_RETURN_ELOG(remoteSession_ != nullptr, "remoteSession_ is not null");
    sptr<IRemoteObject> object = nullptr;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_ELOG(samgr == nullptr, "Failed to get System ability manager");
    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_ELOG(object == nullptr, "object is null");
    serviceProxy_ = iface_cast<ICameraService>(object);
    CHECK_RETURN_ELOG(serviceProxy_ == nullptr, "serviceProxy_ is null");
    sptr<DeferredProcessing::IDeferredPhotoProcessingSession> session = nullptr;
    sptr<DeferredProcessing::IDeferredPhotoProcessingSessionCallback> remoteCallback = nullptr;
    sptr<DeferredPhotoProcSession> deferredPhotoProcSession = nullptr;
    deferredPhotoProcSession = new(std::nothrow) DeferredPhotoProcSession(userId_, callback_);
    CHECK_RETURN(deferredPhotoProcSession == nullptr);
    remoteCallback = new(std::nothrow) DeferredPhotoProcessingSessionCallback(deferredPhotoProcSession);
    CHECK_RETURN(remoteCallback == nullptr);
    serviceProxy_->CreateDeferredPhotoProcessingSession(userId_, remoteCallback, session);
    CHECK_EXECUTE(session, SetDeferredPhotoSession(session));
    return;
}

std::shared_ptr<IDeferredPhotoProcSessionCallback> DeferredPhotoProcSession::GetCallback()
{
    return callback_;
}

} // namespace CameraStandard
} // namespace OHOS