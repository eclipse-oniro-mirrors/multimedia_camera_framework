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

#ifndef OHOS_CAMERA_DEFERRED_PHOTO_PROCESSOR_H
#define OHOS_CAMERA_DEFERRED_PHOTO_PROCESSOR_H

#include <refbase.h>
#include <iostream>
#include <mutex>
#include "camera_death_recipient.h"
#include "ideferred_photo_processing_session.h"
#include "ideferred_photo_processing_session_callback.h"
#include "deferred_photo_processing_session_callback_stub.h"
#include "dps_metadata_info.h"
#include "camera_service_proxy.h"
#include "deferred_type.h"
#include "deferred_processing_types.h"

namespace OHOS {
namespace CameraStandard {
class IDeferredPhotoProcSessionCallback : public RefBase {
public:
    IDeferredPhotoProcSessionCallback() = default;
    virtual ~IDeferredPhotoProcSessionCallback() = default;
    virtual void OnProcessImageDone(const std::string& imageId, const uint8_t* addr, const long bytes,
        uint32_t cloudImageEnhanceFlag) = 0;
    virtual void OnProcessImageDone(const std::string &imageId, std::shared_ptr<PictureIntf> picture,
        uint32_t cloudImageEnhanceFlag) = 0;
    virtual void OnDeliveryLowQualityImage(const std::string &imageId, std::shared_ptr<PictureIntf> picture) = 0;
    virtual void OnError(const std::string& imageId, const DpsErrorCode errorCode) = 0;
    virtual void OnStateChanged(const DpsStatusCode status) = 0;
    int32_t CallbackParcel(
        [[maybe_unused]] uint32_t code,
        [[maybe_unused]] MessageParcel& data,
        [[maybe_unused]] MessageParcel& reply,
        [[maybe_unused]] MessageOption& option);
};

class DeferredPhotoProcSession : public RefBase {
public:
    DeferredPhotoProcSession(int userId, std::shared_ptr<IDeferredPhotoProcSessionCallback> callback);
    virtual ~DeferredPhotoProcSession();
    void BeginSynchronize();
    void EndSynchronize();
    void AddImage(const std::string& imageId, DpsMetadata& metadata, const bool discardable = false);
    void RemoveImage(const std::string& imageId, const bool restorable = true);
    void RestoreImage(const std::string& imageId);
    void ProcessImage(const std::string& appName, const std::string& imageId);
    bool CancelProcessImage(const std::string& imageId);
    std::shared_ptr<IDeferredPhotoProcSessionCallback> GetCallback();
private:
    friend class CameraManager;
    int32_t SetDeferredPhotoSession(sptr<DeferredProcessing::IDeferredPhotoProcessingSession>& session);
    void CameraServerDied(pid_t pid);
    void ReconnectDeferredProcessingSession();
    void ConnectDeferredProcessingSession();
    int userId_;
    std::shared_ptr<IDeferredPhotoProcSessionCallback> callback_;
    sptr<DeferredProcessing::IDeferredPhotoProcessingSession> remoteSession_;
    sptr<CameraDeathRecipient> deathRecipient_ = nullptr;
    sptr<ICameraService> serviceProxy_;
};

class DeferredPhotoProcessingSessionCallback : public DeferredProcessing::DeferredPhotoProcessingSessionCallbackStub {
public:
    DeferredPhotoProcessingSessionCallback() : deferredPhotoProcSession_(nullptr) {
    }

    explicit DeferredPhotoProcessingSessionCallback(sptr<DeferredPhotoProcSession> deferredPhotoProcSession)
        : deferredPhotoProcSession_(deferredPhotoProcSession)
    {
    }

    ~DeferredPhotoProcessingSessionCallback()
    {
        deferredPhotoProcSession_ = nullptr;
    }

    int32_t OnProcessImageDone(const std::string &imageId, const sptr<IPCFileDescriptor>& ipcFileDescriptor,
        int64_t bytes, uint32_t cloudImageEnhanceFlag) override;
    int32_t OnProcessImageDone(const std::string &imageId, const std::shared_ptr<PictureIntf>& picture,
        uint32_t cloudImageEnhanceFlag) override;
    int32_t OnDeliveryLowQualityImage(const std::string &imageId, const std::shared_ptr<PictureIntf>& picture) override;
    int32_t OnError(const std::string &imageId, DeferredProcessing::ErrorCode errorCode) override;
    int32_t OnStateChanged(DeferredProcessing::StatusCode status) override;
    int32_t CallbackParcel(
        [[maybe_unused]] uint32_t code,
        [[maybe_unused]] MessageParcel& data,
        [[maybe_unused]] MessageParcel& reply,
        [[maybe_unused]] MessageOption& option) override;

private:
    sptr<DeferredPhotoProcSession> deferredPhotoProcSession_;
};

} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DEFERRED_PHOTO_PROCESSOR_H