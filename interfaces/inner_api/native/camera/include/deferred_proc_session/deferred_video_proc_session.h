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

#ifndef OHOS_CAMERA_DEFERRED_VIDEO_PROCESSOR_H
#define OHOS_CAMERA_DEFERRED_VIDEO_PROCESSOR_H

#include <refbase.h>
#include <iostream>
#include <mutex>

#include "camera_death_recipient.h"
#include "ideferred_video_processing_session.h"
#include "ideferred_video_processing_session_callback.h"
#include "deferred_video_processing_session_callback_stub.h"
#include "hcamera_service_proxy.h"
#include "ipc_file_descriptor.h"
#include "deferred_type.h"

namespace OHOS {
namespace CameraStandard {
class IDeferredVideoProcSessionCallback : public RefBase {
public:
    IDeferredVideoProcSessionCallback() = default;
    virtual ~IDeferredVideoProcSessionCallback() = default;
    virtual void OnProcessVideoDone(const std::string& videoId, const sptr<IPCFileDescriptor> ipcFd) = 0;
    virtual void OnError(const std::string& videoId, const DpsErrorCode errorCode) = 0;
    virtual void OnStateChanged(const DpsStatusCode status) = 0;
};

class DeferredVideoProcSession : public RefBase {
public:
    DeferredVideoProcSession(int userId, std::shared_ptr<IDeferredVideoProcSessionCallback> callback);
    virtual ~DeferredVideoProcSession();
    void BeginSynchronize();
    void EndSynchronize();
    void AddVideo(const std::string& videoId, const sptr<IPCFileDescriptor> srcFd,
        const sptr<IPCFileDescriptor> dstFd);
    void RemoveVideo(const std::string& videoId, const bool restorable = false);
    void RestoreVideo(const std::string& videoId);
    std::shared_ptr<IDeferredVideoProcSessionCallback> GetCallback();
private:
    friend class CameraManager;
    int32_t SetDeferredVideoSession(sptr<DeferredProcessing::IDeferredVideoProcessingSession>& session);
    void CameraServerDied(pid_t pid);
    void ReconnectDeferredProcessingSession();
    void ConnectDeferredProcessingSession();
    int userId_;
    std::shared_ptr<IDeferredVideoProcSessionCallback> callback_;
    sptr<DeferredProcessing::IDeferredVideoProcessingSession> remoteSession_;
    sptr<CameraDeathRecipient> deathRecipient_ = nullptr;
    sptr<ICameraService> serviceProxy_;
};

class DeferredVideoProcessingSessionCallback : public DeferredProcessing::DeferredVideoProcessingSessionCallbackStub {
public:
    DeferredVideoProcessingSessionCallback() : deferredVideoProcSession_(nullptr) {
    }

    explicit DeferredVideoProcessingSessionCallback(sptr<DeferredVideoProcSession> deferredVideoProcSession)
        : deferredVideoProcSession_(deferredVideoProcSession)
    {
    }

    ~DeferredVideoProcessingSessionCallback()
    {
        deferredVideoProcSession_ = nullptr;
    }

    ErrCode OnProcessVideoDone(const std::string& videoId, const sptr<IPCFileDescriptor>& ipcFileDescriptor) override;
    ErrCode OnError(const std::string& videoId, int32_t errorCode) override;
    ErrCode OnStateChanged(int32_t status) override;

private:
    sptr<DeferredVideoProcSession> deferredVideoProcSession_;
};

} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DEFERRED_VIDEO_PROCESSOR_H