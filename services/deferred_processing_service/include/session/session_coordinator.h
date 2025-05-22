/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_DPS_SESSION_COORDINATOR_H
#define OHOS_CAMERA_DPS_SESSION_COORDINATOR_H

#include <cstdint>

#include "enable_shared_create.h"
#include "ideferred_photo_processing_session_callback.h"
#include "ideferred_video_processing_session_callback.h"
#include "ipc_file_descriptor.h"
#include "ivideo_process_callbacks.h"
#include "photo_session_info.h"
#include "task_manager.h"
#include "video_session_info.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class SessionCoordinator : public EnableSharedCreateInit<SessionCoordinator> {
public:
    ~SessionCoordinator();

    int32_t Initialize() override;
    void Start();
    void Stop();
    void OnStateChanged(const int32_t userId, DpsStatus statusCode);

    void AddVideoSession(const sptr<VideoSessionInfo>& sessionInfo);
    void DeleteVideoSession(const int32_t userId);
    void OnVideoProcessDone(const int32_t userId, const std::string& videoId, const sptr<IPCFileDescriptor>& ipcFd);
    void OnVideoError(const int32_t userId, const std::string& videoId, DpsError errorCode);
    void OnVideoStateChanged(const int32_t userId, DpsStatus statusCode);
    std::shared_ptr<IVideoProcessCallbacks> GetVideoProcCallbacks();

    inline sptr<PhotoSessionInfo> GetPhotoSessionInfo(int32_t userId)
    {
        auto iter = photoInfos_.find(userId);
        if (iter != photoInfos_.end()) {
            return iter->second;
        }
        return nullptr;
    }

    inline sptr<IDeferredVideoProcessingSessionCallback> GetRemoteVideoCallback(int32_t userId)
    {
        auto iter = videoCallbackMap_.find(userId);
        if (iter != videoCallbackMap_.end()) {
            return iter->second.promote();
        }
        return nullptr;
    }

protected:
    SessionCoordinator();

private:
    class VideoProcCallbacks;

    enum struct CallbackType {
        ON_PROCESS_DONE,
        ON_ERROR,
        ON_STATE_CHANGED
    };

    struct RequestResult {
        CallbackType callbackType;
        const int32_t userId;
        const std::string requestId;
        sptr<IPCFileDescriptor> ipcFd;
        long dataSize;
        DpsError errorCode;
        DpsStatus statusCode;
    };

    void ProcessVideoResults(sptr<IDeferredVideoProcessingSessionCallback> callback);

    std::unordered_map<int32_t, sptr<PhotoSessionInfo>> photoInfos_ {};
    std::shared_ptr<IVideoProcessCallbacks> videoProcCallbacks_ {nullptr};
    std::unordered_map<int32_t, wptr<IDeferredVideoProcessingSessionCallback>> videoCallbackMap_ {};
    std::deque<RequestResult> pendingRequestResults_ {};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_SESSION_COORDINATOR_H