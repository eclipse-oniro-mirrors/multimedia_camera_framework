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

#ifndef OHOS_CAMERA_DPS_SESSION_MANAGER_H
#define OHOS_CAMERA_DPS_SESSION_MANAGER_H

#include "enable_shared_create.h"
#include "photo_session_info.h"
#include "session_coordinator.h"
#include "video_session_info.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class SessionManager : public EnableSharedCreateInit<SessionManager> {
public:
    ~SessionManager();
    
    int32_t Initialize() override;
    void Start();
    void Stop();
    sptr<IDeferredPhotoProcessingSession> CreateDeferredPhotoProcessingSession(const int32_t userId,
        const sptr<IDeferredPhotoProcessingSessionCallback>& callback);
    sptr<PhotoSessionInfo> GetPhotoInfo(const int32_t userId);
    void AddPhotoSession(const sptr<PhotoSessionInfo>& sessionInfo);
    void DeletePhotoSession(const int32_t userId);

    sptr<IDeferredPhotoProcessingSessionCallback> GetCallback(const int32_t userId);
    sptr<IDeferredVideoProcessingSession> CreateDeferredVideoProcessingSession(const int32_t userId,
        const sptr<IDeferredVideoProcessingSessionCallback>& callback);
    sptr<VideoSessionInfo> GetVideoInfo(const int32_t userId);
    std::shared_ptr<SessionCoordinator> GetSessionCoordinator();

protected:
    SessionManager();

private:
    std::mutex photoSessionMutex_;
    std::mutex videoSessionMutex_;
    std::atomic<bool> initialized_ {false};
    std::unordered_map<int32_t, sptr<PhotoSessionInfo>> photoSessionInfos_ {};
    std::unordered_map<int32_t, sptr<VideoSessionInfo>> videoSessionInfos_ {};
    std::shared_ptr<SessionCoordinator> coordinator_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_SESSION_MANAGER_H