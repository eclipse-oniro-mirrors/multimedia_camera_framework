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

#ifndef OHOS_CAMERA_DPS_SESSION_MANAGER_H
#define OHOS_CAMERA_DPS_SESSION_MANAGER_H
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <iostream>
#include <refbase.h>
#include "session_info.h"
#include "session_coordinator.h"
#include "ideferred_photo_processing_session.h"
#include "ideferred_photo_processing_session_callback.h"
#include "task_manager.h"
#include "deferred_photo_processor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class SessionManager : public RefBase {
public:
    static std::shared_ptr<SessionManager> Create();
    SessionManager();
    ~SessionManager();
    void Initialize();
    void Start();
    void Stop();
    sptr<IDeferredPhotoProcessingSession> CreateDeferredPhotoProcessingSession(int userId,
        const sptr<IDeferredPhotoProcessingSessionCallback> callback,
        std::shared_ptr<DeferredPhotoProcessor> processor, TaskManager* taskManager);
    std::shared_ptr<IImageProcessCallbacks> GetImageProcCallbacks();
    sptr<IDeferredPhotoProcessingSession> GetDeferredPhotoProcessingSession();
    void OnCallbackDied(int userId);

private:
    std::mutex mutex_;
    std::atomic<bool> initialized_;
    std::unordered_map<int, sptr<SessionInfo>> photoSessionInfos_;
    std::unique_ptr<SessionCoordinator> coordinator_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_SESSION_MANAGER_H