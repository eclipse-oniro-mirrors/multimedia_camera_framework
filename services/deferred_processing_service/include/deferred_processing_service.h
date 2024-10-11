/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
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

#ifndef OHOS_CAMERA_DPS_DEFERRED_PROCESSING_SERVICE_H
#define OHOS_CAMERA_DPS_DEFERRED_PROCESSING_SERVICE_H
#define EXPORT_API __attribute__((visibility("default")))

#include "session_manager.h"
#include "scheduler_manager.h"
#include "task_manager.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredProcessingService : public RefBase {
public:
    EXPORT_API static DeferredProcessingService& GetInstance();
    DeferredProcessingService(const DeferredProcessingService& other) = delete;
    DeferredProcessingService& operator=(const DeferredProcessingService& other) = delete;
    EXPORT_API void Initialize();
    EXPORT_API void Start();
    EXPORT_API void Stop();
    ~DeferredProcessingService();
    EXPORT_API sptr<IDeferredPhotoProcessingSession> CreateDeferredPhotoProcessingSession(const int32_t userId,
        const sptr<IDeferredPhotoProcessingSessionCallback> callbacks);
    EXPORT_API void NotifyCameraSessionStatus(const int32_t userId,
        const std::string& cameraId, bool running, bool isSystemCamera);

private:
    DeferredProcessingService();
    TaskManager* GetPhotoTaskManager(const int32_t userId);
    std::atomic<bool> initialized_;
    std::shared_ptr<SessionManager> sessionManager_;
    std::unique_ptr<SchedulerManager> schedulerManager_;
    std::unordered_map<int, std::shared_ptr<TaskManager>> photoTaskManagerMap_;
    std::mutex taskManagerMutex_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEFERRED_PROCESSING_SERVICE_H