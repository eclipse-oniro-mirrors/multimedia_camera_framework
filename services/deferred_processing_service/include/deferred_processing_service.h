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

#include "ideferred_photo_processing_session.h"
#include "ideferred_photo_processing_session_callback.h"
#include "ideferred_video_processing_session.h"
#include "ideferred_video_processing_session_callback.h"
#include "singleton.h"
#include "task_manager.h"

namespace OHOS::Media {
    class Picture;
}
namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class EXPORT_API DeferredProcessingService : public RefBase, public Singleton<DeferredProcessingService> {
    DECLARE_SINGLETON(DeferredProcessingService)

public:
    void Initialize();
    void Start();
    void Stop();
    void NotifyLowQualityImage(const int32_t userId, const std::string& imageId,
        std::shared_ptr<Media::Picture> picture);
    sptr<IDeferredPhotoProcessingSession> CreateDeferredPhotoProcessingSession(const int32_t userId,
        const sptr<IDeferredPhotoProcessingSessionCallback> callbacks);
    sptr<IDeferredVideoProcessingSession> CreateDeferredVideoProcessingSession(const int32_t userId,
        const sptr<IDeferredVideoProcessingSessionCallback> callbacks);
    void NotifyCameraSessionStatus(const int32_t userId,
        const std::string& cameraId, bool running, bool isSystemCamera);

private:
    TaskManager* GetPhotoTaskManager(const int32_t userId);

    std::atomic<bool> initialized_ {false};
    std::unordered_map<int, std::shared_ptr<TaskManager>> photoTaskManagerMap_;
    std::mutex taskManagerMutex_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEFERRED_PROCESSING_SERVICE_H