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

#ifndef OHOS_CAMERA_DPS_SCHEDULE_MANAGER_H
#define OHOS_CAMERA_DPS_SCHEDULE_MANAGER_H

#include "deferred_photo_controller.h"
#include "deferred_video_controller.h"
#include "enable_shared_create.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class SchedulerManager : public EnableSharedCreateInit<SchedulerManager> {
public:
    ~SchedulerManager();

    int32_t Initialize() override;
    void CreatePhotoProcessor(const int32_t userId);
    std::shared_ptr<PhotoPostProcessor> GetPhotoPostProcessor(const int32_t userId);
    std::shared_ptr<DeferredPhotoProcessor> GetPhotoProcessor(const int32_t userId);
    std::shared_ptr<DeferredPhotoController> GetPhotoController(const int32_t userId);
    void CreateVideoProcessor(const int32_t userId, const std::shared_ptr<IVideoProcessCallbacks>& callbacks);
    std::shared_ptr<VideoPostProcessor> GetVideoPostProcessor(const int32_t userId);
    std::shared_ptr<DeferredVideoProcessor> GetVideoProcessor(const int32_t userId);
    std::shared_ptr<DeferredVideoController> GetVideoController(const int32_t userId);

protected:
    SchedulerManager();

private:
    std::unordered_map<int32_t, std::shared_ptr<DeferredPhotoController>> photoController_ {};
    std::unordered_map<int32_t, std::shared_ptr<VideoPostProcessor>> videoPosts_ {};
    std::unordered_map<int32_t, std::shared_ptr<DeferredVideoProcessor>> videoProcessors_ {};
    std::unordered_map<int32_t, std::shared_ptr<DeferredVideoController>> videoController_ {};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_SCHEDULE_MANAGER_H