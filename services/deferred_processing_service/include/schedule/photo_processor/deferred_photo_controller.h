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

#ifndef OHOS_CAMERA_DPS_DEFERRED_PHOTO_CONTROLLER_H
#define OHOS_CAMERA_DPS_DEFERRED_PHOTO_CONTROLLER_H

#include "background_strategy.h"
#include "deferred_photo_job.h"
#include "deferred_photo_processor.h"
#include "user_initiated_strategy.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredPhotoController : public std::enable_shared_from_this<DeferredPhotoController> {
public:
    ~DeferredPhotoController();

    void Initialize();

protected:
    DeferredPhotoController(const int32_t userId, const std::shared_ptr<PhotoJobRepository>& repository,
        const std::shared_ptr<DeferredPhotoProcessor>& processor);

private:
    class EventsListener;
    class PhotoJobRepositoryListener;

    void TryDoSchedule();
    void PostProcess(DeferredPhotoWorkPtr work);
    void SetDefaultExecutionMode();
    void NotifyPressureLevelChanged(SystemPressureLevel level);
    void NotifyHdiStatusChanged(HdiStatus status);
    void NotifyMediaLibStatusChanged(MediaLibraryStatus status);
    void NotifyCameraStatusChanged(CameraSessionStatus status);
    void OnPhotoJobChanged(bool priorityChanged, bool statusChanged, DeferredPhotoJobPtr jobPtr);
    void StartWaitForUser();
    void StopWaitForUser();

    const int32_t userId_;
    uint32_t timeId_ {INVALID_TIMEID};
    std::unique_ptr<UserInitiatedStrategy> userInitiatedStrategy_ {nullptr};
    std::unique_ptr<BackgroundStrategy> backgroundStrategy_ {nullptr};
    std::shared_ptr<PhotoJobRepository> photoJobRepository_;
    std::shared_ptr<DeferredPhotoProcessor> photoProcessor_;
    std::shared_ptr<EventsListener> eventsListener_;
    std::shared_ptr<PhotoJobRepositoryListener> photoJobRepositoryListener_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEFERRED_PHOTO_CONTROLLER_H