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

#include <vector>
#include <shared_mutex>
#include <iostream>

#include "basic_definitions.h"
#include "photo_job_repository.h"
#include "user_initiated_strategy.h"
#include "background_strategy.h"
#include "iimage_process_callbacks.h"
#include "deferred_photo_processor.h"
#include "ievents_listener.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredPhotoController {
public:
    DeferredPhotoController(int userId, std::shared_ptr<PhotoJobRepository> repository,
        std::shared_ptr<DeferredPhotoProcessor> processor);
    ~DeferredPhotoController();
    void Initialize();

private:
    class EventsListener;
    class PhotoJobRepositoryListener;
    void TryDoSchedule();
    void PostProcess(DeferredPhotoWorkPtr work);
    void NotifyPressureLevelChanged(SystemPressureLevel level);
    void NotifyHdiStatusChanged(HdiStatus status);
    void NotifyMediaLibStatusChanged(MediaLibraryStatus status);
    void NotifyCameraStatusChanged(CameraSessionStatus status);
    void OnPhotoJobChanged(bool priorityChanged, bool statusChanged, DeferredPhotoJobPtr jobPtr);
    void StartWaitForUser();
    void StopWaitForUser();
    void NotifyScheduleState(bool scheduling);

    std::recursive_mutex mutex_;
    int userId_;
    uint32_t callbackHandle_;
    bool isWaitForUser_;
    DpsStatus scheduleState_;
    std::shared_ptr<PhotoJobRepository> photoJobRepository_;
    std::shared_ptr<DeferredPhotoProcessor> photoProcessor_;
    std::unique_ptr<UserInitiatedStrategy> userInitiatedStrategy_;
    std::unique_ptr<BackgroundStrategy> backgroundStrategy_;
    std::shared_ptr<EventsListener> eventsListener_;
    std::shared_ptr<PhotoJobRepositoryListener> photoJobRepositoryListener_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEFERRED_PHOTO_CONTROLLER_H