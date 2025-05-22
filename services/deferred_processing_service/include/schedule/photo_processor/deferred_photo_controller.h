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

#ifndef OHOS_CAMERA_DPS_DEFERRED_PHOTO_CONTROLLER_H
#define OHOS_CAMERA_DPS_DEFERRED_PHOTO_CONTROLLER_H

#include "deferred_photo_processor.h"
#include "enable_shared_create.h"
#include "photo_strategy_center.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredPhotoController : public EnableSharedCreateInit<DeferredPhotoController> {
public:
    ~DeferredPhotoController();

    int32_t Initialize() override;
    std::shared_ptr<DeferredPhotoProcessor> GetPhotoProcessor();
    void OnPhotoJobChanged();

protected:
    DeferredPhotoController(const int32_t userId, const std::shared_ptr<DeferredPhotoProcessor>& processor);

private:
    class StateListener;
    class PhotoJobRepositoryListener;

    void OnSchedulerChanged(const SchedulerType& type, const SchedulerInfo& scheduleInfo);
    void TryDoSchedule();
    void DoProcess(const DeferredPhotoJobPtr& job);
    void SetDefaultExecutionMode();
    void NotifyScheduleState(bool workAvailable);

    const int32_t userId_;
    DpsStatus scheduleState_ {DpsStatus::DPS_SESSION_STATE_IDLE};
    std::shared_ptr<DeferredPhotoProcessor> photoProcessor_;
    std::shared_ptr<PhotoStrategyCenter> photoStrategyCenter_ {nullptr};
    std::shared_ptr<StateListener> photoStateChangeListener_ {nullptr};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEFERRED_PHOTO_CONTROLLER_H