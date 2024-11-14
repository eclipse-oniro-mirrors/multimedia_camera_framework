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

#ifndef OHOS_CAMERA_DPS_DEFERRED_VIDEO_CONTROLLER_H
#define OHOS_CAMERA_DPS_DEFERRED_VIDEO_CONTROLLER_H

#include "deferred_video_processor.h"
#include "video_strategy_center.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredVideoController : public std::enable_shared_from_this<DeferredVideoController> {
public:
    ~DeferredVideoController();

    void Initialize();
    void HandleServiceDied();
    void HandleSuccess(const DeferredVideoWorkPtr& work);
    void HandleError(const DeferredVideoWorkPtr& work, DpsError errorCode);

protected:
    DeferredVideoController(const int32_t userId, const std::shared_ptr<VideoJobRepository>& repository,
        const std::shared_ptr<DeferredVideoProcessor>& processor);

private:
    class StateListener;
    class VideoJobRepositoryListener;

    void OnSchedulerChanged(const ScheduleType& type, const ScheduleInfo& scheduleInfo);
    void OnVideoJobChanged(const DeferredVideoJobPtr& jobPtr);
    void TryDoSchedule();
    void PauseRequests(const ScheduleType& type);
    void PostProcess(const DeferredVideoWorkPtr& work);
    void SetDefaultExecutionMode();
    void StartSuspendLock();
    void StopSuspendLock();
    void HandleNormalSchedule(const DeferredVideoWorkPtr& work);
    void OnTimerOut();

    const int32_t userId_;
    uint32_t normalTimeId_ {0};
    std::shared_ptr<DeferredVideoProcessor> videoProcessor_;
    std::shared_ptr<VideoJobRepository> repository_;
    std::shared_ptr<VideoStrategyCenter> videoStrategyCenter_ {nullptr};
    std::shared_ptr<StateListener> videoStateChangeListener_ {nullptr};
    std::shared_ptr<VideoJobRepositoryListener> videoJobChangeListener_ {nullptr};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEFERRED_VIDEO_CONTROLLER_H