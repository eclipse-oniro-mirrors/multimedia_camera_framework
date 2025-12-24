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
#include "enable_shared_create.h"
#include "video_strategy_center.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredVideoController : public EnableSharedCreateInit<DeferredVideoController> {
public:
    ~DeferredVideoController();

    int32_t Initialize() override;
    void HandleServiceDied();
    void HandleSuccess(const std::string& videoId, std::unique_ptr<MediaUserInfo> userInfo);
    void HandleError(const std::string& videoId, DpsError errorCode);
    void OnVideoJobChanged();

    inline std::shared_ptr<DeferredVideoProcessor> GetVideoProcessor()
    {
        return videoProcessor_;
    }

protected:
    DeferredVideoController(const int32_t userId, const std::shared_ptr<DeferredVideoProcessor>& processor);

private:
    class StateListener;

    void OnSchedulerChanged(const SchedulerType& type, const SchedulerInfo& scheduleInfo);
    void TryDoSchedule();
    void DoProcess(const DeferredVideoJobPtr& job);
    void PauseRequests(const SchedulerType& type);
    void SetDefaultExecutionMode();
    void StartSuspendLock();
    void StopSuspendLock();
    void HandleNormalSchedule(const DeferredVideoJobPtr& job);
    void OnTimerOut();
    DeferredVideoJobPtr GetJob(const std::string& videoId);

    const int32_t userId_;
    uint32_t normalTimeId_ {INVALID_TIMERID};
    std::shared_ptr<DeferredVideoProcessor> videoProcessor_;
    std::shared_ptr<VideoStrategyCenter> videoStrategyCenter_ {nullptr};
    std::shared_ptr<StateListener> videoStateChangeListener_ {nullptr};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEFERRED_VIDEO_CONTROLLER_H