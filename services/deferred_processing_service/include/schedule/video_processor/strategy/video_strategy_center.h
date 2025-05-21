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

#ifndef OHOS_CAMERA_DPS_VIDEO_STRATEGY_CENTER_H
#define OHOS_CAMERA_DPS_VIDEO_STRATEGY_CENTER_H

#include <functional>

#include "istate.h"
#include "istate_change_listener.h"
#include "video_job_repository.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
constexpr uint32_t TIME_OK = 0b0;
using EventCallback = std::function<void(const int32_t)>;
using VideoStateListener = IStateChangeListener<SchedulerType, SchedulerInfo>;

class VideoStrategyCenter : public std::enable_shared_from_this<VideoStrategyCenter> {
public:
    ~VideoStrategyCenter();

    void Initialize();
    void InitHandleEvent();
    void RegisterStateChangeListener(const std::weak_ptr<VideoStateListener>& listener);
    DeferredVideoWorkPtr GetWork();
    DeferredVideoJobPtr GetJob();
    ExecutionMode GetExecutionMode();
    void UpdateSingleTime(bool isOk);
    void UpdateAvailableTime(bool isNeedReset, int32_t useTime);

    inline int32_t GetAvailableTime()
    {
        return availableTime_;
    }

    inline bool IsReady()
    {
        DP_INFO_LOG("DPS_VIDEO: SchedulerOk is: %{public}d",  !isNeedStop_);
        return !isNeedStop_;
    }

    inline bool IsTimeReady()
    {
        DP_INFO_LOG("DPS_VIDEO: TimeOk is: 0x%{public}x", isTimeOk_);
        return isTimeOk_ == TIME_OK;
    }

    inline bool isCharging()
    {
        DP_INFO_LOG("DPS_VIDEO: Charging is: %{public}d", isCharging_);
        return isCharging_;
    }

protected:
    VideoStrategyCenter(const std::shared_ptr<VideoJobRepository>& repository);

private:
    class EventsListener;
    
    void HandleEventChanged(EventType event, int32_t value);
    void HandleCameraEvent(int32_t value);
    void HandleHalEvent(int32_t value);
    void HandleMedialLibraryEvent(int32_t value);
    void HandleScreenEvent(int32_t value);
    void HandleChargingEvent(int32_t value);
    void HandleBatteryEvent(int32_t value);
    void HandleBatteryLevelEvent(int32_t value);
    void HandleTemperatureEvent(int32_t value);
    void HandlePhotoProcessEvent(int32_t value);
    void UpdateValue(SchedulerType type, int32_t value);
    SchedulerInfo ReevaluateSchedulerInfo();
    SchedulerInfo GetSchedulerInfo(SchedulerType type);
    std::shared_ptr<IState> GetSchedulerState(SchedulerType type);

    inline PhotoProcessStatus ConvertProcessState(int32_t size)
    {
        DP_CHECK_RETURN_RET(size > 0, PhotoProcessStatus::BUSY);
        return PhotoProcessStatus::IDLE;
    }

    bool isCharging_ {false};
    bool isNeedStop_ {true};
    uint32_t isTimeOk_ {0};
    int32_t availableTime_ {TOTAL_PROCESS_TIME};
    std::shared_ptr<EventsListener> eventsListener_ {nullptr};
    std::shared_ptr<VideoJobRepository> repository_ {nullptr};
    std::weak_ptr<VideoStateListener> videoStateChangeListener_;
    std::unordered_map<EventType, EventCallback> eventHandlerList_ {};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_VIDEO_STRATEGY_CENTER_H