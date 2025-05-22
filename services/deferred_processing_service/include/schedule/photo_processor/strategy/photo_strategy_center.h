/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_DPS_PHOTO_STRATEGY_CENTER_H
#define OHOS_CAMERA_DPS_PHOTO_STRATEGY_CENTER_H

#include <functional>

#include "basic_definitions.h"
#include "enable_shared_create.h"
#include "ievents_listener.h"
#include "istate.h"
#include "istate_change_listener.h"
#include "photo_job_repository.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
using EventCallback = std::function<void(const int32_t)>;
using PhotoStateListener = IStateChangeListener<SchedulerType, SchedulerInfo>;
class PhotoStrategyCenter;
class PhotoEventsListener : public IEventsListener {
public:
    explicit PhotoEventsListener(const std::weak_ptr<PhotoStrategyCenter>& strategyCenter);
    ~PhotoEventsListener() = default;

    void OnEventChange(EventType event, int32_t value) override;

private:
    std::weak_ptr<PhotoStrategyCenter> strategyCenter_;
};

class PhotoStrategyCenter : public EnableSharedCreateInit<PhotoStrategyCenter> {
public:
    ~PhotoStrategyCenter();

    int32_t Initialize() override;
    void InitHandleEvent();
    void RegisterStateChangeListener(const std::weak_ptr<PhotoStateListener>& listener);
    void HandleEventChanged(EventType event, int32_t value);
    DeferredPhotoJobPtr GetJob();
    HdiStatus GetHdiStatus();

protected:
    PhotoStrategyCenter(const std::shared_ptr<PhotoJobRepository>& repository);

private:
    bool IsReady();
    void HandleCameraEvent(int32_t value);
    void HandleHalEvent(int32_t value);
    void HandleMedialLibraryEvent(int32_t value);
    void HandleTemperatureEvent(int32_t value);
    void UpdateValue(SchedulerType type, int32_t value);
    SchedulerInfo ReevaluateSchedulerInfo();
    SchedulerInfo GetSchedulerInfo(SchedulerType type);
    std::shared_ptr<IState> GetSchedulerState(SchedulerType type);
    ExecutionMode GetExecutionMode(JobPriority priority);

    bool isNeedStop_ {true};
    std::shared_ptr<PhotoEventsListener> eventsListener_ {nullptr};
    std::shared_ptr<PhotoJobRepository> repository_ {nullptr};
    std::weak_ptr<PhotoStateListener> photoStateChangeListener_;
    std::unordered_map<EventType, EventCallback> eventHandlerList_ {};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_PHOTO_STRATEGY_CENTER_H