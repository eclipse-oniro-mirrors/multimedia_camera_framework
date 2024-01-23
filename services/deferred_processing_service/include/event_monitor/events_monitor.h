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

#ifndef OHOS_DEFERRED_PROCESSING_SERVICE_EVENTS_MONITOR_H
#define OHOS_DEFERRED_PROCESSING_SERVICE_EVENTS_MONITOR_H
#include <set>
#include <shared_mutex>
#include <iostream>
#include <any>
#include "ievents_listener.h"
#include "basic_definitions.h"
#include "task_manager.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#ifdef CAMERA_USE_THERMAL
#include "ithermal_srv.h"
#endif

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class ThermalLevelSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit ThermalLevelSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    virtual ~ThermalLevelSubscriber();
    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data) override;
    SystemPressureLevel MapEventLevel(int level);
};

class EventsMonitor {
public:
    static EventsMonitor& GetInstance();
    explicit EventsMonitor();
    ~EventsMonitor();
    void Initialize();
    void NotifyCameraSessionStatus(int userId, const std::string& cameraId, bool running, bool isSystemCamera);
    void NotifyMediaLibraryStatus(bool available);
    void NotifyImageEnhanceStatus(int32_t status);
    void NotifySystemPressureLevel(SystemPressureLevel level);
    void NotifyThermalLevel(int level);
    void NotifyEventToObervers(int userId, EventType event, int value);
    void RegisterTaskManager(int userId, TaskManager* taskManager);
    void RegisterThermalLevel();
    void UnRegisterThermalLevel();
    void RegisterEventsListener(int userId, const std::vector<EventType>& events,
        const std::shared_ptr<IEventsListener>& listener);
    void UnRegisterListener(int userId, TaskManager* taskManager);
    void SetRegisterThermalStatus(bool isHasRegistered);
    void ScheduleRegisterThermalListener();
    void NotifyObservers(EventType event, int value, int userId = 0);

private:
    class ThermalMgrDeathRecipient;
    void NotifyObserversUnlocked(int userId, EventType event, int value);
    void ConnectThermalSvr();

    std::mutex mutex_;
    bool initialized_;
    std::atomic<int> numActiveSessions_;
    std::map<int, std::vector<TaskManager*>> userIdToTaskManager;
    std::map<int, std::map<EventType, std::vector<std::weak_ptr<IEventsListener>>>> userIdToeventListeners_;
    bool mIsRegistered;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ = nullptr;
    std::shared_ptr<ThermalLevelSubscriber> thermalLevelSubscriber_ = nullptr;
    std::mutex thermalEventMutex;
#ifdef CAMERA_USE_THERMAL
    sptr<OHOS::PowerMgr::IThermalSrv> thermalSrv_ = nullptr;
#endif
};
}
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PROCESSING_SERVICE_EVENTS_MONITOR_H
