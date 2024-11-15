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

#ifndef OHOS_CAMERA_DPS_EVENTS_MONITOR_H
#define OHOS_CAMERA_DPS_EVENTS_MONITOR_H

#include "events_subscriber.h"
#include "ievents_listener.h"
#include "singleton.h"
#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class CommonEventListener : public SystemAbilityStatusChangeStub {
public:
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

private:
    std::shared_ptr<EventSubscriber> eventSubscriber_ {nullptr};
};

class EventsMonitor : public Singleton<EventsMonitor> {
    DECLARE_SINGLETON(EventsMonitor)

public:
    void Initialize();
    void NotifyCameraSessionStatus(const int32_t userId,
        const std::string& cameraId, bool running, bool isSystemCamera);
    void NotifyMediaLibraryStatus(bool available);
    void NotifyImageEnhanceStatus(int32_t status);
    void NotifyVideoEnhanceStatus(int32_t status);
    void NotifyScreenStatus(int32_t status);
    void NotifyChargingStatus(int32_t status);
    void NotifyBatteryStatus(int32_t status);
    void NotifyBatteryLevel(int32_t level);
    void NotifySystemPressureLevel(SystemPressureLevel level);
    void NotifyThermalLevel(int level);
    void NotifyPhotoProcessSize(int32_t offlineSize, int32_t backSize);
    void NotifyEventToObervers(int userId, EventType event, int value);
    void RegisterEventsListener(int userId, const std::vector<EventType>& events,
        const std::weak_ptr<IEventsListener>& listener);
    void NotifyObservers(EventType event, int value, int userId = 0);

private:
    void NotifyObserversUnlocked(int userId, EventType event, int value);
    int32_t SubscribeSystemAbility();
    int32_t UnSubscribeSystemAbility();

    std::mutex mutex_;
    std::atomic_bool initialized_ {false};
    std::atomic<int> numActiveSessions_ {0};
    std::map<int32_t, std::map<EventType, std::vector<std::weak_ptr<IEventsListener>>>> userIdToeventListeners_ {};
    sptr<CommonEventListener> ceListener_ {nullptr};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_EVENTS_MONITOR_H
