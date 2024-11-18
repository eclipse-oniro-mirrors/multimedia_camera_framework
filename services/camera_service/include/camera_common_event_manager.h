/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
#ifndef CAMERA_COMMON_EVENT_MANAGER_H
#define CAMERA_COMMON_EVENT_MANAGER_H

#include "refbase.h"
#include "camera_log.h"
#include "camera_util.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "matching_skills.h"

#include <functional>
#include <mutex>

namespace OHOS {
namespace CameraStandard {

using EventReceiver = std::function<void(const EventFwk::CommonEventData&)>;
static const std::string COMMON_EVENT_DATA_SHARE_READY = "usual.event.DATA_SHARE_READY";
class CameraCommonEventManager : public RefBase {
public:
    CameraCommonEventManager();
    ~CameraCommonEventManager();
    static sptr<CameraCommonEventManager> GetInstance();
    void SubscribeCommonEvent(const std::string &eventName, EventReceiver receiver);
    void UnSubscribeCommonEvent(const std::string &eventName);

    class CameraCommonEventSubscriber : public EventFwk::CommonEventSubscriber {
    public:
    CameraCommonEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo, EventReceiver receiver);
    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;

    private:
        EventReceiver eventReceiver_;
    };

private:
    static sptr<CameraCommonEventManager> instance_;
    std::map<std::string, std::shared_ptr<CameraCommonEventSubscriber>> commonEventSubscriberMap_;
    static std::mutex instanceMutex_;
    static std::mutex mapMutex_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_COMMON_EVENT_MANAGER_H