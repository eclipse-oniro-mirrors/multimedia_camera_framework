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

#include "camera_common_event_manager.h"

namespace OHOS {
namespace CameraStandard {

sptr<CameraCommonEventManager> CameraCommonEventManager::instance_ = nullptr;
std::mutex CameraCommonEventManager::instanceMutex_;
std::mutex CameraCommonEventManager::mapMutex_;
CameraCommonEventManager::CameraCommonEventManager()
{}

CameraCommonEventManager::~CameraCommonEventManager()
{}

sptr<CameraCommonEventManager> CameraCommonEventManager::GetInstance()
{
    if (instance_ != nullptr) {
        return instance_;
    }
    std::lock_guard<std::mutex> lock(instanceMutex_);
    if (instance_ != nullptr) {
        return instance_;
    }
    instance_ = new (std::nothrow) CameraCommonEventManager();
    return instance_;
}

void CameraCommonEventManager::SubscribeCommonEvent(const std::string &eventName, EventReceiver receiver)
{
    MEDIA_INFO_LOG("SubscribeCommonEvent eventName=%{public}s", eventName.c_str());
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(eventName);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto subscriberPtr = std::make_shared<CameraCommonEventSubscriber>(subscribeInfo, receiver);
    if (subscriberPtr == nullptr) {
        MEDIA_INFO_LOG("subscriberPtr is nullptr");
        return;
    }
    if (EventFwk::CommonEventManager::SubscribeCommonEvent(subscriberPtr)) {
        MEDIA_INFO_LOG("SubscribeCommonEvent success");
        {
            std::lock_guard<std::mutex> lock(mapMutex_);
            commonEventSubscriberMap_.insert(std::make_pair(eventName, subscriberPtr));
        }
    }
}

void CameraCommonEventManager::UnSubscribeCommonEvent(const std::string &eventName)
{
    MEDIA_INFO_LOG("UnSubscribeCommonEvent eventName=%{public}s", eventName.c_str());
    std::lock_guard<std::mutex> lock(mapMutex_);
    auto subscriber = commonEventSubscriberMap_.find(eventName);
    if (subscriber == commonEventSubscriberMap_.end()) {
        MEDIA_INFO_LOG("UnSubscribeCommonEvent event:%{public}s is not subscribed", eventName.c_str());
        return;
    }
    auto commonEventSubscriber = subscriber->second;
    if (commonEventSubscriber != nullptr) {
        EventFwk::CommonEventManager::UnSubscribeCommonEvent(commonEventSubscriber);
    }
    commonEventSubscriberMap_.erase(subscriber);
}

CameraCommonEventManager::CameraCommonEventSubscriber::CameraCommonEventSubscriber(
    const EventFwk::CommonEventSubscribeInfo &subscribeInfo, EventReceiver receiver)
    : EventFwk::CommonEventSubscriber(subscribeInfo), eventReceiver_(receiver) {}

void CameraCommonEventManager::CameraCommonEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    if (eventReceiver_ == nullptr) {
        MEDIA_INFO_LOG("eventReceiver_ is nullptr");
        return;
    }
    eventReceiver_(data);
}

} // namespace CameraStandard
} // namespace OHOS