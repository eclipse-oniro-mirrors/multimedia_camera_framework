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

#ifndef OHOS_CAMERA_DPS_EVENTS_SUBSCRIBER_H
#define OHOS_CAMERA_DPS_EVENTS_SUBSCRIBER_H

#include "events_strategy.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class EventSubscriber : public EventFwk::CommonEventSubscriber,
    public std::enable_shared_from_this<EventSubscriber> {
public:
    virtual ~EventSubscriber();

    static std::shared_ptr<EventSubscriber> Create();
    void Initialize();
    void Subcribe();
    void UnSubscribe();
    void OnReceiveEvent(const EventFwk::CommonEventData& data) override;

protected:
    explicit EventSubscriber(const EventFwk::CommonEventSubscribeInfo& subscriberInfo);

private:
    static const std::vector<std::string> events_;
    std::unordered_map<std::string, std::shared_ptr<EventStrategy>> eventStrategy_ {};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_EVENTS_SUBSCRIBER_H