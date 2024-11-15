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

#include "event_status_change_command.h"

#include "dp_log.h"
#include "events_monitor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
EventStatusChangeCommand::EventStatusChangeCommand(const int32_t userId, const EventType event, const int value)
    : userId_(userId), eventId_(event), value_(value)
{
    DP_DEBUG_LOG("entered.");
}

EventStatusChangeCommand::~EventStatusChangeCommand()
{
    DP_DEBUG_LOG("entered.");
}

int32_t EventStatusChangeCommand::Executing()
{
    DP_DEBUG_LOG("event status change, userId: %{public}d, event: %{public}d, value: %{public}d",
        userId_, eventId_, value_);
    EventsMonitor::GetInstance().NotifyEventToObervers(userId_, eventId_, value_);
    return DP_OK;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS