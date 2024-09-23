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

#include "screen_strategy.h"

#include "basic_definitions.h"
#include "common_event_support.h"
#include "events_monitor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
ScreenStrategy::ScreenStrategy()
{
    DP_DEBUG_LOG("entered.");
}

ScreenStrategy::~ScreenStrategy()
{
    DP_DEBUG_LOG("entered.");
}

void ScreenStrategy::handleEvent(const EventFwk::CommonEventData& data)
{
    auto action = data.GetWant().GetAction();
    int32_t screenState = ScreenStatus::SCREEN_OFF;
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON) {
        screenState = ScreenStatus::SCREEN_ON;
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
        screenState = ScreenStatus::SCREEN_OFF;
    }
    DP_INFO_LOG("OnScreenStatusChanged state:%{public}d", screenState);
    EventsMonitor::GetInstance().NotifyScreenStatus(screenState);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS