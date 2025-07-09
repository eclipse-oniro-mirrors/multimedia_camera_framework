/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "camera_timer.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
CameraTimer::CameraTimer() : timer_(std::make_unique<OHOS::Utils::Timer>("CameraServiceTimer"))
{
    MEDIA_INFO_LOG("entered.");
    timer_->Setup();
};

CameraTimer::~CameraTimer()
{
    MEDIA_INFO_LOG("entered.");
    if (timer_) {
        timer_->Shutdown();
        timer_ = nullptr;
    }
}

uint32_t CameraTimer::Register(const TimerCallback& callback, uint32_t interval, bool once)
{
    CHECK_RETURN_RET_ELOG(timer_ == nullptr, 0, "timer is nullptr");

    uint32_t timerId = timer_->Register(callback, interval, once);
    MEDIA_DEBUG_LOG("timerId: %{public}u", timerId);
    return timerId;
}

void CameraTimer::Unregister(uint32_t timerId)
{
    MEDIA_DEBUG_LOG("timerId: %{public}d", timerId);
    CHECK_RETURN_ELOG(timer_ == nullptr, "timer is nullptr");

    timer_->Unregister(timerId);
}
} // namespace CameraStandard
} // namespace OHOS