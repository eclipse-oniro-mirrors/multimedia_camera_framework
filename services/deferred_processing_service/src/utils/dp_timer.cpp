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

#include "dp_timer.h"

#include "common_timer_errors.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
DpsTimer::DpsTimer() : timer_(std::make_unique<Utils::Timer>("DpsManagerTimer"))
{
    timer_->Setup();
}

DpsTimer::~DpsTimer()
{
    if (timer_) {
        timer_->Shutdown(true);
        timer_ = nullptr;
    }
}

uint32_t DpsTimer::StartTimer(const TimerCallback& callback, uint32_t interval)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(timer_ == nullptr, INVALID_TIMEID, "DpsTimer is nullptr");

    uint32_t ret = timer_->Register(callback, interval, true);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret == Utils::TIMER_ERR_DEAL_FAILED, INVALID_TIMEID, "Register timer failed");

    DP_DEBUG_LOG("timerId is %{public}u, interval is %{public}u", ret, interval);
    return ret;
}

void DpsTimer::StopTimer(uint32_t& timerId)
{
    DP_DEBUG_LOG("timer shutting down, timerId = %{public}u", timerId);
    DP_CHECK_ERROR_RETURN_LOG(timerId == INVALID_TIMEID, "UnRegister timer failed, timerId is invalid");
    DP_CHECK_ERROR_RETURN_LOG(timer_ == nullptr, "DpsTimer is nullptr");

    timer_->Unregister(timerId);
    timerId = INVALID_TIMEID;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS