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
CameraTimer *CameraTimer::GetInstance()
{
    static CameraTimer instance;
    return &instance;
}

CameraTimer::CameraTimer()
    : userCount_(0),
      timer_(nullptr)
{
    MEDIA_INFO_LOG("entered.");
};

CameraTimer::~CameraTimer()
{
    MEDIA_INFO_LOG("entered.");
    if (timer_) {
        timer_->Shutdown();
        timer_ = nullptr;
    }
}

void CameraTimer::IncreaseUserCount()
{
    MEDIA_INFO_LOG("entered, num of user: %d + 1", static_cast<int>(userCount_.load()));
    if (timer_ == nullptr) {
        timer_ = std::make_unique<OHOS::Utils::Timer>("CameraServiceTimer");
        timer_->Setup();
        MEDIA_INFO_LOG("create timer thread");
    }
    ++userCount_;
    return;
}

void CameraTimer::DecreaseUserCount()
{
    MEDIA_INFO_LOG("entered, num of user: %u - 1", userCount_.load());
    --userCount_;
    if (userCount_.load() == 0 && timer_ != nullptr) {
        MEDIA_INFO_LOG("delete timer thread");
    }
    return;
}

uint32_t CameraTimer::Register(const TimerCallback& callback, uint32_t interval, bool once)
{
    if (timer_ == nullptr) {
        MEDIA_ERR_LOG("timer is nullptr");
        return 0;
    }

    uint32_t timerId = timer_->Register(callback, interval, once);
    MEDIA_DEBUG_LOG("timerId: %{public}u", timerId);
    return timerId;
}

void CameraTimer::Unregister(uint32_t timerId)
{
    MEDIA_DEBUG_LOG("timerId: %{public}d", timerId);
    if (timer_) {
        MEDIA_DEBUG_LOG("timerId: %{public}d", timerId);
        timer_->Unregister(timerId);
        return;
    }
    return;
}
} // namespace CameraStandard
} // namespace OHOS