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

#include "timer.h"
#include "steady_clock.h"
#include "core/timer_core.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

std::shared_ptr<Timer> Timer::Create(const std::string& name, TimerType timerType,
    uint32_t intervalMs, TimerCallback callback)
{
    DP_DEBUG_LOG("name: %s, timer type: %d(0: once, 1: periodic), intervalMs: %u", name.c_str(), timerType, intervalMs);
    struct MakeSharedHelper : public Timer {
        MakeSharedHelper(const std::string& name, TimerType timerType, uint32_t intervalMs, TimerCallback callback)
            : Timer(name, timerType, intervalMs, std::move(callback))
        {
        }
    };
    auto timer = std::make_shared<MakeSharedHelper>(name, timerType, intervalMs, std::move(callback));
    if (timer && !timer->Initialize()) {
        timer.reset();
    }
    return timer;
}

Timer::Timer(const std::string& name, TimerType timerType, uint32_t intervalMs, TimerCallback callback)
    : name_(name), timerType_(timerType), intervalMs_(intervalMs), callback_(std::move(callback)), expiredTimeMs_(0)
{
    DP_DEBUG_LOG("name: %s, timer type: %d(0: once, 1: periodic), intervalMs: %u",
        name_.c_str(), timerType, intervalMs);
}

Timer::~Timer()
{
    DP_DEBUG_LOG("name: %s, timer type: %d(0: once, 1: periodic), intervalMs: %u",
        name_.c_str(), timerType_, intervalMs_);
    std::lock_guard<std::mutex> lock(mutex_);
    active_ = false;
}

bool Timer::Initialize()
{
    return TimerCore::GetInstance().Initialize();
}

const std::string& Timer::GetName()
{
    return name_;
}

bool Timer::Start(uint32_t delayTimeMs)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return StartUnlocked(delayTimeMs);
}

bool Timer::StartAt(uint64_t timestampMs)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return StartAtUnlocked(timestampMs);
}

bool Timer::Stop()
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_DEBUG_LOG("stop timer (%s), timer type: %d(0: once, 1: periodic), intervalMs: %u",
        name_.c_str(), timerType_, intervalMs_);
    if (!active_) {
        return true;
    }
    active_ = false;
    return TimerCore::GetInstance().DeregisterTimer(expiredTimeMs_, shared_from_this());
}

bool Timer::StartUnlocked(uint32_t delayTimeMs)
{
    auto curTimeMs = SteadyClock::GetTimestampMilli();
    auto timestampMs = curTimeMs + (delayTimeMs == 0 ? intervalMs_ : delayTimeMs);
    DP_DEBUG_LOG("timer (%s), type: %d(0: once, 1: periodic), curTime: %d, expiredTime: %d",
        name_.c_str(), timerType_, static_cast<int>(curTimeMs), static_cast<int>(timestampMs));
    return StartAtUnlocked(timestampMs);
}

bool Timer::StartAtUnlocked(uint64_t timestampMs)
{
    if (active_) {
        TimerCore::GetInstance().DeregisterTimer(expiredTimeMs_, shared_from_this());
    }
    active_ = true;
    expiredTimeMs_ = timestampMs;
    return TimerCore::GetInstance().RegisterTimer(expiredTimeMs_, shared_from_this());
}

bool Timer::IsActive()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return active_;
}

void Timer::TimerExpired()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_) {
            DP_DEBUG_LOG("inactive timer (%s) expired, type: %d(0: once, 1: periodic), intervalMs: %u", name_.c_str(),
                timerType_, intervalMs_);
            return;
        }
        if (timerType_ == TimerType::PERIODIC) {
            StartUnlocked();
        } else {
            active_ = false;
        }
    }
    DP_DEBUG_LOG("timer (%s) expired, type: %d(0: once, 1: periodic), expiredTimeMs at %d", name_.c_str(),
        timerType_, static_cast<int>(expiredTimeMs_));
    if (callback_) {
        callback_();
    }
}
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
