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

#include <securec.h>
#include <algorithm>
#include "timer_core.h"
#include "thread_utils.h"
#include "steady_clock.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace {
    constexpr uint32_t EXPIREATION_TIME_MILLI_SECONDS = 12 * 60 * 1000;
} //namespace

namespace DeferredProcessing {
TimerCore& TimerCore::GetInstance()
{
    static TimerCore instance;
    return instance;
}

TimerCore::TimerCore()
{
    DP_DEBUG_LOG("entered.");
}

TimerCore::~TimerCore()
{
    DP_DEBUG_LOG("entered.");
    {
        std::unique_lock<std::mutex> lock(mutex_);
        registeredTimers_.clear();
        active_ = false;
        cv_.notify_one();
    }
    if (worker_.joinable()) {
        worker_.join();
    }
    DP_DEBUG_LOG("exited.");
}

bool TimerCore::Initialize()
{
    DP_DEBUG_LOG("entered.");
    std::unique_lock<std::mutex> lock(mutex_);
    if (!active_) {
        active_ = true;
        const std::string threadName = "TimerCore";
        worker_ = std::thread([this, threadName]() { TimerLoop(threadName); });
        SetThreadName(worker_.native_handle(), threadName);
        SetThreadPriority(worker_.native_handle(), PRIORITY_NORMAL);
    }
    return true;
}

bool TimerCore::RegisterTimer(uint64_t timestampMs, const std::shared_ptr<Timer>& timer)
{
    if (!active_) {
        return false;
    }
    if (timer == nullptr) {
        DP_DEBUG_LOG("failed due to nullptr.");
        return false;
    }
    std::unique_lock<std::mutex> lock(mutex_);
    if (registeredTimers_.count(timestampMs) == 0) {
        timeline_.push(timestampMs);
        if (timestampMs == timeline_.top()) {
            resetTimer_ = true;
            cv_.notify_one();
        }
    }
    registeredTimers_[timestampMs].push_back(timer);
    DP_DEBUG_LOG("register timer (%s), timestamp: %d, timeline.top: %d", timer->GetName().c_str(),
        static_cast<int>(timestampMs), static_cast<int>(timeline_.top()));
    return true;
}

bool TimerCore::DeregisterTimer(uint64_t timestampMs, const std::shared_ptr<Timer>& timer)
{
    if (!active_) {
        return true;
    }
    if (timer == nullptr) {
        DP_ERR_LOG("failed due to nullptr.");
        return false;
    }
    DP_DEBUG_LOG("(%s, %d) entered.", timer->GetName().c_str(), static_cast<int>(timestampMs));
    std::unique_lock<std::mutex> lock(mutex_);
    if (registeredTimers_.count(timestampMs)) {
        auto& timers = registeredTimers_[timestampMs];
        timers.erase(std::remove_if(timers.begin(), timers.end(),
            [this, &timer](auto& weakTimer) { return IsSameOwner(timer, weakTimer); }), timers.end());
        if (timers.empty()) {
            registeredTimers_.erase(timestampMs);
        }
    }
    return true;
}

void TimerCore::TimerLoop(const std::string& threadName)
{
    DP_DEBUG_LOG("(%s) entered.", threadName.c_str());
    while (active_.load()) {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            bool stopWaiting = cv_.wait_for(lock, GetNextExpirationTimeUnlocked(), [this] {
                bool stopWaiting = !active_.load() || resetTimer_.load();
                resetTimer_ = false;
                return stopWaiting;
            });
            if (stopWaiting) {
                continue;
            }
        }
        DoTimeout();
    }
    DP_DEBUG_LOG("(%s) exited.", threadName.c_str());
}

std::chrono::milliseconds TimerCore::GetNextExpirationTimeUnlocked()
{
    std::chrono::milliseconds expirationTime(EXPIREATION_TIME_MILLI_SECONDS);
    if (!timeline_.empty()) {
        expirationTime = SteadyClock::GetRemainingTimeMs(timeline_.top());
    }
    DP_DEBUG_LOG("expiration time: %lld.", expirationTime.count());
    return expirationTime;
}

void TimerCore::DoTimeout()
{
    std::vector<std::weak_ptr<Timer>> timers;
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (timeline_.empty()) {
            DP_DEBUG_LOG("no register timer.");
            return;
        }
        auto timestamp = timeline_.top();
        timeline_.pop();
        if (registeredTimers_.count(timestamp) == 0) {
            DP_DEBUG_LOG("timer for timestamp %d hasn't been registered.", static_cast<int>(timestamp));
            return;
        }
        DP_DEBUG_LOG("expired timestamp: %d", static_cast<int>(timestamp));
        timers = std::move(registeredTimers_[timestamp]);
        registeredTimers_.erase(timestamp);
    }
    for (auto& weakTimer : timers) {
        if (auto timer = weakTimer.lock()) {
            timer->TimerExpired();
        }
    }
}

bool TimerCore::IsSameOwner(const std::shared_ptr<Timer>& lhs, const std::weak_ptr<Timer>& rhs)
{
    return !lhs.owner_before(rhs) && !rhs.owner_before(lhs);
}
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
