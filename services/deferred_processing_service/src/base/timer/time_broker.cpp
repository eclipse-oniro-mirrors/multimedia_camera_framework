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

#include "time_broker.h"
#include "steady_clock.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
std::shared_ptr<TimeBroker> TimeBroker::Create(std::string name)
{
    DP_DEBUG_LOG("(%s) created.", name.c_str());
    auto timeBroker = std::make_shared<TimeBroker>(std::move(name));
    if (timeBroker) {
        timeBroker->Initialize();
    }
    return timeBroker;
}

TimeBroker::TimeBroker(std::string name)
    : name_(std::move(name)), timer_(nullptr), timerInfos_(), expiringTimers_()
{
    DP_DEBUG_LOG("(%s) entered.", name_.c_str());
}

TimeBroker::~TimeBroker()
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_DEBUG_LOG("(%s) entered.", name_.c_str());
    if (timer_) {
        timer_->Stop();
        timer_.reset();
    }
    timerInfos_.clear();
    expiringTimers_.clear();
}

void TimeBroker::Initialize()
{
    std::weak_ptr<TimeBroker> weakThis(shared_from_this());
    timer_ = Timer::Create(name_, TimerType::ONCE, 0, [weakThis]() {
        if (auto timeBroker = weakThis.lock()) {
            timeBroker->TimerExpired();
        }
    });
}

bool TimeBroker::RegisterCallback(uint32_t delayTimeMs, std::function<void(uint32_t handle)> timerCallback,
    uint32_t& handle)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_DEBUG_LOG("(%s) register callback with delayTimeMs (%d).", name_.c_str(), static_cast<int>(delayTimeMs));
    auto ret = GetNextHandle(handle);
    if (ret) {
        auto timestamp = SteadyClock::GetTimestampMilli() + delayTimeMs;
        auto timerInfo = std::make_shared<TimerInfo>(handle, timestamp, std::move(timerCallback));
        expiringTimers_[timestamp].push_back(timerInfo);
        timerInfos_.emplace(handle, timerInfo);
        timeline_.push(timestamp);
        if (timestamp == timeline_.top()) {
            timer_->StartAt(timestamp);
        }
    }
    return ret;
}
void TimeBroker::DeregisterCallback(uint32_t handle)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (handle == 0) {
        DP_DEBUG_LOG("(%s) invalid handle (%d).", name_.c_str(), static_cast<int>(handle));
        return;
    }
    timerInfos_.erase(handle);
}

bool TimeBroker::GetNextHandle(uint32_t& handle)
{
    do {
        handle = GenerateHandle();
    } while (timerInfos_.count(handle) != 0 && handle != preHandle_);
    if (handle != preHandle_) {
        preHandle_ = handle;
        return true;
    }
    return false;
}

uint32_t TimeBroker::GenerateHandle()
{
    static uint32_t handle = 0;
    if (++handle == 0) {
        ++handle;
    }
    return handle;
}

void TimeBroker::TimerExpired()
{
    std::vector<std::shared_ptr<TimerInfo>> timerInfos;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        DP_DEBUG_LOG("(%s) TimerExpired.", name_.c_str());
        if (timeline_.empty()) {
            DP_DEBUG_LOG("(%s) unexpected TimerExpired", name_.c_str());
            return;
        }
        auto timestamp = timeline_.top();
        timeline_.pop();
        timerInfos.reserve(expiringTimers_[timestamp].size());
        for (auto& weakTimerInfoPtr : expiringTimers_[timestamp]) {
            if (auto timerInfo = weakTimerInfoPtr.lock()) {
                timerInfos_.erase(timerInfo->handle);
                timerInfos.push_back(std::move(timerInfo));
            }
        }
        expiringTimers_.erase(timestamp);
        auto ret = RestartTimer(timestamp);
        if (!ret) {
            DP_DEBUG_LOG("(%s) RestartTimer failed (%d)", name_.c_str(), ret);
        }
    }
    for (auto &timerInfo : timerInfos) {
        timerInfo->timerCallback(timerInfo->handle);
    }
}

bool TimeBroker::RestartTimer(bool force)
{
    if (timeline_.empty() || (timer_->IsActive() && force == false)) {
        DP_DEBUG_LOG("(%s) RestartTimer unnecessary.", name_.c_str());
        return true;
    }
    auto timestamp = timeline_.top();
    DP_DEBUG_LOG("(%s) restart timer, expiring timestamp: %d", name_.c_str(), static_cast<int>(timestamp));
    return timer_->StartAt(timestamp);
}
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
