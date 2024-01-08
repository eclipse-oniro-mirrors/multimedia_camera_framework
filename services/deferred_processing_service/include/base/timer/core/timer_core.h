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

#ifndef OHOS_DEFERRED_PROCESSING_SERVICE_TIMER_CORE_H
#define OHOS_DEFERRED_PROCESSING_SERVICE_TIMER_CORE_H

#include <atomic>
#include <condition_variable>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>
#include "timer.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class TimerCore {
public:
    static TimerCore& GetInstance();
    ~TimerCore();
    bool Initialize();
    bool RegisterTimer(uint64_t timestampMs, const std::shared_ptr<Timer>& timer);
    bool DeregisterTimer(uint64_t timestampMs, const std::shared_ptr<Timer>& timer);

private:
    TimerCore();
    void TimerLoop(const std::string& threadName);
    std::chrono::milliseconds GetNextExpirationTimeUnlocked();
    void DoTimeout();
    bool IsSameOwner(const std::shared_ptr<Timer>& lhs, const std::weak_ptr<Timer>& rhs);

    std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> active_{false};
    std::atomic<bool> resetTimer_{false};
    std::thread worker_{};
    std::priority_queue<uint64_t, std::vector<uint64_t>, std::greater<uint64_t>> timeline_;
    std::map<uint64_t, std::vector<std::weak_ptr<Timer>>> registeredTimers_{};
};
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PROCESSING_SERVICE_TIMER_CORE_H
