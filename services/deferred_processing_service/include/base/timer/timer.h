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

#ifndef OHOS_DEFERRED_PROCESSING_SERVICE_TIMER_H
#define OHOS_DEFERRED_PROCESSING_SERVICE_TIMER_H

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
using TimerCallback = std::function<void()>;

enum class TimerType {
    ONCE = 0,
    PERIODIC = 1
};

class TimerCore;

class Timer : public std::enable_shared_from_this<Timer> {
public:
    static std::shared_ptr<Timer> Create(const std::string& name, TimerType timerType,
        uint32_t intervalMs, TimerCallback callback);
    ~Timer();
    const std::string& GetName();
    bool Start(uint32_t delayTimeMs = 0);
    bool StartAt(uint64_t timestampMs);
    bool Stop();
    bool IsActive();

private:
    friend TimerCore;
    Timer(const std::string& name, TimerType timerType, uint32_t intervalMs, TimerCallback callback);
    bool Initialize();
    bool StartUnlocked(uint32_t delayTimeMs = 0);
    bool StartAtUnlocked(uint64_t timestampMs);
    void TimerExpired();

    std::mutex mutex_;
    bool active_{false};
    const std::string name_;
    const TimerType timerType_;
    const uint32_t intervalMs_;
    TimerCallback callback_;
    uint64_t expiredTimeMs_{0};
};
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PROCESSING_SERVICE_TIMER_H