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

#ifndef OHOS_DEFERRED_PROCESSING_SERVICE_TIME_BROKER_H
#define OHOS_DEFERRED_PROCESSING_SERVICE_TIME_BROKER_H

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <vector>
#include "timer.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class TimeBroker : public std::enable_shared_from_this<TimeBroker> {
public:
    static std::shared_ptr<TimeBroker> Create(std::string name);
    explicit TimeBroker(std::string name);
    ~TimeBroker();
    void Initialize();
    bool RegisterCallback(uint32_t delayTimeMs, std::function<void(uint32_t handle)> timerCallback, uint32_t& handle);
    void DeregisterCallback(uint32_t handle);

private:
    struct TimerInfo {
        TimerInfo(uint32_t handle, uint64_t timestamp, std::function<void(uint32_t handle)> callback)
            : handle(handle), timestamp(timestamp), timerCallback(std::move(callback))
        {
        }
        uint32_t handle;
        uint64_t timestamp;
        std::function<void(uint32_t handle)> timerCallback;
    };
    bool GetNextHandle(uint32_t& handle);
    uint32_t GenerateHandle();
    void TimerExpired();
    bool RestartTimer(bool force = false);

    const std::string name_;
    std::mutex mutex_;
    std::shared_ptr<Timer> timer_;
    std::priority_queue<uint64_t, std::vector<uint64_t>, std::greater<uint64_t>> timeline_;
    std::map<uint32_t, std::shared_ptr<TimerInfo>> timerInfos_;
    std::map<uint64_t, std::vector<std::weak_ptr<TimerInfo>>> expiringTimers_;
    uint32_t preHandle_{0};
};
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PROCESSING_SERVICE_TIME_BROKER_H
