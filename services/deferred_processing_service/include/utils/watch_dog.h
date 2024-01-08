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

#ifndef OHOS_DEFERRED_PROCESSING_SERVICE_WATCH_DOG_H
#define OHOS_DEFERRED_PROCESSING_SERVICE_WATCH_DOG_H

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include "time_broker.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class Watchdog {
public:
    explicit Watchdog(std::string name)
        : name_(std::move(name)), timeBroker_(TimeBroker::Create(name_))
    {
        DP_INFO_LOG("(%s) entered.", name_.c_str());
    }

    Watchdog(const Watchdog& other) = delete;

    Watchdog& operator=(const Watchdog& other) = delete;

    ~Watchdog()
    {
    }

    void StartMonitor(uint32_t& handle, uint32_t durationMs, std::function<void(uint32_t handle)> callback)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!timeBroker_) {
            DP_ERR_LOG("(%s) timerBroker_ nullptr.", name_.c_str());
            return;
        }
        bool ret = timeBroker_->RegisterCallback(durationMs,
        [callback = std::move(callback)](uint32_t handle) {callback(handle); }, handle);
        if (ret) {
            DP_INFO_LOG("(%s) handle = %d", name_.c_str(), handle);
        } else {
            DP_ERR_LOG("(%s) timerBroker_ RegisterCallback failed, status = %d.", name_.c_str(), ret);
        }
    }

    void StopMonitor(const uint32_t& handle)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (timeBroker_) {
            DP_INFO_LOG("(%s) handle = %d", name_.c_str(), handle);
            timeBroker_->DeregisterCallback(handle);
        } else {
            DP_ERR_LOG("(%s) failed", name_.c_str());
        }
    }

private:

    std::mutex mutex_;
    std::string name_;
    std::shared_ptr<TimeBroker> timeBroker_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PROCESSING_SERVICE_WATCH_DOG_H
