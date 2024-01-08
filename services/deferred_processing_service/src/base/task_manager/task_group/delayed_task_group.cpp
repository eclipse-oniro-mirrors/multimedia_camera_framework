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

#include "delayed_task_group.h"
#include "steady_clock.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
DelayedTaskGroup::DelayedTaskGroup(const std::string& name, TaskFunc func, const ThreadPool* threadPool)
    : BaseTaskGroup(name, std::move(func), true, threadPool), mutex_(), timeBroker_(nullptr), paramMap_()
{
    DP_DEBUG_LOG("(%s) entered.", GetName().c_str());
    Initialize();
}

DelayedTaskGroup::~DelayedTaskGroup()
{
    DP_DEBUG_LOG("(%s) entered.", GetName().c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    if (timeBroker_) {
        timeBroker_.reset();
    }
    paramMap_.clear();
}

void DelayedTaskGroup::Initialize()
{
    DP_DEBUG_LOG("(%s) Initialize entered.", GetName().c_str());
    BaseTaskGroup::Initialize();
    timeBroker_ = TimeBroker::Create("DelayedTaskGroup");
}

bool DelayedTaskGroup::SubmitTask(std::any param)
{
    if (!param.has_value()) {
        DP_DEBUG_LOG("(%s) SubmitTask failed due to containing no parameter.", GetName().c_str());
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto&& [delayTimeMs, task] = std::any_cast<std::tuple<uint32_t, std::function<void()>>&&>(std::move(param));
    DP_DEBUG_LOG("(%s) SubmitTask, delayTimeMs %d ,expiring timestamp: %d",
        GetName().c_str(),
        static_cast<int>(delayTimeMs),
        static_cast<int>(SteadyClock::GetTimestampMilli() + delayTimeMs));
    uint32_t handle;
    auto ret = timeBroker_->RegisterCallback(delayTimeMs, [this](uint32_t handle) { TimerExpired(handle); }, handle);
    if (ret) {
        paramMap_.emplace(handle, std::move(task));
    } else {
        DP_ERR_LOG("(%s) SubmitTask failed due to RegisterCallback.", GetName().c_str());
    }
    return ret;
}
    
void DelayedTaskGroup::TimerExpired(uint32_t handle)
{
    DP_DEBUG_LOG("(%s) TimerExpired, handle = %d", GetName().c_str(), static_cast<int>(handle));
    std::lock_guard<std::mutex> lock(mutex_);
    if (paramMap_.count(handle) == 0) {
        DP_DEBUG_LOG("(%s) TimerExpired, handle = %d", GetName().c_str(), static_cast<int>(handle));
        return;
    }
    BaseTaskGroup::SubmitTask(std::move(paramMap_[handle]));
    paramMap_.erase(handle);
}
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
