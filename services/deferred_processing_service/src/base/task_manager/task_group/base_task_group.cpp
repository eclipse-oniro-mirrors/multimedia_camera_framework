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

#include "base_task_group.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
BaseTaskGroup::BaseTaskGroup(const std::string& name, TaskFunc func, bool serial, const ThreadPool* threadPool)
    : name_(name),
      func_(std::move(func)),
      serial_(serial),
      threadPool_(threadPool),
      handle_(INVALID_TASK_GROUP_HANDLE),
      inflight_(false),
      que_(name + " queue")
{
    DP_DEBUG_LOG("task group (%s).", name_.c_str());
}

BaseTaskGroup::~BaseTaskGroup()
{
    DP_DEBUG_LOG("task group name: %s, handle: %d", name_.c_str(), static_cast<int>(handle_));
    que_.SetActive(false);
    que_.Clear();
}

void BaseTaskGroup::Initialize()
{
    handle_ = GenerateHandle();
    que_.SetActive(true);
    DP_DEBUG_LOG("task group (%s), handle: %d", name_.c_str(), static_cast<int>(handle_));
}

const std::string& BaseTaskGroup::GetName()
{
    return name_;
}

TaskGroupHandle BaseTaskGroup::GetHandle()
{
    return handle_;
}

bool BaseTaskGroup::SubmitTask(std::any param)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (que_.Full()) {
        DP_WARNING_LOG("Submit task (%s), handle: %d, que is full!", name_.c_str(), static_cast<int>(handle_));
    } else {
        DP_DEBUG_LOG("Submit task (%s), handle: %d, size: %zu.", name_.c_str(),
            static_cast<int>(handle_), que_.Size());
    }
    que_.Push(std::move(param));
    DispatchTaskUnlocked();
    return true;
}

std::function<void()> BaseTaskGroup::GetTaskUnlocked()
{
    if (que_.Empty()) {
        DP_DEBUG_LOG("(%s) no available tasks.", name_.c_str());
        return {};
    }
    std::weak_ptr<BaseTaskGroup> weakThis(shared_from_this());
    auto task = [param = que_.Pop(), weakThis]() {
        auto thiz = weakThis.lock();
        if (thiz) {
            thiz->func_(std::move(param));
            thiz->OnTaskComplete();
        }
    };
    DP_DEBUG_LOG("return one task %s, handle:%d, size: %zu.", name_.c_str(), static_cast<int>(handle_), que_.Size());
    return task;
}

TaskGroupHandle BaseTaskGroup::GenerateHandle()
{
    static std::atomic<uint64_t> counter = 0;
    DP_DEBUG_LOG("(%s) entered.", name_.c_str());
    uint64_t prefix = std::hash<std::string>{}(name_);
    uint64_t handle = ++counter;
    return prefix | handle;
}

void BaseTaskGroup::DispatchTaskUnlocked()
{
    DP_DEBUG_LOG("(%s) entered.", name_.c_str());
    if (serial_ && inflight_.load()) {
        DP_DEBUG_LOG("(%s), task is running, redispatch tasks after finish running.", name_.c_str());
        return;
    }
    auto task = GetTaskUnlocked();
    if (task) {
        inflight_ = true;
        threadPool_->Submit([task = std::move(task)] { task(); });
    } else {
        DP_DEBUG_LOG("all tasks have completed for %s handle:%d.", name_.c_str(), static_cast<int>(handle_));
    }
}
void BaseTaskGroup::OnTaskComplete()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (serial_) {
        inflight_ = false;
    }
    DispatchTaskUnlocked();
}
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
