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

#include "task_registry.h"
#include "delayed_task_group.h"
#include "task_group.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
TaskRegistry::TaskRegistry(const std::string& name, const ThreadPool* threadPool)
    : name_(name), threadPool_(threadPool), mutex_(), registry_()
{
    DP_DEBUG_LOG("name: %s.", name.c_str());
}

TaskRegistry::~TaskRegistry()
{
    DP_DEBUG_LOG("name: %s.", name_.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    registry_.clear();
}

bool TaskRegistry::RegisterTaskGroup(const std::string& name, TaskFunc func, bool serial, bool delayTask,
    TaskGroupHandle& handle)
{
    DP_DEBUG_LOG("name: %s, serial: %d, delayTask: %d.", name.c_str(), serial, delayTask);
    if (IsTaskGroupAlreadyRegistered(name)) {
        DP_DEBUG_LOG("failed, task group (%s) already existed!", name.c_str());
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    std::shared_ptr<ITaskGroup> taskGroup = [delayTask, &name, func = std::move(func), serial, pool = threadPool_] () {
        if (delayTask) {
            std::shared_ptr<ITaskGroup> ret = std::make_shared<DelayedTaskGroup>(name, std::move(func), pool);
            return ret;
        } else {
            std::shared_ptr<ITaskGroup> ret = std::make_shared<TaskGroup>(name, std::move(func), serial, pool);
            return ret;
        }
    }();
    handle = taskGroup->GetHandle();
    registry_.emplace(handle, taskGroup);
    return true;
}

bool TaskRegistry::DeregisterTaskGroup(const std::string& name, TaskGroupHandle& handle)
{
    DP_DEBUG_LOG("name: %s.", name.c_str());
    if (!IsTaskGroupAlreadyRegistered(name)) {
        DP_DEBUG_LOG("name: %s, with handle:%d, failed due to non exist task group!",
            name.c_str(), static_cast<int>(handle));
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = registry_.find(handle);
    if (it == registry_.end()) {
        DP_DEBUG_LOG("name: %s, handle:%d failed due to non-existent task group!",
            name.c_str(), static_cast<int>(handle));
        return false;
    }
    registry_.erase(it);
    return true;
}

bool TaskRegistry::SubmitTask(TaskGroupHandle handle, std::any param)
{
    DP_DEBUG_LOG("submit one task to %d", static_cast<int>(handle));
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = registry_.find(handle);
    if (it == registry_.end()) {
        DP_DEBUG_LOG("failed due to task group %d non-exist!", static_cast<int>(handle));
        return false;
    }
    return it->second->SubmitTask(std::move(param));
}

bool TaskRegistry::IsTaskGroupAlreadyRegistered(const std::string& name)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = registry_.begin(); it != registry_.end(); ++it) {
        if (it->second->GetName() == name) {
            DP_DEBUG_LOG("task group (%s) had registered.", name.c_str());
            return true;
        }
    }
    DP_DEBUG_LOG("task group (%s) hasn't been registered.", name.c_str());
    return false;
}
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
