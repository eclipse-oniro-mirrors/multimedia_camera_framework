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

#include <tuple>

#include "task_manager.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
TaskManager::TaskManager(const std::string& name, uint32_t  numThreads)
    : name_(name),
      numThreads_(numThreads),
      pool_(nullptr),
      taskRegistry_(nullptr),
      defaultTaskHandle_(INVALID_TASK_GROUP_HANDLE),
      delayedTaskHandle_(INVALID_TASK_GROUP_HANDLE)
{
    DP_INFO_LOG("name: %s, maxThreads: %d.", name.c_str(), numThreads);
    Initialize();
}

void TaskManager::Initialize()
{
    DP_INFO_LOG("entered.");
    pool_ = ThreadPool::Create(name_, numThreads_);
    taskRegistry_ = std::make_unique<TaskRegistry>(name_, pool_.get());
    auto ret = RegisterTaskGroup("defaultTaskGroup",
        [this](std::any param) { DoDefaultWorks(std::move(param)); }, true, false, defaultTaskHandle_);
    DP_INFO_LOG("register default task group: %d, handle: %d", ret, static_cast<int>(defaultTaskHandle_));
    (void)(ret);
    return;
}

TaskManager::~TaskManager()
{
    DP_INFO_LOG("name: %s.", name_.c_str());
    DeregisterTaskGroup("defaultTaskGroup", defaultTaskHandle_);
    defaultTaskHandle_ = INVALID_TASK_GROUP_HANDLE;
    if (delayedTaskHandle_ != INVALID_TASK_GROUP_HANDLE) {
        DeregisterTaskGroup("delayedTaskGroup", delayedTaskHandle_);
        delayedTaskHandle_ = INVALID_TASK_GROUP_HANDLE;
    }
    pool_.reset();
    taskRegistry_.reset();
}

void TaskManager::CreateDelayedTaskGroupIfNeed()
{
    if (delayedTaskHandle_ != INVALID_TASK_GROUP_HANDLE) {
        return;
    } else {
        RegisterTaskGroup("delayedTaskGroup",
            [this](std::any param) { DoDefaultWorks(std::move(param)); }, true, true, delayedTaskHandle_);
    }
    return;
}

void TaskManager::BeginBackgroundTasks()
{
    DP_INFO_LOG("name: %s.", name_.c_str());
}

void TaskManager::EndBackgroundTasks()
{
    DP_INFO_LOG("name: %s.", name_.c_str());
}

bool TaskManager::RegisterTaskGroup(const std::string& name, TaskFunc func, bool serial, TaskGroupHandle& handle)
{
    return RegisterTaskGroup(name, std::move(func), serial, false, handle);
}

bool TaskManager::DeregisterTaskGroup(const std::string& name, TaskGroupHandle& handle)
{
    bool ret = false;
    if (taskRegistry_) {
        ret = taskRegistry_->DeregisterTaskGroup(name, handle);
        DP_INFO_LOG("deregister task group: %s, ret: %d", name.c_str(), ret);
    } else {
        DP_INFO_LOG("invalid ptr");
    }
    return ret;
}

bool TaskManager::SubmitTask(std::function<void()> task)
{
    return SubmitTask(defaultTaskHandle_, std::move(task));
}

bool TaskManager::SubmitTask(std::function<void()> task, uint32_t delayMilli)
{
    CreateDelayedTaskGroupIfNeed();
    return SubmitTask(delayedTaskHandle_, std::make_tuple(delayMilli, std::move(task)));
}

bool TaskManager::SubmitTask(TaskGroupHandle handle, std::any param)
{
    DP_INFO_LOG("submit task to handle: %d", static_cast<int>(handle));
    if (taskRegistry_ == nullptr) {
        DP_ERR_LOG("invalid ptr");
        return false;
    }
    return taskRegistry_->SubmitTask(handle, std::move(param));
}


bool TaskManager::RegisterTaskGroup(const std::string& name, TaskFunc func, bool serial, bool delayTask,
    TaskGroupHandle& handle)
{
    bool ret = false;
    if (taskRegistry_) {
        ret = taskRegistry_->RegisterTaskGroup(name, func, serial, delayTask, handle);
    }
    return ret;
}

void TaskManager::DoDefaultWorks(std::any param)
{
    auto task = std::any_cast<std::function<void()>&&>(std::move(param));
    if (task) {
        task();
    }
}
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
