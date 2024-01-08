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

#include "thread_pool.h"
#include <sys/time.h>
#include <algorithm>
#include "thread_utils.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
std::unique_ptr<ThreadPool> ThreadPool::Create(const std::string& name, uint32_t numThreads)
{
    auto pool = std::make_unique<ThreadPool>(name, numThreads);
    if (pool) {
        pool->Initialize();
    }
    return pool;
}

ThreadPool::ThreadPool(const std::string& name, uint32_t numThreads)
    : name_(name), numThreads_(numThreads), workers_(), isStopped_(false), mutex_(), taskCv_(), tasks_()
{
    if (numThreads_ == 0) {
        numThreads_ = 1;
    }
    numThreads_ = std::min(numThreads_, static_cast<uint32_t>(std::thread::hardware_concurrency()));
    DP_DEBUG_LOG("name: %s, numThreads, orig: %u, new: %u.", name.c_str(), numThreads, numThreads_);
}

ThreadPool::~ThreadPool()
{
    DP_DEBUG_LOG("name: %s.", name_.c_str());
    isStopped_ = true;
    taskCv_.notify_all();
    for (auto& threadInfo : workers_) {
        if (threadInfo.thread.joinable()) {
            DP_DEBUG_LOG("joining thread (%s).", threadInfo.name.c_str());
            threadInfo.thread.join();
        }
    }
}

void ThreadPool::Initialize()
{
    DP_DEBUG_LOG("entered.");
    workers_.reserve(numThreads_);
    std::string threadNamePrefix = "DPS_Worker_";
    for (uint32_t i = 0; i < numThreads_; ++i) {
        auto threadName = threadNamePrefix + std::to_string(i);
        workers_.emplace_back(threadName, [this, threadName]() { WorkerLoop(threadName); });
        SetThreadName(workers_.back().thread.native_handle(), workers_.back().name);
    }
    PrintThreadInfo();
}

void ThreadPool::WorkerLoop(const std::string& threadName)
{
    DP_DEBUG_LOG("(%s) entered.", threadName.c_str());
    while (!isStopped_.load()) {
        auto task = GetTask();
        if (task) {
            task();
        } else {
            DP_DEBUG_LOG("empty task.");
        }
    }
    DP_DEBUG_LOG("(%s) exited.", threadName.c_str());
}

void ThreadPool::BeginBackgroundTasks() const
{
    DP_DEBUG_LOG("entered.");
    for (auto& workerInfo : workers_) {
        SetThreadPriority(workerInfo.thread.native_handle(), PRIORITY_BACKGROUND);
    }
}

void ThreadPool::EndBackgroundTasks() const
{
    DP_DEBUG_LOG("entered.");
    for (auto& workerInfo : workers_) {
        SetThreadPriority(workerInfo.thread.native_handle(), PRIORITY_NORMAL);
    }
}

void ThreadPool::PrintThreadInfo()
{
    struct sched_param sch;
    int policy = -1;
    for (auto& workerInfo : workers_) {
        int ret = pthread_getschedparam(workerInfo.thread.native_handle(), &policy, &sch);
        if (ret == 0) {
            DP_DEBUG_LOG("thread (%s) priority: %d, policy = %d(0:OTHER, 1:FIFO, 2:RR)", workerInfo.name.c_str(),
                         sch.sched_priority, policy);
        } else {
            DP_DEBUG_LOG("thread (%s) pthread_getschedparam failed, ret = %d.", workerInfo.name.c_str(), ret);
        }
    }
}

ThreadPool::Task ThreadPool::GetTask() const
{
    std::unique_lock<std::mutex> lock(mutex_);
    taskCv_.wait(lock, [this] { return isStopped_.load() || !tasks_.empty(); });
    if (isStopped_.load()) {
        return {};
    }
    auto task = std::move(tasks_.front());
    tasks_.pop();
    return task;
}

bool ThreadPool::HasPendingTasks() const
{
    std::unique_lock<std::mutex> lock(mutex_);
    return !tasks_.empty();
}

bool ThreadPool::Submit(Task func) const
{
    DP_DEBUG_LOG("entered.");
    if (!isStopped_.load()) {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            tasks_.emplace([task = std::move(func)] { task(); });
        }
        taskCv_.notify_one();
    } else {
        DP_ERR_LOG("failed due to thread pool has been stopped.");
        return false;
    }
    return true;
}
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
