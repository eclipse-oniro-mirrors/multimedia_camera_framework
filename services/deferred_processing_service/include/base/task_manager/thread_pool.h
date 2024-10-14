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

#ifndef OHOS_DEFERRED_PROCESSING_SERVICE_THREAD_POOL_H
#define OHOS_DEFERRED_PROCESSING_SERVICE_THREAD_POOL_H

#include <pthread.h>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class ThreadPool {
    using Task = std::function<void()>;

public:
    static std::unique_ptr<ThreadPool> Create(const std::string& name, uint32_t numThreads);
    ~ThreadPool();
    void BeginBackgroundTasks() const;
    void EndBackgroundTasks() const;
    bool HasPendingTasks() const;
    bool Submit(Task func) const;

private:
    struct ThreadInfo {
        std::string name;
        mutable std::thread thread;

        ThreadInfo(std::string name, std::function<void()> func)
            : name(std::move(name)), thread(std::move(func))
        {
        }

        ThreadInfo(ThreadInfo&& other)
        {
            name = std::move(other.name);
            thread = std::move(other.thread);
        }

        ThreadInfo& operator=(ThreadInfo&& other)
        {
            if (this != &other) {
                name = std::move(other.name);
                thread = std::move(other.thread);
            }
            return *this;
        }
        ~ThreadInfo() = default;
        /* data */
    };

    friend std::unique_ptr<ThreadPool> std::make_unique<ThreadPool>(const std::string&, uint32_t&);
    ThreadPool(const std::string& name, uint32_t numThreads);
    void Initialize();
    void WorkerLoop(const std::string& threadName);
    void PrintThreadInfo();
    Task GetTask() const;

    const std::string name_;
    uint32_t numThreads_;
    std::vector<ThreadInfo> workers_;
    mutable std::atomic<bool> isStopped_;
    mutable std::mutex mutex_;
    mutable std::condition_variable taskCv_;
    mutable std::queue<Task> tasks_;
};
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PROCESSING_SERVICE_THREAD_POOL_H
