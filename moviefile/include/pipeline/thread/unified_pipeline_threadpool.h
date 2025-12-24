/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_UNIFIED_PIPELINE_THREADPOOL_H
#define OHOS_UNIFIED_PIPELINE_THREADPOOL_H

#include <atomic>
#include <future>
#include <list>
#include <memory>
#include <vector>

#include "unified_pipeline_worker_thread.h"

namespace OHOS {
namespace CameraStandard {

class UnifiedPipelineThreadpool : public WorkerThread::WorkerThreadStatusCallback,
                                  public std::enable_shared_from_this<UnifiedPipelineThreadpool> {
public:
    // Default thread size is 1
    explicit UnifiedPipelineThreadpool(size_t minThreads = 1, size_t maxThreads = 1);
    virtual ~UnifiedPipelineThreadpool();

    void OnIdle() override;

    template<typename F, typename... Args>
    auto Submit(F&& f, Args&&... args) -> std::shared_ptr<std::packaged_task<decltype(f(args...))()>>;

    void SetThreadCount(size_t min, size_t max);
    void Shutdown();

    inline int64_t GetTaskSize()
    {
        std::lock_guard<std::mutex> taskLock(workerMutex_);
        return tasks_.size();
    }

private:
    std::shared_ptr<WorkerThread> CreateWorkerNoLock();
    std::shared_ptr<WorkerThread> GetAnIdleWorkerNoLock();

    void HandleTaskWithThreadLeader();
    void HandleTask();

    std::mutex workerMutex_; // Lock for workers_ & tasks_
    std::vector<std::shared_ptr<WorkerThread>> workers_;
    std::list<std::shared_ptr<PipelineTask>> tasks_;
    std::atomic<bool> isShutdown_ = false;
    std::atomic<size_t> minThreads_ = 1;
    std::atomic<size_t> maxThreads_ = 1;
};

template<typename F, typename... Args>
auto UnifiedPipelineThreadpool::Submit(F&& f, Args&&... args)
    -> std::shared_ptr<std::packaged_task<decltype(f(args...))()>>
{
    using ReturnType = decltype(f(args...));
    auto task =
        std::make_shared<std::packaged_task<ReturnType()>>(std::bind(std::forward<F>(f), std::forward<Args>(args)...));
    {
        std::unique_lock<std::mutex> lock(workerMutex_);
        if (isShutdown_) {
            return nullptr;
        }
        tasks_.emplace_back(std::make_shared<PipelineTask>([task]() { (*task)(); }));
    }
    HandleTask();
    return task;
}
} // namespace CameraStandard
} // namespace OHOS

#endif // OHOS_UNIFIED_PIPELINE_THREADPOOL_H
