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

#include "unified_pipeline_threadpool.h"

#include <memory>
#include <thread>
#include <utility>
#include <vector>

#include "camera_log.h"
#include "unified_pipeline_worker_thread.h"
namespace OHOS {
namespace CameraStandard {

void UnifiedPipelineThreadpool::OnIdle()
{
    HandleTask();
}

UnifiedPipelineThreadpool::UnifiedPipelineThreadpool(size_t minThreads, size_t maxThreads)
    : minThreads_(minThreads), maxThreads_(maxThreads)
{}

std::shared_ptr<WorkerThread> UnifiedPipelineThreadpool::CreateWorkerNoLock()
{
    auto worker = std::make_shared<WorkerThread>();
    worker->SetStatusCallback(weak_from_this());
    workers_.emplace_back(worker);
    return worker;
}

UnifiedPipelineThreadpool::~UnifiedPipelineThreadpool()
{
    Shutdown();
}

void UnifiedPipelineThreadpool::Shutdown()
{
    std::vector<std::shared_ptr<WorkerThread>> shutdownWorkers = {};
    {
        std::lock_guard<std::mutex> taskLock(workerMutex_);
        CHECK_RETURN(isShutdown_);
        isShutdown_ = true;
        size_t pendingTaskSize = tasks_.size();
        MEDIA_INFO_LOG(
            "UnifiedPipelineThreadpool::Shutdown drop task size:%{public}d", static_cast<uint32_t>(pendingTaskSize));
        shutdownWorkers = workers_;
    }
    for (auto& worker : shutdownWorkers) {
        worker->Shutdown();
    }
}

std::shared_ptr<WorkerThread> UnifiedPipelineThreadpool::GetAnIdleWorkerNoLock()
{
    for (auto& worker : workers_) {
        CHECK_RETURN_RET(worker->IsIdle(), worker);
    }
    std::shared_ptr<WorkerThread> idleWorker = nullptr;
    if (workers_.size() < maxThreads_) {
        idleWorker = CreateWorkerNoLock();
    }
    return idleWorker;
}

void UnifiedPipelineThreadpool::HandleTask()
{
    std::shared_ptr<PipelineTask> workerTask = nullptr;
    std::lock_guard<std::mutex> taskLock(workerMutex_);
    CHECK_RETURN(isShutdown_ || tasks_.empty());
    workerTask = tasks_.front();
    std::shared_ptr<WorkerThread> idleWorker = GetAnIdleWorkerNoLock();
    if (idleWorker != nullptr && idleWorker->SubmitTask(workerTask)) {
        tasks_.pop_front();
    } else {
        auto taskSize = tasks_.size();
        if (taskSize >= 10) { // if task size greater 10 , let's log some msg.
            MEDIA_WARNING_LOG(
                "UnifiedPipelineThreadpool::HandleTask no idle thread, wait... task size:%{public}zu", taskSize);
        }
    }
}

} // namespace CameraStandard
} // namespace OHOS