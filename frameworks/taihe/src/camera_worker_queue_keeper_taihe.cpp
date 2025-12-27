/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "camera_worker_queue_keeper_taihe.h"

#include "camera_utils_taihe.h"
namespace Ani {
namespace Camera {
constexpr uint64_t WORKER_TIMEOUT = 2000L;
constexpr int32_t WORKER_TASK_WAIT_COUNT_MAX = 1;
static std::mutex g_workerQueueKeeperMutex;
static std::shared_ptr<CameraTaiheWorkerQueueKeeper> g_WorkerQueueKeeper = nullptr;

void CameraTaiheWorkerQueueKeeper::WorkerQueueTasksResetCreateTimeNoLock(TaiheWorkerQueueTaskTimePoint timePoint)
{
    for (auto& task : workerQueueTasks_) {
        task->createTimePoint = timePoint;
        task->waitCount = 0;
    }
}

std::shared_ptr<CameraTaiheWorkerQueueKeeper> CameraTaiheWorkerQueueKeeper::GetInstance()
{
    CHECK_RETURN_RET(g_WorkerQueueKeeper != nullptr, g_WorkerQueueKeeper);
    std::lock_guard<std::mutex> lock(g_workerQueueKeeperMutex);
    CHECK_RETURN_RET(g_WorkerQueueKeeper != nullptr, g_WorkerQueueKeeper);

    g_WorkerQueueKeeper = std::make_shared<CameraTaiheWorkerQueueKeeper>();
    return g_WorkerQueueKeeper;
}

std::shared_ptr<TaiheWorkerQueueTask> CameraTaiheWorkerQueueKeeper::AcquireWorkerQueueTask(const std::string& taskName)
{
    auto queueTask = std::make_shared<TaiheWorkerQueueTask>(taskName);
    std::lock_guard<std::mutex> lock(workerQueueTaskMutex_);
    workerQueueTasks_.push_back(queueTask);
    return queueTask;
}

bool CameraTaiheWorkerQueueKeeper::WorkerLockCondition(std::shared_ptr<TaiheWorkerQueueTask> queueTask, bool& isError)
{
    std::lock_guard<std::mutex> lock(workerQueueTaskMutex_);
    if (std::find(workerQueueTasks_.begin(), workerQueueTasks_.end(), queueTask) == workerQueueTasks_.end()) {
        MEDIA_ERR_LOG("CameraTaiheWorkerQueueKeeper::WorkerLockCondition current task %{public}s not in queue",
            queueTask->taskName.c_str());
        isError = true;
        return true;
    }
    auto firstTask = workerQueueTasks_.front();
    CHECK_RETURN_RET(firstTask == queueTask, true);
    CHECK_RETURN_RET(firstTask->queueStatus == RUNNING, false);
    auto now = std::chrono::steady_clock::now();
    auto diffTime = std::chrono::duration_cast<std::chrono::milliseconds>(now - firstTask->createTimePoint);
    CHECK_RETURN_RET(diffTime < std::chrono::milliseconds(WORKER_TIMEOUT), false);
    if (queueTask->waitCount < WORKER_TASK_WAIT_COUNT_MAX) {
        queueTask->waitCount++;
        return false;
    }
    MEDIA_ERR_LOG("CameraTaiheWorkerQueueKeeper::WorkerLockCondition current task %{public}s wait queue task %{public}s"
                  "timeout, waitTime:%{public}lld",
        queueTask->taskName.c_str(), firstTask->taskName.c_str(), diffTime.count());
    workerQueueTasks_.pop_front();
    CHECK_RETURN_RET_ELOG(workerQueueTasks_.empty(), false, "workerQueueTasks is empty.");
    auto frontTask = workerQueueTasks_.front();
    CHECK_RETURN_RET(frontTask == queueTask, true);
    MEDIA_INFO_LOG("CameraTaiheWorkerQueueKeeper::WorkerLockCondition current task not equal front task,%{public}s "
                   "vs %{public}s, continue wait.",
        queueTask->taskName.c_str(), frontTask->taskName.c_str());
    WorkerQueueTasksResetCreateTimeNoLock(now);
    workerCond_.notify_all();
    return false;
}

bool CameraTaiheWorkerQueueKeeper::ConsumeWorkerQueueTask(
    std::shared_ptr<TaiheWorkerQueueTask> queueTask, std::function<void(void)> func)
{
    CHECK_RETURN_RET(queueTask == nullptr, false);
    std::unique_lock<std::mutex> lock(workerQueueMutex_);
    {
        std::lock_guard<std::mutex> lock(workerQueueTaskMutex_);
        CHECK_RETURN_RET(workerQueueTasks_.empty(), false);
        CHECK_RETURN_RET(
            std::find(workerQueueTasks_.begin(), workerQueueTasks_.end(), queueTask) == workerQueueTasks_.end(), false);
    }
    bool isMatchCondition = false;
    bool isError = false;
    while (!isMatchCondition) {
        isMatchCondition = workerCond_.wait_for(lock, std::chrono::milliseconds(WORKER_TIMEOUT),
            [this, &queueTask, &isError]() { return WorkerLockCondition(queueTask, isError); });
    }
    if (isError) {
        MEDIA_ERR_LOG("CameraTaiheWorkerQueueKeeper::ConsumeWorkerQueueTask wait task %{public}s occur error",
            queueTask->taskName.c_str());
        workerCond_.notify_all();
        return false;
    }
    queueTask->queueStatus = RUNNING;
    func();
    queueTask->queueStatus = DONE;
    {
        auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lock(workerQueueTaskMutex_);
        workerQueueTasks_.pop_front();
        WorkerQueueTasksResetCreateTimeNoLock(now);
    }

    workerCond_.notify_all();
    return true;
}
} // namespace Camera
} // namespace Ani