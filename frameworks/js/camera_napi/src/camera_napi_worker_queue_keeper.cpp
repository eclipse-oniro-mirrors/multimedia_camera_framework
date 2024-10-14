/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "camera_napi_worker_queue_keeper.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <new>

#include "camera_log.h"
#include "camera_napi_const.h"
#include "camera_napi_utils.h"
namespace OHOS {
namespace CameraStandard {
constexpr uint64_t WORKER_TIMEOUT = 2000L;
constexpr int32_t WORKER_TASK_WAIT_COUNT_MAX = 1;
static std::mutex g_WorkerQueueKeeperMutex;
static std::shared_ptr<CameraNapiWorkerQueueKeeper> g_WorkerQueueKeeper = nullptr;

void CameraNapiWorkerQueueKeeper::WorkerQueueTasksResetCreateTimeNoLock(NapiWorkerQueueTaskTimePoint timePoint)
{
    for (auto& task : workerQueueTasks_) {
        task->createTimePoint = timePoint;
        task->waitCount = 0;
    }
}

std::shared_ptr<CameraNapiWorkerQueueKeeper> CameraNapiWorkerQueueKeeper::GetInstance()
{
    if (g_WorkerQueueKeeper != nullptr) {
        return g_WorkerQueueKeeper;
    }
    std::lock_guard<std::mutex> lock(g_WorkerQueueKeeperMutex);
    if (g_WorkerQueueKeeper != nullptr) {
        return g_WorkerQueueKeeper;
    }

    g_WorkerQueueKeeper = std::make_shared<CameraNapiWorkerQueueKeeper>();
    return g_WorkerQueueKeeper;
}

std::shared_ptr<NapiWorkerQueueTask> CameraNapiWorkerQueueKeeper::AcquireWorkerQueueTask(const std::string& taskName)
{
    auto queueTask = std::make_shared<NapiWorkerQueueTask>(taskName);
    std::lock_guard<std::mutex> lock(workerQueueTaskMutex_);
    workerQueueTasks_.push_back(queueTask);
    return queueTask;
}

bool CameraNapiWorkerQueueKeeper::WorkerLockCondition(std::shared_ptr<NapiWorkerQueueTask> queueTask, bool& isError)
{
    std::lock_guard<std::mutex> lock(workerQueueTaskMutex_);
    if (std::find(workerQueueTasks_.begin(), workerQueueTasks_.end(), queueTask) == workerQueueTasks_.end()) {
        MEDIA_ERR_LOG("CameraNapiWorkerQueueKeeper::WorkerLockCondition current task %{public}s not in queue",
            queueTask->taskName.c_str());
        isError = true;
        return true;
    }
    auto firstTask = workerQueueTasks_.front();
    if (firstTask == queueTask) {
        return true;
    }
    if (firstTask->queueStatus == RUNNING) {
        return false;
    }
    auto now = std::chrono::steady_clock::now();
    auto diffTime = std::chrono::duration_cast<std::chrono::milliseconds>(now - firstTask->createTimePoint);
    if (diffTime < std::chrono::milliseconds(WORKER_TIMEOUT)) {
        return false;
    }
    if (queueTask->waitCount < WORKER_TASK_WAIT_COUNT_MAX) {
        queueTask->waitCount++;
        return false;
    }
    MEDIA_ERR_LOG("CameraNapiWorkerQueueKeeper::WorkerLockCondition current task %{public}s wait queue task %{public}s "
                  "timeout, waitTime:%{public}lld",
        queueTask->taskName.c_str(), firstTask->taskName.c_str(), diffTime.count());
    workerQueueTasks_.pop_front();
    auto frontTask = workerQueueTasks_.front();
    if (frontTask == queueTask) {
        return true;
    }
    MEDIA_INFO_LOG("CameraNapiWorkerQueueKeeper::WorkerLockCondition current task not equal front task,%{public}s "
                   "vs %{public}s, continue wait.",
        queueTask->taskName.c_str(), frontTask->taskName.c_str());
    WorkerQueueTasksResetCreateTimeNoLock(now);
    workerCond_.notify_all();
    return false;
}

bool CameraNapiWorkerQueueKeeper::ConsumeWorkerQueueTask(
    std::shared_ptr<NapiWorkerQueueTask> queueTask, std::function<void(void)> func)
{
    if (queueTask == nullptr) {
        return false;
    }
    std::unique_lock<std::mutex> lock(workerQueueMutex_);
    {
        std::lock_guard<std::mutex> lock(workerQueueTaskMutex_);
        CHECK_ERROR_RETURN_RET(workerQueueTasks_.empty(), false);
        CHECK_ERROR_RETURN_RET(
            std::find(workerQueueTasks_.begin(), workerQueueTasks_.end(), queueTask) == workerQueueTasks_.end(), false);
    }
    bool isMatchCondition = false;
    bool isError = false;
    while (!isMatchCondition) {
        isMatchCondition = workerCond_.wait_for(lock, std::chrono::milliseconds(WORKER_TIMEOUT),
            [this, &queueTask, &isError]() { return WorkerLockCondition(queueTask, isError); });
    }
    if (isError) {
        MEDIA_ERR_LOG("CameraNapiWorkerQueueKeeper::ConsumeWorkerQueueTask wait task %{public}s occur error",
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
} // namespace CameraStandard
} // namespace OHOS