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

#include <memory>
#include <mutex>
#include <new>

#include "camera_log.h"
#include "camera_napi_const.h"
#include "camera_napi_utils.h"

namespace OHOS {
namespace CameraStandard {
static std::mutex g_WorkerQueueKeeperMutex;
static std::shared_ptr<CameraNapiWorkerQueueKeeper> g_WorkerQueueKeeper = nullptr;
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

void CameraNapiWorkerQueueKeeper::AcquireWorkerQueueId(uint64_t& queueId)
{
    std::lock_guard<std::mutex> lock(workerQueueIdMutex_);
    workerQueueId_++;
    queueId = workerQueueId_;
    workerQueueIds_.push_back(queueId);
}

bool CameraNapiWorkerQueueKeeper::ConsumeWorkerQueueId(uint64_t queueId, std::function<void(void)> func)
{
    {
        std::lock_guard<std::mutex> lock(workerQueueIdMutex_);
        CHECK_ERROR_RETURN_RET(workerQueueIds_.empty(), false);
        CHECK_ERROR_RETURN_RET(
            std::find(workerQueueIds_.begin(), workerQueueIds_.end(), queueId) == workerQueueIds_.end(), false);
    }

    std::unique_lock<std::mutex> lock(workerQueueMutex_);
    workerCond_.wait(lock, [this, &queueId]() {
        {
            std::lock_guard<std::mutex> lock(workerQueueIdMutex_);
            if (workerQueueIds_.front() != queueId) {
                return false;
            }
            workerQueueIds_.pop_front();
            return true;
        }
    });
    func();
    workerCond_.notify_all();
    return true;
}
} // namespace CameraStandard
} // namespace OHOS