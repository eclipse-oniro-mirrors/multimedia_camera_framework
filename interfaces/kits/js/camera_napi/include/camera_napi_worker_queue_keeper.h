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

#ifndef CAMERA_NAPI_WORKER_QUEUE_KEEPER
#define CAMERA_NAPI_WORKER_QUEUE_KEEPER

#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <mutex>

#include "camera_napi_const.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "napi/native_api.h"

namespace OHOS {
namespace CameraStandard {
class CameraNapiWorkerQueueKeeper {
public:
    explicit CameraNapiWorkerQueueKeeper() = default;
    virtual ~CameraNapiWorkerQueueKeeper() = default;
    static std::shared_ptr<CameraNapiWorkerQueueKeeper> GetInstance();

    std::shared_ptr<NapiWorkerQueueTask> AcquireWorkerQueueTask(const std::string& taskName);
    bool ConsumeWorkerQueueTask(std::shared_ptr<NapiWorkerQueueTask> queueTask, std::function<void(void)> func);

private:
    void WorkerQueueTasksResetCreateTimeNoLock(NapiWorkerQueueTaskTimePoint timePoint);
    bool WorkerLockCondition(std::shared_ptr<NapiWorkerQueueTask> queueTask, bool& isError);

    std::mutex workerQueueMutex_;
    std::condition_variable workerCond_;

    std::mutex workerQueueTaskMutex_;
    std::list<std::shared_ptr<NapiWorkerQueueTask>> workerQueueTasks_;
};
} // namespace CameraStandard
} // namespace OHOS

#endif