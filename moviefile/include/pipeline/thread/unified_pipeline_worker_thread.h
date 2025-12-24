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

#ifndef OHOS_UNIFIED_PIPELINE_WORKER_THREAD_H
#define OHOS_UNIFIED_PIPELINE_WORKER_THREAD_H

#include <functional>
#include <memory>
#include <mutex>

namespace OHOS {
namespace CameraStandard {

struct PipelineTask {
public:
    PipelineTask() {};
    PipelineTask(std::function<void()> fun) : func(fun) {};
    std::function<void()> func;
};
class WorkerThread {
public:
    class WorkerThreadStatusCallback {
    public:
        virtual ~WorkerThreadStatusCallback() = default;
        virtual void OnIdle() = 0;
    };

    explicit WorkerThread();

    ~WorkerThread();

    bool IsIdle();

    bool SubmitTask(std::shared_ptr<PipelineTask> task);

    void Shutdown();

    void SetStatusCallback(std::weak_ptr<WorkerThreadStatusCallback> statusCallback);

private:
    enum class ThreadStatus { INVALID, IDLE, READY, RUNNING, DONE };

    std::mutex workerMutex_;
    std::condition_variable workerCondition_;
    std::shared_ptr<PipelineTask> task_ = nullptr;
    std::atomic<ThreadStatus> threadStatus_ = ThreadStatus::INVALID;
    std::shared_ptr<std::thread> innerThread_;

    std::mutex statusCallbackMutex_;
    std::weak_ptr<WorkerThreadStatusCallback> statusCallback_;

    std::shared_ptr<WorkerThreadStatusCallback> GetStatusCallback();
};
} // namespace CameraStandard
} // namespace OHOS

#endif // OHOS_UNIFIED_PIPELINE_THREADPOOL_H
