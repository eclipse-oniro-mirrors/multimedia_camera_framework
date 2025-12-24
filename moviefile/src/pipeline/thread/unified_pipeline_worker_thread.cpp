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

#include "unified_pipeline_worker_thread.h"
#include "camera_log.h"

#include <memory>
#include <mutex>
#include <thread>
#include <utility>

namespace OHOS {
namespace CameraStandard {
WorkerThread::WorkerThread()
{
    innerThread_ = std::make_shared<std::thread>([this]() {
        std::shared_ptr<PipelineTask> threadInnerTask = nullptr;
        {
            std::unique_lock<std::mutex> lock(workerMutex_);
            threadStatus_ = ThreadStatus::IDLE;
            workerCondition_.notify_one();
        }
        while (threadStatus_ != ThreadStatus::DONE) {
            {
                std::unique_lock<std::mutex> lock(workerMutex_);
                workerCondition_.wait(lock,
                    [this] { return threadStatus_ == ThreadStatus::READY || threadStatus_ == ThreadStatus::DONE; });
                CHECK_RETURN(threadStatus_ == ThreadStatus::DONE);
                threadStatus_ = ThreadStatus::RUNNING;
                threadInnerTask = task_;
            }
            if (threadInnerTask && threadInnerTask->func) {
                threadInnerTask->func();
                threadInnerTask = nullptr;
            }
            {
                std::lock_guard<std::mutex> lock(workerMutex_);
                CHECK_RETURN(threadStatus_ == ThreadStatus::DONE);
                threadStatus_ = ThreadStatus::IDLE;
            }
            auto callback = GetStatusCallback();
            if (callback) {
                callback->OnIdle();
            }
        }
    });
    std::unique_lock<std::mutex> lock(workerMutex_);
    workerCondition_.wait(lock, [this] { return threadStatus_ == ThreadStatus::IDLE; });
}

WorkerThread::~WorkerThread()
{
    Shutdown();
}

bool WorkerThread::IsIdle()
{
    // Do not lock threadStatus_ here
    return threadStatus_ == ThreadStatus::IDLE;
}

bool WorkerThread::SubmitTask(std::shared_ptr<PipelineTask> task)
{
    CHECK_RETURN_RET(!IsIdle(), false);
    // Double-check threadStatus_ to prevent thread queuing and blocking.
    std::lock_guard<std::mutex> lock(workerMutex_);
    CHECK_RETURN_RET(threadStatus_ != ThreadStatus::IDLE, false);
    threadStatus_ = ThreadStatus::READY;
    task_ = task;
    workerCondition_.notify_one();
    return true;
}

void WorkerThread::Shutdown()
{
    {
        std::lock_guard<std::mutex> lock(workerMutex_);
        threadStatus_ = ThreadStatus::DONE;
        workerCondition_.notify_one();
    }
    if (innerThread_ && innerThread_->joinable()) {
        innerThread_->join();
    }
}

void WorkerThread::SetStatusCallback(std::weak_ptr<WorkerThreadStatusCallback> statusCallback)
{
    std::lock_guard<std::mutex> lock(statusCallbackMutex_);
    statusCallback_ = statusCallback;
}

std::shared_ptr<WorkerThread::WorkerThreadStatusCallback> WorkerThread::GetStatusCallback()
{
    std::lock_guard<std::mutex> lock(statusCallbackMutex_);
    return statusCallback_.lock();
}

} // namespace CameraStandard
} // namespace OHOS