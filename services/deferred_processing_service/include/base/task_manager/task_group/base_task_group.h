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

#ifndef OHOS_DEFERRED_PROCESSING_SERVICE_BASE_TASK_GROUP_H
#define OHOS_DEFERRED_PROCESSING_SERVICE_BASE_TASK_GROUP_H

#include <any>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include "itask_group.h"
#include "blocking_queue.h"
#include "thread_pool.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class BaseTaskGroup : public ITaskGroup, public std::enable_shared_from_this<BaseTaskGroup> {
public:
    BaseTaskGroup(const std::string& name, TaskFunc func, bool serial, const ThreadPool* threadPool);
    ~BaseTaskGroup() override;
    const std::string& GetName() final;
    TaskGroupHandle GetHandle() final;
    bool SubmitTask(std::any param) override;

protected:
    virtual void Initialize();
    std::function<void()> GetTaskUnlocked();
    TaskGroupHandle GenerateHandle();
    void DispatchTaskUnlocked();
    virtual void OnTaskComplete();

private:
    std::mutex mutex_;
    const std::string name_;
    const TaskFunc func_;
    const bool serial_;
    const ThreadPool* threadPool_;
    TaskGroupHandle handle_;
    std::atomic<bool> inflight_;
    BlockingQueue<std::any> que_;
};
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PROCESSING_SERVICE_BASE_TASK_GROUP_H
