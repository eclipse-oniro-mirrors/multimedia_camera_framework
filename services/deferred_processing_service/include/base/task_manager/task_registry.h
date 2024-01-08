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

#ifndef OHOS_DEFERRED_PROCESSING_SERVICE_TASK_REGISTRY_H
#define OHOS_DEFERRED_PROCESSING_SERVICE_TASK_REGISTRY_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>

#include "thread_pool.h"
#include "itask_group.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class TaskRegistry final {
public:
    TaskRegistry(const std::string& name, const ThreadPool* threadPool);
    ~TaskRegistry();
    bool RegisterTaskGroup(const std::string& name, TaskFunc func, bool serial, bool delayTask,
        TaskGroupHandle& handle);
    bool DeregisterTaskGroup(const std::string& name, TaskGroupHandle& handle);
    bool SubmitTask(TaskGroupHandle handle, std::any param);

private:

    bool IsTaskGroupAlreadyRegistered(const std::string& name);

    const std::string name_;
    const ThreadPool* threadPool_;
    std::mutex mutex_;
    std::map<TaskGroupHandle, std::shared_ptr<ITaskGroup>> registry_;
};
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PROCESSING_SERVICE_TASK_REGISTRY_H
