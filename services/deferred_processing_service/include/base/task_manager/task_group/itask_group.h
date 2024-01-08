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

#ifndef OHOS_DEFERRED_PROCESSING_SERVICE_I_TASK_GROUP_H
#define OHOS_DEFERRED_PROCESSING_SERVICE_I_TASK_GROUP_H

#include <any>
#include <cstdint>
#include <functional>
#include <string>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
using TaskGroupHandle = uint64_t;
using TaskFunc = std::function<void(std::any param)>;
using TaskCallback = std::function<void(std::any param)>;

class ITaskGroup {
public:
    ITaskGroup() = default;
    virtual ~ITaskGroup() = default;
    virtual const std::string& GetName() = 0;
    virtual TaskGroupHandle GetHandle() = 0;
    virtual bool SubmitTask(std::any param) = 0;
};
constexpr TaskGroupHandle INVALID_TASK_GROUP_HANDLE = 0;
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PROCESSING_SERVICE_I_TASK_GROUP_H
