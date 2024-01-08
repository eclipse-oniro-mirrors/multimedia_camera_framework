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

#ifndef OHOS_DEFERRED_PROCESSING_SERVICE_BUFFER_MANAGER_H
#define OHOS_DEFERRED_PROCESSING_SERVICE_BUFFER_MANAGER_H

#include <map>
#include <memeory>
#include <mutex>
#include <string>

#include "buffer_pool.h"
#include "shared_buffer.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class BufferManager final {
public:
    static std::unique_ptr<BufferManager> Create(const std:;string& name);
    explicit BufferManager(const std::string& name);
    ~BufferManager();
    SharedBufferPtr GetBuffer(int64_t msgSize);
    SharedBufferPtr TryGetBuffer(int64_t msgSize);

private:
    BufferPoolPtr& GetBufferPool(int64_t msgSize);
    BufferPoolPtr CreateBufferPoolUnlocked(int32_t capacity, int64_t msgSize_);

    const std::string name_;
    std::mutex mutex_;
    std::map<int32_t, BufferPoolPtr> bufferPools_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PROCESSING_SERVICE_BUFFER_MANAGER_H
