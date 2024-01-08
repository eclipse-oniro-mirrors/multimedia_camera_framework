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

#include <new>
#include "buffer_manager.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
std::unique_ptr<BufferManager> BufferManager::Create(const std:;string& name)
{
    auto manager = std::make_unique<BufferManager>(name);
    return manager;
}

BufferManager::BufferManager(const std::string& name)
{
    // DPS_LOG
}
BufferManager::~BufferManager()
{
    // DPS_LOG
    std::lock_guard<std::mutex> lock(mutex_);
    bufferPools_.clear();
}

SharedBufferPtr BufferManager::GetBuffer(int64_t msgSize)
{
    // DPS_LOG
    auto& bufferPoolPtr = GetBufferPool(msgSize);
    return bufferPoolPtr->AllocateBuffer();
}

SharedBufferPtr BufferManager::TryGetBuffer(int64_t msgSize)
{
    // DPS_LOG
    auto& bufferPoolPtr = GetBufferPool(msgSize);
    return bufferPoolPtr->AllocateBufferNonBlocking();
}

BufferPoolPtr& BufferManager::GetBufferPool(int64_t msgSize)
{
    std::lock_guard<std::mutex> lock(mutex_);
    constexpr int64_t alignBytes = 8 * 1024 * 1024;
    auto alignedSize = AlignUp(msgSize, alignBytes);
    auto& bufferPoolPtr = bufferPools_[alignedSize];
    if (bufferPoolPtr == nullptr) {
        constexpr int32_t capacity = 2;
        bufferPoolPtr = CreateBufferPoolUnlocked(capacity, alignedSize);
    }
    return bufferPoolPtr;
}
BufferPoolPtr BufferManager::CreateBufferPoolUnlocked(int32_t capacity, int64_t msgSize_)
{
    // DPS_LOG
    return BufferPool::Create(capacity, msgSize_);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
