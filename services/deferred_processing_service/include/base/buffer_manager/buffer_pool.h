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

#ifndef OHOS_DEFERRED_PROCESSING_SERVICE_BUFFER_POOL_H
#define OHOS_DEFERRED_PROCESSING_SERVICE_BUFFER_POOL_H

#include <atomic>
#include <condition_variable>
#include <list>
#include <memory>
#include <mutex>
#include "SharedBuffer.h"
#include "base/timer/timer_broker.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class BufferPool : public std::enable_shared_from_this<BufferPool> {
public:
    static std::shared_ptr<BufferPool> Create(int32_t capacity, int64_t msgSize);
    BufferPool(int32_t capacity, int64_t msgSize);
    ~BufferPool();
    bool Initialize();
    void SetActive(bool active);
    int32_t GetSize();
    int32_t GetCapacity();
    bool Empty();
    void RecycleBuffer(std::unique_ptr<SharedBuffer> buffer);
    SharedBufferPtr AllocateBuffer();
    SharedBufferPtr AllocateBufferNonBlocking();

private:
    bool HasMoreBuffersUnlocked();
    bool CanExpandBufferUnlocked();
    void ExpandBufferUnlocked();
    SharedBufferPtr AllocateBufferUnlocked();
    void StartDecayTimerUnlocked(SharedBuffer* bufferPtr);
    void StopDecayTimerUnlocked(SharedBuffer* bufferPtr);
    void FreePhysicalMemory(uint32_t handle);

    const int32_t capacity_;
    const int64_t msgSize_;
    const int64_t msgSizeAligned_;

    std::mutex mutex_;
    std::condition_variable cv_;
    std::condition_variable cvFinishAlloc_;
    std::list<std::unique_ptr<SharedBuffer>> freeBuffers_;

    std::atomic<bool> initialized_;
    std::atomic<bool> isActive_;
    std::atomic<bool> allocInProgress_;
    std::atomic<int32_t> usedBufferNum_;
    std::shared_ptr<TimeBroker> timeBroker_;
    std::map<SharedBuffer*, uint32_t> decayingBuffers_;
};
using BufferPoolPtr = std::shared_ptr<BufferPool>;
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PROCESSING_SERVICE_BUFFER_POOL_H
