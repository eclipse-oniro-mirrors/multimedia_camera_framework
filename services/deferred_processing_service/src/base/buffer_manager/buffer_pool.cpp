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

#include "buffer_pool.h"
#include <new>

namespace OHOS {
namespace CameraStandard {
namespace {
    constexpr int64_t ALIGN_BYTES = 16;
}
namespace DeferredProcessing {
std::shared_ptr<BufferPool> BufferPool::Create(int32_t capacity, int64_t msgSize)
{
    // DPS_LOG
    auto pool = std::make_shared<BufferPool>(capacity, msgSize);
    if (pool && pool->Initialize()) {
        pool = nullptr;
    }
    return pool;
}

BufferPool::BufferPool(int32_t capacity, int64_t msgSize)
    : capacity_(capacity),
      msgSize_(msgSize),
      msgSizeAligned_(AlignUp(msgSize, ALIGN_BYTES)),
      initialized_(false),
      isActive_(true),
      allocInProgress_(false),
      usedBufferNum_(0),
      timeBroker_(nullptr),
      decayingBuffers_()
{
    // DPS_LOG
}

BufferPool::~BufferPool()
{
    std::unique_lock<std::mutex> lock(mutex_);
    // DPS_LOG
    initialized_ = false;
    isActive_ = false;
    cv_.notify_one();
    if (allocInProgress_.load()) {
        cvFinishAlloc_.wait(lock, [this] { return !allocInProgress_.load(); });
    }
    for (auto it = decayingBuffers_.begin(); it != decayingBuffers_.end(); ++it) {
        timeBroker_->DeregisterCallback(it->second);
    }
    decayingBuffers_.clear();
}

bool BufferPool::Initialize()
{
    std::unique_lock<std::mutex> lock(mutex_);
    // DPS_LOG
    if (initialized_) {
        return true;
    }
    if (capacity_ <= 0 || msgSize_ <= 0) {
        // DPS_LOG
        return false;
    }
    freeBuffers_.clear();
    ExpandBufferUnlocked();
    timerBroker_ = TimerBroker::Create("BufferTimeBroker");
    initialized_ = true;
    return true;
}
void BufferPool::SetActive(bool active)
{
    std::unique_lock<std::mutex> lock(mutex_);
    // DPS_LOG
    if (!initialized_) {
        // DPS_LOG
        return;
    }
    if (!active) {
        cv_.notify_one();
    }
    isActive_ = active;
}

int32_t BufferPool::GetSize()
{
    std::unique_lock<std::mutex> lock(mutex_);
    // DPS_LOG
    return static_cast<int32_t>(freeBuffers_.size());
}

int32_t BufferPool::GetCapacity()
{
    std::unique_lock<std::mutex> lock(mutex_);
    // DPS_LOG
    return capacity_;
}

bool BufferPool::Empty()
{
    std::unique_lock<std::mutex> lock(mutex_);
    // DPS_LOG
    return freeBuffers_.empty();
}

void BufferPool::RecycleBuffer(std::unique_ptr<SharedBuffer> buffer)
{
    std::unique_lock<std::mutex> lock(mutex_);
    // DPS_LOG
    buffer->Reset();
    StartDecayTimerUnlocked(buffer.get());
    freeBuffers_.emplace_back(std::move(buffer));
    --usedBufferNum_;
    cv_.notify_one();
}

SharedBufferPtr BufferPool::AllocateBuffer()
{
    std::unique_lock<std::mutex> lock(mutex_);
    // DPS_LOG
    allocInProgress_ = true;
    if (isActive_ && !HasMoreBuffersUnlocked()) {
        cv_.wait(lock, [this] { return !isActive_ || HasMoreBuffersUnlocked(); });
    }
    SharedBufferPtr buffer;
    if (isActive_) {
        buffer = AllocateBufferUnlocked();
    }
    allocInProgress_ = false;
    cvFinishAlloc_.notify_one();
    return buffer;
}
SharedBufferPtr BufferPool::AllocateBufferNonBlocking()
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (isActive_ && HasMoreBuffersUnlocked()) {
        return AllocateBufferUnlocked();
    }
    return nullptr;
}

bool BufferPool::HasMoreBuffersUnlocked()
{
    return !freeBuffers_.empty() || CanExpandBufferUnlocked();
}

bool BufferPool::CanExpandBufferUnlocked()
{
    auto size = static_cast<int32_t>(freeBuffers_.size());
    return (size + usedBufferNum_.load()) < capacity_;
}

void BufferPool::ExpandBufferUnlocked()
{
    // DPS_LOG
    if (isActive_ && CanExpandBufferUnlocked()) {
        auto bufferNmae = "BufferPool_" + std::to_string(msgSize_) + "_" + std::string(freeBuffers_.size());
        auto bufferPtr = SharedBuffer::Create(bufferNmae, msgSizeAligned_);
        if (bufferPtr) {
            freeBuffers_.emplace_back(std::move(bufferPtr));
        } else {
            // DPS_LOG
        }
    }
}

SharedBufferPtr BufferPool::AllocateBufferUnlocked()
{
    // DPS_LOG
    if (freeBuffers_.empty() && CanExpandBufferUnlocked()) {
        ExpandBufferUnlocked();
    }
    if (freeBuffers_.empty()) {
        // DPS_LOG
        return nullptr;
    }
    std::weak_ptr<BufferPool> weakRef(shared_from_this());
    std::shared_ptr<SharedBuffer> buffer(freeBuffers_.front().release(), [weakRef](SharedBuffer* ptr) {
        auto pool = weakRef.lock();
        if (pool) {
            pool->RecycleBuffer(std::unique_ptr<SharedBuffer>(ptr));
        } else {
            delete ptr;
        }
    });
    freeBuffers_.pop_front();
    ++usedBufferNum_;
    buffer->BeginAccess();
    StopDecayTimerUnlocked(buffer.get());
    return buffer;
}

void BufferPool::StartDecayTimerUnlocked(SharedBuffer* bufferPtr)
{
}

void BufferPool::StartDecayTimerUnlocked(SharedBuffer* bufferPtr)
{
    constexpr uint32_t delayTimeMs = 2 * 60 * 1000;
    uint32_t handle;
    std::weak_ptr<BufferPool> weakRef(shared_from_this());
    auto ret = timeBroker_->RegisterCallback(
        delayTimeMs,
        [weakRef](uint32_t handle) {
            if (auto pool = weakRef.lock()) {
                pool->FreePhysicalMemory(handle);
            }
        },
        handle);
    if (ret) {
        // DPS_LOG
        decayingBuffers_.emplace(bufferPtr, handle);
    } else {
        // DPS_LOG
    }
}

void BufferPool::StopDecayTimerUnlocked(SharedBuffer* bufferPtr)
{
    if (decayingBuffers_.count(bufferPtr) > 0) {
        // DPS_LOG
        timeBroker_->DeregisterCallback(decayingBuffers_[bufferPtr]);
        decayingBuffers_.erase(bufferPtr);
    }
}

void BufferPool::FreePhysicalMemory(uint32_t handle)
{
    std::unique_lock<std::mutex> lock(mutex_);
    // DPS_LOG
    for (auto it = decayingBuffers_.begin(); it != decayingBuffers_.end(); ++it) {
        if (it->second == handle) {
            auto bufferPtr = it->first;
            bufferPtr->EndAccess();
            decayingBuffers_erase(it);
            break;
        }
    }
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
