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

#ifndef OHOS_DEFERRED_PROCESSING_SERVICE_BLOCKING_QUEUE_H
#define OHOS_DEFERRED_PROCESSING_SERVICE_BLOCKING_QUEUE_H

#include <atomic>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <string>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
template <typename T>
class BlockingQueue {
public:
    explicit BlockingQueue(const std::string& name, size_t capacity = 0)
        : name_(name), capacity_(capacity > 0 ? capacity : std::numeric_limits<size_t>::max()), isActive_(true)
    {
    }
    ~BlockingQueue() = default;
    size_t Size()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        return que_.size();
    }
    bool Full()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        return que_.size() == capacity_;
    }
    size_t Capacity()
    {
        return capacity_;
    }
    size_t Empty()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        return que_.empty();
    }
    bool Push(const T& value)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        auto ret = CanPush(lock);
        if (ret == true) {
            que_.push(value);
            cvEmpty_.notify_all();
        }
        return ret;
    }
    bool Push(const T& value, int timeoutMs)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        auto ret = CanPush(lock, timeoutMs);
        if (ret == true) {
            que_.push(value);
            cvEmpty_.notify_all();
        }
        return ret;
    }
    bool Push(T&& value, int timeoutMs)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        auto ret = CanPush(lock, timeoutMs);
        if (ret == true) {
            que_.push(std::move(value));
            cvEmpty_.notify_all();
        }
        return ret;
    }
    T Pop()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!isActive_) {
            return {};
        }
        if (que_.empty()) {
            cvEmpty_.wait(lock, [this] { return !isActive_ || !que_.empty(); });
        }
        if (!isActive_) {
            return {};
        }
        T el = que_.front();
        que_.pop();
        cvFull_.notify_one();
        return el;
    }
    T Pop(int timeoutMs)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!isActive_) {
            return {};
        }
        if (que_.empty()) {
            cvEmpty_.wait_for(lock, timeoutMs, [this] { return !isActive_ || !que_.empty(); });
        }
        if (!isActive_ || que_.empty()) {
            return {};
        }
        T el = que_.front();
        que_.pop();
        cvFull_.notify_one();
        return el;
    }
    void Clear()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        ClearUnlocked();
    }
    void SetActive(bool active)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        isActive_ = active;
        if (!active) {
            ClearUnlocked();
            cvEmpty_.notify_one();
        }
    }

private:
    void ClearUnlocked()
    {
        if (que_.empty()) {
            return;
        }
        bool needNotify = que_.size() == capacity_;
        std::queue<T>().swap(que_);
        if (needNotify) {
            cvFull_.notify_one();
        }
    }
    bool CanPush(std::unique_lock<std::mutex>& lock)
    {
        if (!isActive_) {
            return false;
        }
        if (que_.size() >= capacity_) {
            cvFull_.wait(lock, [this] { return !isActive_ || que_.size() < capacity_; });
        }
        if (!isActive_) {
            return false;
        }
        return true;
    }
    bool CanPush(std::unique_lock<std::mutex>& lock, int timeoutMs)
    {
        if (!isActive_) {
            return false;
        }
        if (que_.size() >= capacity_) {
            cvFull_.wait(lock, timeoutMs, [this] { return !isActive_ || que_.size() < capacity_; });
        }
        if (!isActive_ || (que_.size() == capacity_)) {
            return false;
        }
        return true;
    }

    std::mutex mutex_;
    std::condition_variable cvFull_;
    std::condition_variable cvEmpty_;
    std::string name_;
    std::queue<T> que_;
    const size_t capacity_;
    std::atomic<bool> isActive_;
};
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PROCESSING_SERVICE_BLOCKING_QUEUE_H
