/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_LRU_MAP_H
#define OHOS_CAMERA_LRU_MAP_H

#include <map>
#include <mutex>
#include <queue>
#include <list>

namespace OHOS {
namespace CameraStandard {
template<typename K, typename V>
class LruMap final {
public:
    LruMap() = default;
    ~LruMap() = default;

    LruMap(const LruMap &) = delete;
    LruMap(LruMap &&) = delete;
    LruMap& operator=(const LruMap &) = delete;
    LruMap& operator=(LruMap &&) = delete;

    bool Get(const K &key, V &value)
    {
        std::lock_guard<std::mutex> lock(lruLock_);
        if (cache_.find(key) == cache_.end()) {
            return false;
        }
        value = cache_[key];
        return MoveNodeToLast(key, value);
    }

    bool Put(const K &key, const V &inValue)
    {
        std::lock_guard<std::mutex> lock(lruLock_);
        cache_[key] = inValue;
        return MoveNodeToLast(key, inValue);
    }

    void Clear()
    {
        std::lock_guard<std::mutex> lock(lruLock_);
        cache_.clear();
        queue_.clear();
    }

private:
    bool MoveNodeToLast(const K &key, const V &val)
    {
        auto it = std::find_if(queue_.begin(), queue_.end(), [&key](const std::pair<K, V>& pair) {
            return pair.first == key;
        });
        if (it != queue_.end()) {
            queue_.erase(it);
        }
        std::pair<K, V> entry = {key, val};
        queue_.push_back(entry);
        while (queue_.size() > MAX_CACHE_ITEMS) {
            std::pair<K, V> &pair = queue_.front();
            cache_.erase(pair.first);
            queue_.pop_front();
        }
        return true;
    }

    std::mutex lruLock_;
    std::map<K, V> cache_;
    std::deque<std::pair<K, V>> queue_;

    static const int MAX_CACHE_ITEMS = 10;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_LRU_MAP_H