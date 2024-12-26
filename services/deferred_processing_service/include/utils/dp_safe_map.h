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

#ifndef OHOS_CAMERA_DPS_SAFE_MAP_H
#define OHOS_CAMERA_DPS_SAFE_MAP_H

#include <mutex>
#include <optional>
#include <unordered_map>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
template <typename K, typename V>
class DpsSafeMap {
public:
    DpsSafeMap() {}

    ~DpsSafeMap() {}

    DpsSafeMap(const DpsSafeMap& rhs)
    {
        operator=(rhs);
    }

    DpsSafeMap& operator=(const DpsSafeMap& rhs)
    {
        if (this == &rhs) {
            return *this;
        }
        auto tmp = rhs.Clone();
        std::lock_guard<std::mutex> lock(mutex_);
        map_ = std::move(tmp);

        return *this;
    }

    template <typename... Args>
    void Emplace(const K& key, Args&&... args)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        map_.emplace(key, std::forward<Args>(args)...);
    }

    void EnsureInsert(const K& key, const V& value)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        map_[key] = value;
    }

    std::optional<V> Find(const K& key)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto iter = map_.find(key);
        if (iter != map_.end()) {
            return iter->second;
        }
        return std::nullopt;
    }

    void Erase(const K& key)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        map_.erase(key);
    }

    int Size()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return map_.size();
    }

    bool IsEmpty()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return map_.empty();
    }

    void Clear()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        map_.clear();
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<K, V> map_;

    std::unordered_map<K, V> Clone() const noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return map_;
    }
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_SAFE_MAP_H