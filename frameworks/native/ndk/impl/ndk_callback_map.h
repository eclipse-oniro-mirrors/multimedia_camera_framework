/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_NDK_CALLBACK_MAP_H
#define OHOS_CAMERA_NDK_CALLBACK_MAP_H

#include <cstdint>
#include <mutex>
#include <unordered_map>

template<typename K, typename V>
class NDKCallbackMap {
public:
    void SetMapValue(K key, std::shared_ptr<V> value)
    {
        if (key == nullptr) {
            return;
        }
        std::lock_guard<std::mutex> lock(mapMutex_);
        callbackMap_[key] = value;
    }

    std::shared_ptr<V> RemoveValue(K key)
    {
        std::shared_ptr<V> callback = nullptr;
        std::lock_guard<std::mutex> lock(mapMutex_);
        auto it = callbackMap_.find(key);
        if (it != callbackMap_.end()) {
            callback = it->second;
            callbackMap_.erase(it);
        }
        return callback;
    }

private:
    std::mutex mapMutex_;
    std::unordered_map<K, std::shared_ptr<V>> callbackMap_;
};

#endif