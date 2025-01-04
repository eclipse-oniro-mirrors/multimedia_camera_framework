/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef CAMERA_LISTENER_MANAGER_H
#define CAMERA_LISTENER_MANAGER_H

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

#include "refbase.h"

namespace OHOS {
namespace CameraStandard {
template<typename T>
class CameraListenerManager {
public:
    CameraListenerManager() = default;
    ~CameraListenerManager() = default;
    bool AddListener(std::shared_ptr<T> listener)
    {
        std::lock_guard<std::recursive_mutex> lock(listenerMutex_);
        if (!isTriggering_) {
            return AddListenerNoLock(listener, listeners_);
        }
        return AddListenerNoLock(listener, triggerAddListeners_);
    }

    void RemoveListener(std::shared_ptr<T> listener)
    {
        std::lock_guard<std::recursive_mutex> lock(listenerMutex_);
        if (!isTriggering_) {
            return RemoveListenerNoLock(listener, listeners_);
        }
        // Add this listener to remove-list.
        AddListenerNoLock(listener, triggerRemoveListeners_);
    }

    void ClearListeners()
    {
        std::lock_guard<std::recursive_mutex> lock(listenerMutex_);
        listeners_.clear();
    }

    void TriggerListener(std::function<void(T*)> fun)
    {
        std::lock_guard<std::recursive_mutex> lock(listenerMutex_);
        isTriggering_ = true;
        triggerAddListeners_.clear();
        triggerRemoveListeners_.clear();
        for (std::shared_ptr<T>& listener : listeners_) {
            fun(listener.get());
        }
        for (auto& removeListener : triggerRemoveListeners_) {
            for (auto it = triggerAddListeners_.begin(); it != triggerAddListeners_.end(); it++) {
                if (removeListener == *it) {
                    triggerAddListeners_.erase(it);
                    break;
                }
            }
        }
        for (auto& listener : triggerRemoveListeners_) {
            RemoveListenerNoLock(listener, listeners_);
        }

        for (auto& listener : triggerAddListeners_) {
            AddListenerNoLock(listener, listeners_);
        }
        isTriggering_ = false;
    }

    size_t GetListenerCount()
    {
        std::lock_guard<std::recursive_mutex> lock(listenerMutex_);
        return listeners_.size();
    }

    bool IsListenerExist(std::shared_ptr<T> listener)
    {
        std::lock_guard<std::recursive_mutex> lock(listenerMutex_);
        for (auto& listListener : listeners_) {
            if (listener == listListener) {
                return true;
            }
        }
        return false;
    }

private:
    bool AddListenerNoLock(std::shared_ptr<T>& listener, std::vector<std::shared_ptr<T>>& listeners) const
    {
        if (listener == nullptr) {
            return false;
        }
        for (auto& itListener : listeners) {
            if (itListener == listener) {
                return false;
            }
        }
        listeners.emplace_back(listener);
        return true;
    }

    void RemoveListenerNoLock(std::shared_ptr<T>& listener, std::vector<std::shared_ptr<T>>& listeners) const
    {
        if (listener == nullptr) {
            return;
        }
        for (auto it = listeners_.begin(); it != listeners.end(); it++) {
            if (*it == listener) {
                listeners.erase(it);
                return;
            }
        }
    }

    mutable std::recursive_mutex listenerMutex_;
    bool isTriggering_ = false;
    std::vector<std::shared_ptr<T>> listeners_;
    std::vector<std::shared_ptr<T>> triggerAddListeners_;
    std::vector<std::shared_ptr<T>> triggerRemoveListeners_;
};
} // namespace CameraStandard
} // namespace OHOS

#endif