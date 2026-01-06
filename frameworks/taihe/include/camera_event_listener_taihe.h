/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_CAMERA_EVENT_LISTENER_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_CAMERA_EVENT_LISTENER_TAIHE_H

#include <memory>

#include "camera_utils_taihe.h"
#include "listener_base_taihe.h"

namespace Ani {
namespace Camera {
template<typename T, typename = std::enable_if_t<std::is_base_of_v<ListenerBase, T>>>
class CameraAniEventListener {
public:
    std::shared_ptr<T> RegisterCallbackListener(const std::string& eventName,
        ani_env *env, std::shared_ptr<uintptr_t> callback, bool isOnce)
    {
        std::shared_ptr<T> listener = nullptr;
        {
            std::lock_guard<std::mutex> lock(eventListenerMapMutex_);
            listener = GetEventListenerNoLock(env);
            if (listener == nullptr) {
                listener = std::make_shared<T>(env);
                SetEventListenerNoLock(env, listener);
            }
        }
        listener->SaveCallbackReference(eventName, callback, isOnce);
        return listener;
    }

    std::shared_ptr<T> UnregisterCallbackListener(
        const std::string& eventName, ani_env *env, std::shared_ptr<uintptr_t> callback)
    {
        std::lock_guard<std::mutex> lock(eventListenerMapMutex_);
        auto listener = GetEventListenerNoLock(env);
        CHECK_RETURN_RET(listener == nullptr, nullptr);
        listener->RemoveCallbackRef(eventName, callback);
        return listener;
    }

private:
    std::shared_ptr<T> GetEventListenerNoLock(ani_env *env)
    {
        auto it = eventListenerMap_.find(env);
        if (it == eventListenerMap_.end()) {
            return nullptr;
        }
        return it->second;
    }

    void SetEventListenerNoLock(ani_env *env, std::shared_ptr<T> eventListener)
    {
        eventListenerMap_[env] = eventListener;
    }

    std::mutex eventListenerMapMutex_;
    std::unordered_map<ani_env *, std::shared_ptr<T>> eventListenerMap_;
};

} // namespace Camera
} // namespace Ani
#endif //FRAMEWORKS_TAIHE_INCLUDE_CAMERA_EVENT_LISTENER_TAIHE_H