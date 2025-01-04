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

#ifndef CAMERA_NAPI_EVENT_LISTENER_H
#define CAMERA_NAPI_EVENT_LISTENER_H

#include <memory>

#include "camera_napi_utils.h"
#include "listener_base.h"

namespace OHOS {
namespace CameraStandard {
template<typename T, typename = std::enable_if_t<std::is_base_of_v<ListenerBase, T>>>
class CameraNapiEventListener {
public:
    inline void RegisterCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce)
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
    }

    inline void UnregisterCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
    {
        std::lock_guard<std::mutex> lock(eventListenerMapMutex_);
        auto listener = GetEventListenerNoLock(env);
        if (listener == nullptr) {
            return;
        }
        listener->RemoveCallbackRef(eventName, callback);
    }

    inline std::shared_ptr<T> GetEventListener(napi_env env)
    {
        std::lock_guard<std::mutex> lock(eventListenerMapMutex_);
        return GetEventListenerNoLock(env);
    }

private:
    inline std::shared_ptr<T> GetEventListenerNoLock(napi_env env)
    {
        auto it = eventListenerMap_.find(env);
        if (it == eventListenerMap_.end()) {
            return nullptr;
        }
        return it->second;
    }

    inline void SetEventListenerNoLock(napi_env env, std::shared_ptr<T> eventListener)
    {
        eventListenerMap_[env] = eventListener;
    }

    std::mutex eventListenerMapMutex_;
    std::unordered_map<napi_env, std::shared_ptr<T>> eventListenerMap_;
};

} // namespace CameraStandard
} // namespace OHOS
#endif