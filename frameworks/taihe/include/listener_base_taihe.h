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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_LISTENER_BASE_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_LISTENER_BASE_TAIHE_H

#include <unordered_map>

#include "camera_auto_ref_taihe.h"
#include "event_handler.h"
namespace Ani {
namespace Camera {
class ListenerBase {
public:
    explicit ListenerBase(ani_env* env);
    virtual ~ListenerBase();
    struct CallbackList {
        std::mutex listMutex;
        std::list<std::shared_ptr<AutoRef>> refList;
    };

    virtual void SaveCallbackReference(const std::string eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce) final;
    virtual void RemoveCallbackRef(const std::string eventName, std::shared_ptr<uintptr_t> callback) final;
    virtual void RemoveAllCallbacks(const std::string eventName) final;
    virtual bool IsEmpty(const std::string eventName) const final;
    inline CallbackList& GetCallbackList(const std::string eventName) const
    {
        std::lock_guard<std::mutex> lock(namedCallbackMapMutex_);
        auto it = namedCallbackMap_.find(eventName);
        if (it == namedCallbackMap_.end()) {
            auto callbackList = std::make_shared<CallbackList>();
            namedCallbackMap_.emplace(eventName, callbackList);
            return *callbackList;
        }
        return *it->second;
    }

    inline static bool IsSameRef(std::shared_ptr<uintptr_t> src, std::shared_ptr<uintptr_t> dst)
    {
        std::shared_ptr<taihe::callback<void()>> srcPtr =
        std::reinterpret_pointer_cast<taihe::callback<void()>>(src);
        std::shared_ptr<taihe::callback<void()>> dstPtr =
        std::reinterpret_pointer_cast<taihe::callback<void()>>(dst);
        return *srcPtr == *dstPtr;
    }

    template<typename... Params>
    void ExecuteAsyncCallback(const std::string eventName, int32_t errCode, std::string message, Params... params) const
    {
        auto& callbackList = GetCallbackList(eventName);
        std::lock_guard<std::mutex> lock(callbackList.listMutex);
        for (auto it = callbackList.refList.begin(); it != callbackList.refList.end();) {
            auto func = it->get()->GetCallbackFunction();
            bool isOnce = it->get()->isOnce_;
            std::shared_ptr<taihe::callback<void(uintptr_t, Params...)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t, Params...)>>(func);
            auto err = CameraUtilsTaihe::ToBusinessError(get_env(), errCode, message);
            (*cacheCallback)(reinterpret_cast<uintptr_t>(err), params...);
            if (isOnce) {
                callbackList.refList.erase(it);
            } else {
                it++;
            }
        }
    }

    template<typename... Params>
    void ExecuteCallback(const std::string eventName, Params... params) const
    {
        auto& callbackList = GetCallbackList(eventName);
        std::lock_guard<std::mutex> lock(callbackList.listMutex);
        for (auto it = callbackList.refList.begin(); it != callbackList.refList.end();) {
            auto func = it->get()->GetCallbackFunction();
            bool isOnce = it->get()->isOnce_;
            std::shared_ptr<taihe::callback<void(Params...)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(Params...)>>(func);
            (*cacheCallback)(params...);
            if (isOnce) {
                callbackList.refList.erase(it);
            } else {
                it++;
            }
        }
    }

    void ExecuteErrorCallback(const std::string eventName, int32_t errorCode) const
    {
        auto& callbackList = GetCallbackList(eventName);
        std::lock_guard<std::mutex> lock(callbackList.listMutex);
        for (auto it = callbackList.refList.begin(); it != callbackList.refList.end();) {
            auto func = it->get()->GetCallbackFunction();
            bool isOnce = it->get()->isOnce_;
            std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(func);
            auto err = CameraUtilsTaihe::ToBusinessError(get_env(), errorCode, " ");
            (*cacheCallback)(reinterpret_cast<uintptr_t>(err));
            if (isOnce) {
                callbackList.refList.erase(it);
            } else {
                it++;
            }
        }
    }

    std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_ = nullptr;

protected:
    ani_env* env_ = nullptr;

private:
    mutable std::mutex namedCallbackMapMutex_;
    mutable std::unordered_map<std::string, std::shared_ptr<CallbackList>> namedCallbackMap_;
};
} // namespace Camera
} // namespace Ani
#endif /* FRAMEWORKS_TAIHE_INCLUDE_LISTENER_BASE_TAIHE_H */
