/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef LISTENER_BASE_CJ_H
#define LISTENER_BASE_CJ_H

#include <mutex>
#include <refbase.h>
#include <string>

namespace OHOS {
namespace CameraStandard {

template <typename... T> struct CallbackRef {
    std::function<void(T...)> ref;
    int64_t id;
    CallbackRef(const std::function<void(T...)> ref_, int64_t id_)
    {
        ref = ref_;
        id = id_;
    }
};

template <typename... T> class ListenerBase {
public:
    void SaveCallbackRef(const std::shared_ptr<CallbackRef<T...>> callback);

    void RemoveCallbackRef(int64_t id);

    void RemoveAllCallbackRef();

    void ExecuteCallback(T const... callbackPara) const;

private:
    mutable std::mutex listMutex_{};
    std::vector<std::shared_ptr<CallbackRef<T...>>> callbackList;
};

template <typename... T> void ListenerBase<T...>::SaveCallbackRef(const std::shared_ptr<CallbackRef<T...>> callback)
{
    std::lock_guard<std::mutex> lock(listMutex_);
    callbackList.push_back(callback);
}

template <typename... T> void ListenerBase<T...>::RemoveCallbackRef(int64_t id)
{
    std::lock_guard<std::mutex> lock(listMutex_);
    for (auto it = callbackList.begin(); it != callbackList.end(); it++) {
        if ((*it)->id == id) {
            callbackList.erase(it);
            break;
        }
    }
}

template <typename... T> void ListenerBase<T...>::RemoveAllCallbackRef()
{
    std::lock_guard<std::mutex> lock(listMutex_);
    callbackList.clear();
}

template <typename... T> void ListenerBase<T...>::ExecuteCallback(T const... callbackPara) const
{
    std::lock_guard<std::mutex> lock(listMutex_);
    if (callbackList.size() == 0) {
        // LOG("no OnError func registered")
        return;
    }
    int len = static_cast<int>(callbackList.size());
    for (int i = 0; i < len; i++) {
        callbackList[i]->ref(callbackPara...);
    }
}
} // namespace CameraStandard
} // namespace OHOS

#endif