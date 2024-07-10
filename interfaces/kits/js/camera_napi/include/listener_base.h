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

#ifndef LISTENER_BASE_H_
#define LISTENER_BASE_H_

#include <list>
#include <memory>
#include <mutex>
#include <unordered_map>

#include "camera_napi_auto_ref.h"
#include "camera_napi_utils.h"
namespace OHOS {
namespace CameraStandard {
class ListenerBase {
public:
    explicit ListenerBase(napi_env env);
    virtual ~ListenerBase();

    struct ExecuteCallbackNapiPara {
        napi_value recv;
        size_t argc;
        const napi_value* argv;
        napi_value* result;
    };
    virtual void SaveCallbackReference(const std::string eventName, napi_value callback, bool isOnce) final;
    virtual void ExecuteCallback(const std::string eventName, const ExecuteCallbackNapiPara& callbackPara) const final;
    virtual void RemoveCallbackRef(const std::string eventName, napi_value callback) final;
    virtual void RemoveAllCallbacks(const std::string eventName) final;
    virtual bool IsEmpty(const std::string eventName) const final;

protected:
    napi_env env_ = nullptr;

private:
    struct CallbackList {
        std::mutex listMutex;
        std::list<AutoRef> refList;
    };

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

    mutable std::mutex namedCallbackMapMutex_;
    mutable std::unordered_map<std::string, std::shared_ptr<CallbackList>> namedCallbackMap_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* LISTENER_BASE_H_ */
