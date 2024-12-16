/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "listener_base.h"

#include <uv.h>

#include "camera_log.h"
#include "js_native_api.h"
#include "js_native_api_types.h"

namespace OHOS {
namespace CameraStandard {
ListenerBase::ListenerBase(napi_env env) : env_(env)
{
    MEDIA_DEBUG_LOG("ListenerBase is called.");
}

ListenerBase::~ListenerBase()
{
    MEDIA_DEBUG_LOG("~ListenerBase is called.");
}

void ListenerBase::SaveCallbackReference(const std::string eventName, napi_value callback, bool isOnce)
{
    if (callback == nullptr) {
        MEDIA_ERR_LOG("SaveCallbackReference:%s js callback is nullptr, save nothing", eventName.c_str());
        return;
    }
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env_, callback, &valueType);
    if (valueType != napi_function) {
        MEDIA_ERR_LOG("SaveCallbackReference:%s js callback valueType is not function", eventName.c_str());
        return;
    }
    auto& callbackList = GetCallbackList(eventName);
    std::lock_guard<std::mutex> lock(callbackList.listMutex);
    for (auto it = callbackList.refList.begin(); it != callbackList.refList.end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameNapiValue(env_, callback, it->GetCallbackFunction());
        CHECK_ERROR_RETURN_LOG(isSameCallback, "SaveCallbackReference: has same callback, nothing to do");
    }
    callbackList.refList.emplace_back(AutoRef(env_, callback, isOnce));
    MEDIA_DEBUG_LOG("Save callback reference success, %s callback list size [%{public}zu]", eventName.c_str(),
        callbackList.refList.size());
}

void ListenerBase::RemoveCallbackRef(const std::string eventName, napi_value callback)
{
    if (callback == nullptr) {
        MEDIA_INFO_LOG("RemoveCallbackReference: js callback is nullptr, remove all callback reference");
        RemoveAllCallbacks(eventName);
        return;
    }
    auto& callbackList = GetCallbackList(eventName);
    std::lock_guard<std::mutex> lock(callbackList.listMutex);
    for (auto it = callbackList.refList.begin(); it != callbackList.refList.end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameNapiValue(env_, callback, it->GetCallbackFunction());
        if (isSameCallback) {
            MEDIA_INFO_LOG("RemoveCallbackReference: find %s callback, delete it", eventName.c_str());
            callbackList.refList.erase(it);
            return;
        }
    }
    MEDIA_INFO_LOG("RemoveCallbackReference: %s callback not find", eventName.c_str());
}

void ListenerBase::ExecuteCallback(const std::string eventName, const ExecuteCallbackNapiPara& callbackPara) const
{
    MEDIA_DEBUG_LOG("ListenerBase::ExecuteCallback is called");
    auto& callbackList = GetCallbackList(eventName);
    std::lock_guard<std::mutex> lock(callbackList.listMutex);
    for (auto it = callbackList.refList.begin(); it != callbackList.refList.end();) {
        napi_call_function(env_, callbackPara.recv, it->GetCallbackFunction(), callbackPara.argc, callbackPara.argv,
            callbackPara.result);
        if (it->isOnce_) {
            callbackList.refList.erase(it);
        } else {
            it++;
        }
    }
    MEDIA_DEBUG_LOG("ListenerBase::ExecuteCallback, %s callback list size [%{public}zu]", eventName.c_str(),
        callbackList.refList.size());
}

void ListenerBase::RemoveAllCallbacks(const std::string eventName)
{
    auto& callbackList = GetCallbackList(eventName);
    std::lock_guard<std::mutex> lock(callbackList.listMutex);
    callbackList.refList.clear();
    MEDIA_INFO_LOG("RemoveAllCallbacks: remove all js callbacks success");
}

bool ListenerBase::IsEmpty(const std::string eventName) const
{
    auto& callbackList = GetCallbackList(eventName);
    std::lock_guard<std::mutex> lock(callbackList.listMutex);
    return callbackList.refList.empty();
}
} // namespace CameraStandard
} // namespace OHOS
