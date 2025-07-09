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

#include <memory>
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

ListenerBase::ExecuteCallbackData::ExecuteCallbackData(napi_env env, napi_value errCode, napi_value returnData)
    : env_(env), errCode_(errCode), returnData_(returnData) {};

void ListenerBase::SaveCallbackReference(const std::string eventName, napi_value callback, bool isOnce)
{
    CHECK_RETURN_ELOG(callback == nullptr,
        "SaveCallbackReference:%s js callback is nullptr, save nothing", eventName.c_str());
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env_, callback, &valueType);
    CHECK_RETURN_ELOG(valueType != napi_function,
        "SaveCallbackReference:%s js callback valueType is not function", eventName.c_str());
    auto& callbackList = GetCallbackList(eventName);
    std::lock_guard<std::mutex> lock(callbackList.listMutex);
    for (auto it = callbackList.refList.begin(); it != callbackList.refList.end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameNapiValue(env_, callback, it->GetCallbackFunction());
        CHECK_RETURN_ELOG(isSameCallback, "SaveCallbackReference: has same callback, nothing to do");
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

void ListenerBase::ExecuteCallbackScopeSafe(
    const std::string eventName, const std::function<ExecuteCallbackData()> fun) const
{
    napi_handle_scope scope_ = nullptr;
    napi_open_handle_scope(env_, &scope_);

    MEDIA_DEBUG_LOG("ListenerBase::ExecuteCallback %{public}s is called", eventName.c_str());
    auto& callbackList = GetCallbackList(eventName);
    std::lock_guard<std::mutex> lock(callbackList.listMutex);
    for (auto it = callbackList.refList.begin(); it != callbackList.refList.end();) {
        // Do not move this call out of loop.
        ExecuteCallbackData callbackData = fun();
        if (callbackData.env_ == nullptr) {
            MEDIA_ERR_LOG("ExecuteCallback %{public}s env is null ", eventName.c_str());
            continue;
        }

        napi_value result[ARGS_TWO] = { nullptr, nullptr };
        napi_value retVal;
        result[0] = callbackData.errCode_;
        result[1] = callbackData.returnData_;

        napi_call_function(callbackData.env_, nullptr, it->GetCallbackFunction(), ARGS_TWO, result, &retVal);
        if (it->isOnce_) {
            callbackList.refList.erase(it);
        } else {
            it++;
        }
    }
    MEDIA_DEBUG_LOG("ListenerBase::ExecuteCallback, %s callback list size [%{public}zu]", eventName.c_str(),
        callbackList.refList.size());

    napi_close_handle_scope(env_, scope_);
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
