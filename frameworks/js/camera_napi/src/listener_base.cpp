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

void ListenerBase::SaveCallbackReference(napi_value callback, bool isOnce)
{
    napi_ref callbackRef = nullptr;
    const int32_t refCount = 1;
    std::lock_guard<std::mutex> lock(baseCbListMutex_);
    for (auto it = baseCbList_.begin(); it != baseCbList_.end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        CHECK_AND_RETURN_LOG(!isSameCallback, "SaveCallbackReference: has same callback, nothing to do");
    }
    napi_status status = napi_create_reference(env_, callback, refCount, &callbackRef);
    CHECK_AND_RETURN_LOG(status == napi_ok && callbackRef != nullptr, "creating reference for callback fail");
    std::shared_ptr<AutoRef> cb = std::make_shared<AutoRef>(env_, callbackRef, isOnce);
    baseCbList_.push_back(cb);
    MEDIA_DEBUG_LOG("Save callback reference success, base callback list size [%{public}zu]", baseCbList_.size());
}

void ListenerBase::RemoveCallbackRef(napi_env env, napi_value callback)
{
    if (callback == nullptr) {
        MEDIA_INFO_LOG("RemoveCallbackReference: js callback is nullptr, remove all callback reference");
        RemoveAllCallbacks();
        return;
    }
    std::lock_guard<std::mutex> lock(baseCbListMutex_);
    for (auto it = baseCbList_.begin(); it != baseCbList_.end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        if (isSameCallback) {
            MEDIA_INFO_LOG("RemoveCallbackReference: find js callback, delete it");
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            (*it)->cb_ = nullptr;
            CHECK_AND_RETURN_LOG(status == napi_ok, "RemoveCallbackReference: delete reference for callback fail");
            baseCbList_.erase(it);
            return;
        }
    }
    MEDIA_INFO_LOG("RemoveCallbackReference: js callback no find");
}

void ListenerBase::ExecuteCallback(const ExecuteCallbackNapiPara& callbackPara) const
{
    std::lock_guard<std::mutex> lock(baseCbListMutex_);
    MEDIA_DEBUG_LOG("ListenerBase::ExecuteCallback is called");
    napi_value callback = nullptr;
    for (auto it = baseCbList_.begin(); it != baseCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_call_function(
            env_, callbackPara.recv, callback, callbackPara.argc, callbackPara.argv, callbackPara.result);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            baseCbList_.erase(it);
        } else {
            it++;
        }
    }
    MEDIA_DEBUG_LOG("ListenerBase::ExecuteCallback list size [%{public}zu]", baseCbList_.size());
}

void ListenerBase::RemoveAllCallbacks()
{
    std::lock_guard<std::mutex> lock(baseCbListMutex_);
    for (auto it = baseCbList_.begin(); it != baseCbList_.end(); ++it) {
        napi_delete_reference(env_, (*it)->cb_);
        (*it)->cb_ = nullptr;
    }
    baseCbList_.clear();
    MEDIA_INFO_LOG("RemoveAllCallbacks: remove all js callbacks success");
}

size_t ListenerBase::IsEmpty()
{
    std::lock_guard<std::mutex> lock(baseCbListMutex_);
    return baseCbList_.empty();
}
} // namespace CameraStandard
} // namespace OHOS
