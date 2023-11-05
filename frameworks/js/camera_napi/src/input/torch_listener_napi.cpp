/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include <uv.h>
#include "input/torch_listener_napi.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

TorchListenerNapi::TorchListenerNapi(napi_env env): env_(env)
{
    MEDIA_DEBUG_LOG("TorchListenerNapi is called.");
}

TorchListenerNapi::~TorchListenerNapi()
{
    MEDIA_DEBUG_LOG("~TorchListenerNapi is called.");
}

void TorchListenerNapi::OnTorchStatusChangeCallbackAsync(const TorchStatusInfo &torchStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnTorchStatusChangeCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("Failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("Failed to allocate work");
        return;
    }
    std::unique_ptr<TorchStatusChangeCallbackInfo> callbackInfo =
        std::make_unique<TorchStatusChangeCallbackInfo>(torchStatusInfo, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        TorchStatusChangeCallbackInfo* callbackInfo = reinterpret_cast<TorchStatusChangeCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnTorchStatusChangeCallback(callbackInfo->info_);
            delete callbackInfo;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("Failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void TorchListenerNapi::OnTorchStatusChangeCallback(const TorchStatusInfo &torchStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnTorchStatusChangeCallback is called");
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env_, &scope);
    if (scope == nullptr) {
        return;
    }
    napi_value result[ARGS_TWO];
    napi_value callback;
    napi_value retVal;
    napi_value propValue;
    for (auto it = torchCbList_.begin(); it != torchCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_get_undefined(env, &result[PARAM0]);
        napi_get_undefined(env, &result[PARAM1]);

        napi_create_object(env, &result[PARAM1]);

        napi_get_boolean(env,  torchStatusInfo.isTorchAvailable, &propValue);
        napi_set_named_property(env, result[PARAM1], "isTorchAvailable", propValue);
        napi_get_boolean(env,  torchStatusInfo.isTorchActive, &propValue);
        napi_set_named_property(env, result[PARAM1], "isTorchActive", propValue);
        napi_create_double(env,  torchStatusInfo.torchLevel, &propValue);
        napi_set_named_property(env, result[PARAM1], "torchLevel", propValue);

        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_call_function(env, nullptr, callback, ARGS_TWO, result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference((*it)->env_, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            torchCbList_.erase(it);
        } else {
            it++;
        }
    }
    napi_close_handle_scope(env_, scope);
}

void TorchListenerNapi::OnTorchStatusChange(const TorchStatusInfo &torchStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnTorchStatusChange is called");
    OnTorchStatusChangeCallbackAsync(torchStatusInfo);
}

void TorchListenerNapi::SaveCallbackReference(const std::string &eventType, napi_value callback, bool isOnce)
{
    std::lock_guard<std::mutex> lock(mutex_);
    napi_ref callbackRef = nullptr;
    const int32_t refCount = 1;

    for (auto it = torchCbList_.begin(); it != torchCbList_.end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        CHECK_AND_RETURN_LOG(!isSameCallback, "SaveCallbackReference: has same callback, nothing to do");
    }
    napi_status status = napi_create_reference(env_, callback, refCount, &callbackRef);
    CHECK_AND_RETURN_LOG(status == napi_ok && callbackRef != nullptr,
                         "TorchListenerNapi: creating reference for callback fail");
    std::shared_ptr<AutoRef> cb = std::make_shared<AutoRef>(env_, callbackRef, isOnce);
    torchCbList_.push_back(cb);
    MEDIA_DEBUG_LOG("Save callback reference success, torch callback list size [%{public}zu]",
        torchCbList_.size());
}

void TorchListenerNapi::RemoveCallbackRef(napi_env env, napi_value callback)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (callback == nullptr) {
        MEDIA_INFO_LOG("RemoveCallbackReference: js callback is nullptr, remove all callback reference");
        RemoveAllCallbacks();
        return;
    }
    for (auto it = torchCbList_.begin(); it != torchCbList_.end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        if (isSameCallback) {
            MEDIA_INFO_LOG("RemoveCallbackReference: find js callback, delete it");
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            (*it)->cb_ = nullptr;
            CHECK_AND_RETURN_LOG(status == napi_ok, "RemoveCallbackReference: delete reference for callback fail");
            torchCbList_.erase(it);
            return;
        }
    }
    MEDIA_INFO_LOG("RemoveCallbackReference: js callback no find");
}

void TorchListenerNapi::RemoveAllCallbacks()
{
    for (auto it = torchCbList_.begin(); it != torchCbList_.end(); ++it) {
        napi_delete_reference(env_, (*it)->cb_);
        (*it)->cb_ = nullptr;
    }
    torchCbList_.clear();
    MEDIA_INFO_LOG("RemoveAllCallbacks: remove all js callbacks success");
}
} // namespace CameraStandard
} // namespace OHOS
