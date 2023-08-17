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
#include "input/camera_mute_listener_napi.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

CameraMuteListenerNapi::CameraMuteListenerNapi(napi_env env): env_(env)
{
    MEDIA_DEBUG_LOG("CameraMuteListenerNapi is called.");
}

CameraMuteListenerNapi::~CameraMuteListenerNapi()
{
    MEDIA_DEBUG_LOG("~CameraMuteListenerNapi is called.");
}

void CameraMuteListenerNapi::OnCameraMuteCallbackAsync(bool muteMode) const
{
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
    std::unique_ptr<CameraMuteCallbackInfo> callbackInfo =
        std::make_unique<CameraMuteCallbackInfo>(muteMode, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        CameraMuteCallbackInfo* callbackInfo = reinterpret_cast<CameraMuteCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnCameraMuteCallback(callbackInfo->muteMode_);
            delete callbackInfo;
        }
        delete work;
    });
    if (ret) {
        MEDIA_ERR_LOG("Failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void CameraMuteListenerNapi::OnCameraMuteCallback(bool muteMode) const
{
    MEDIA_DEBUG_LOG("OnCameraMuteCallback is called, muteMode: %{public}d", muteMode);
    napi_value result[ARGS_TWO];
    napi_value callback;
    napi_value retVal;
    for (auto it = cameraMuteCbList_.begin(); it != cameraMuteCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_get_undefined(env, &result[PARAM0]);
        napi_get_undefined(env, &result[PARAM1]);
        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_get_boolean(env, muteMode, &result[PARAM1]);
        napi_call_function(env, nullptr, callback, ARGS_TWO, result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference((*it)->env_, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            cameraMuteCbList_.erase(it);
        } else {
            it++;
        }
    }
}

void CameraMuteListenerNapi::OnCameraMute(bool muteMode) const
{
    MEDIA_DEBUG_LOG("OnCameraMute is called, muteMode: %{public}d", muteMode);
    OnCameraMuteCallbackAsync(muteMode);
}

void CameraMuteListenerNapi::SaveCallbackReference(const std::string &eventType, napi_value callback, bool isOnce)
{
    std::lock_guard<std::mutex> lock(mutex_);
    napi_ref callbackRef = nullptr;
    const int32_t refCount = 1;

    bool isSameCallback = true;
    for (auto it = cameraMuteCbList_.begin(); it != cameraMuteCbList_.end(); ++it) {
        isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        CHECK_AND_RETURN_LOG(!isSameCallback, "SaveCallbackReference: has same callback, nothing to do");
    }
    napi_status status = napi_create_reference(env_, callback, refCount, &callbackRef);
    CHECK_AND_RETURN_LOG(status == napi_ok && callbackRef != nullptr,
                         "CameraManagerCallbackNapi: creating reference for callback fail");
    std::shared_ptr<AutoRef> cb = std::make_shared<AutoRef>(env_, callbackRef, isOnce);
    cameraMuteCbList_.push_back(cb);
    MEDIA_DEBUG_LOG("Save callback reference success, cameraMute callback list size [%{public}zu]",
        cameraMuteCbList_.size());
}

void CameraMuteListenerNapi::RemoveCallbackRef(napi_env env, napi_value callback)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (callback == nullptr) {
        MEDIA_INFO_LOG("RemoveCallbackReference: js callback is nullptr, remove all callback reference");
        RemoveAllCallbacks();
        return;
    }
    for (auto it = cameraMuteCbList_.begin(); it != cameraMuteCbList_.end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        if (isSameCallback) {
            MEDIA_INFO_LOG("RemoveCallbackReference: find js callback, delete it");
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            (*it)->cb_ = nullptr;
            CHECK_AND_RETURN_LOG(status == napi_ok, "RemoveCallbackReference: delete reference for callback fail");
            cameraMuteCbList_.erase(it);
            return;
        }
    }
    MEDIA_INFO_LOG("RemoveCallbackReference: js callback no find");
}

void CameraMuteListenerNapi::RemoveAllCallbacks()
{
    for (auto it = cameraMuteCbList_.begin(); it != cameraMuteCbList_.end(); ++it) {
        napi_delete_reference(env_, (*it)->cb_);
        (*it)->cb_ = nullptr;
    }
    cameraMuteCbList_.clear();
    MEDIA_INFO_LOG("RemoveAllCallbacks: remove all js callbacks success");
}
} // namespace CameraStandard
} // namespace OHOS
