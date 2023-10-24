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

#include "input/camera_info_napi.h"
#include "input/camera_manager_callback_napi.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;
namespace {
    constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "CameraManagerCallbackNapi"};
}

CameraManagerCallbackNapi::CameraManagerCallbackNapi(napi_env env): env_(env)
{}

CameraManagerCallbackNapi::~CameraManagerCallbackNapi()
{
}

void CameraManagerCallbackNapi::OnCameraStatusCallbackAsync(const CameraStatusInfo &cameraStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnCameraStatusCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("failed to allocate work");
        return;
    }
    std::unique_ptr<CameraStatusCallbackInfo> callbackInfo =
        std::make_unique<CameraStatusCallbackInfo>(cameraStatusInfo, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        CameraStatusCallbackInfo* callbackInfo = reinterpret_cast<CameraStatusCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnCameraStatusCallback(callbackInfo->info_);
            delete callbackInfo;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void CameraManagerCallbackNapi::OnCameraStatusCallback(const CameraStatusInfo &cameraStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnCameraStatusCallback is called");
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env_, &scope);
    if (scope == nullptr) {
        return;
    }
    napi_value result[ARGS_TWO];
    napi_value callback = nullptr;
    napi_value retVal;
    napi_value propValue;
    napi_value undefinedResult;
    for (auto it = cameraManagerCbList_.begin(); it != cameraManagerCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_get_undefined(env, &result[PARAM0]);
        napi_get_undefined(env, &result[PARAM1]);
        napi_get_undefined(env, &undefinedResult);

        CAMERA_NAPI_CHECK_NULL_PTR_RETURN_VOID(cameraStatusInfo.cameraDevice, "callback cameraDevice is null");

        napi_create_object(env, &result[PARAM1]);

        if (cameraStatusInfo.cameraDevice != nullptr) {
            napi_value cameraDeviceNapi = CameraDeviceNapi::CreateCameraObj(env, cameraStatusInfo.cameraDevice);
            napi_set_named_property(env, result[PARAM1], "camera", cameraDeviceNapi);
        } else {
            MEDIA_ERR_LOG("Camera info is null");
            napi_set_named_property(env, result[PARAM1], "camera", undefinedResult);
        }

        int32_t jsCameraStatus = -1;
        jsCameraStatus = cameraStatusInfo.cameraStatus;
        napi_create_int64(env, jsCameraStatus, &propValue);
        napi_set_named_property(env, result[PARAM1], "status", propValue);

        napi_get_reference_value(env, (*it)->cb_, &callback);
        MEDIA_INFO_LOG("CameraId: %{public}s, CameraStatus: %{public}d",
                       cameraStatusInfo.cameraDevice->GetID().c_str(), cameraStatusInfo.cameraStatus);
        napi_call_function(env, nullptr, callback, ARGS_TWO, result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference((*it)->env_, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            cameraManagerCbList_.erase(it);
        } else {
            it++;
        }
    }
    napi_close_handle_scope(env_, scope);
}

void CameraManagerCallbackNapi::OnCameraStatusChanged(const CameraStatusInfo &cameraStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnCameraStatusChanged is called, CameraStatus: %{public}d", cameraStatusInfo.cameraStatus);
    OnCameraStatusCallbackAsync(cameraStatusInfo);
}

void CameraManagerCallbackNapi::OnFlashlightStatusChanged(const std::string &cameraID,
    const FlashStatus flashStatus) const
{
    (void)cameraID;
    (void)flashStatus;
}

void CameraManagerCallbackNapi::SaveCallbackReference(const std::string &eventType, napi_value callback, bool isOnce)
{
    std::lock_guard<std::mutex> lock(mutex_);
    napi_ref callbackRef = nullptr;
    const int32_t refCount = 1;

    for (auto it = cameraManagerCbList_.begin(); it != cameraManagerCbList_.end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        CHECK_AND_RETURN_LOG(!isSameCallback, "SaveCallbackReference: has same callback, nothing to do");
    }
    napi_status status = napi_create_reference(env_, callback, refCount, &callbackRef);
    CHECK_AND_RETURN_LOG(status == napi_ok && callbackRef != nullptr,
                         "ErrorCallbackListener: creating reference for callback fail");
    std::shared_ptr<AutoRef> cb = std::make_shared<AutoRef>(env_, callbackRef, isOnce);
    cameraManagerCbList_.push_back(cb);
    MEDIA_INFO_LOG("Save callback reference success, cameraManager callback list size [%{public}zu]",
                   cameraManagerCbList_.size());
}

void CameraManagerCallbackNapi::RemoveCallbackRef(napi_env env, napi_value callback)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (callback == nullptr) {
        MEDIA_INFO_LOG("RemoveCallbackReference: js callback is nullptr, remove all callback reference");
        RemoveAllCallbacks();
        return;
    }
    for (auto it = cameraManagerCbList_.begin(); it != cameraManagerCbList_.end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        if (isSameCallback) {
            MEDIA_INFO_LOG("RemoveCallbackReference: find js callback, delete it");
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            (*it)->cb_ = nullptr;
            CHECK_AND_RETURN_LOG(status == napi_ok, "RemoveCallbackReference: delete reference for callback fail");
            cameraManagerCbList_.erase(it);
            return;
        }
    }
    MEDIA_INFO_LOG("RemoveCallbackReference: js callback no find");
}

void CameraManagerCallbackNapi::RemoveAllCallbacks()
{
    for (auto it = cameraManagerCbList_.begin(); it != cameraManagerCbList_.end(); ++it) {
        napi_delete_reference(env_, (*it)->cb_);
        (*it)->cb_ = nullptr;
    }
    cameraManagerCbList_.clear();
    MEDIA_INFO_LOG("RemoveAllCallbacks: remove all js callbacks success");
}
} // namespace CameraStandard
} // namespace OHOS
