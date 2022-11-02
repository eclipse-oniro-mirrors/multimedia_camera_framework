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

CameraManagerCallbackNapi::CameraManagerCallbackNapi(napi_env env, napi_ref ref): env_(env), callbackRef_(ref)
{}

CameraManagerCallbackNapi::~CameraManagerCallbackNapi()
{
}

void CameraManagerCallbackNapi::OnCameraStatusCallbackAsync(const CameraStatusInfo &cameraStatusInfo) const
{
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("CameraManagerCallbackNapi:OnCameraStatusCallbackAsync() failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("CameraManagerCallbackNapi:OnCameraStatusCallbackAsync() failed to allocate work");
        return;
    }
    std::unique_ptr<CameraStatusCallbackInfo> callbackInfo =
        std::make_unique<CameraStatusCallbackInfo>(cameraStatusInfo, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        CameraStatusCallbackInfo* callbackInfo = reinterpret_cast<CameraStatusCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnCameraStatusCallback(callbackInfo->info_);
            delete callbackInfo;
        }
        delete work;
    });
    if (ret) {
        MEDIA_ERR_LOG("CameraManagerCallbackNapi:OnCameraStatusCallbackAsync() failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void CameraManagerCallbackNapi::OnCameraStatusCallback(const CameraStatusInfo &cameraStatusInfo) const
{
    napi_value result;
    napi_value callback = nullptr;
    napi_value retVal;
    napi_value propValue;
    napi_value undefinedResult;

    napi_get_undefined(env_, &result);
    napi_get_undefined(env_, &undefinedResult);

    CAMERA_NAPI_CHECK_NULL_PTR_RETURN_VOID(cameraStatusInfo.cameraDevice, "callback cameraDevice is null");

    napi_create_object(env_, &result);

    if (cameraStatusInfo.cameraDevice != nullptr) {
        napi_value cameraDeviceNapi = CameraDeviceNapi::CreateCameraObj(env_, cameraStatusInfo.cameraDevice);
        napi_set_named_property(env_, result, "camera", cameraDeviceNapi);
    } else {
        MEDIA_ERR_LOG("Camera info is null");
        napi_set_named_property(env_, result, "camera", undefinedResult);
    }

    int32_t jsCameraStatus = -1;
    jsCameraStatus = cameraStatusInfo.cameraStatus;
    napi_create_int64(env_, jsCameraStatus, &propValue);
    napi_set_named_property(env_, result, "status", propValue);

    napi_get_reference_value(env_, callbackRef_, &callback);
    MEDIA_INFO_LOG("CameraManagerCallbackNapi:OnCameraStatusChanged CameraId: %{public}s, CameraStatus: %{public}d",
                   cameraStatusInfo.cameraDevice->GetID().c_str(), cameraStatusInfo.cameraStatus);
    napi_call_function(env_, nullptr, callback, ARGS_ONE, &result, &retVal);
}

void CameraManagerCallbackNapi::OnCameraStatusChanged(const CameraStatusInfo &cameraStatusInfo) const
{
    MEDIA_DEBUG_LOG("CameraManagerCallbackNapi:OnCameraStatusChanged CameraStatus: %{public}d",
                    cameraStatusInfo.cameraStatus);
    OnCameraStatusCallbackAsync(cameraStatusInfo);
}

void CameraManagerCallbackNapi::OnFlashlightStatusChanged(const std::string &cameraID,
    const FlashStatus flashStatus) const
{
    (void)cameraID;
    (void)flashStatus;
}
} // namespace CameraStandard
} // namespace OHOS
