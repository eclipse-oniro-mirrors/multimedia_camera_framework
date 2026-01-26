/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "mode/photo_session_napi.h"

#include "camera_log.h"
#include "input/camera_manager.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

thread_local napi_ref PhotoSessionNapi::sConstructor_ = nullptr;

PhotoSessionNapi::PhotoSessionNapi() : env_(nullptr)
{
}
PhotoSessionNapi::~PhotoSessionNapi()
{
    MEDIA_DEBUG_LOG("~PhotoSessionNapi is called");
}
void PhotoSessionNapi::PhotoSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("PhotoSessionNapiDestructor is called");
    PhotoSessionNapi* cameraObj = reinterpret_cast<PhotoSessionNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}
napi_value PhotoSessionNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    std::vector<std::vector<napi_property_descriptor>> descriptors = { camera_process_props, camera_process_sys_props,
        flash_props, flash_sys_props, auto_exposure_props, focus_props, focus_sys_props, zoom_props, zoom_sys_props,
        filter_props, preconfig_props, color_management_props, auto_switch_props, macro_props, white_balance_props,
        imaging_mode_props };
    std::vector<napi_property_descriptor> photo_session_props = CameraNapiUtils::GetPropertyDescriptor(descriptors);
    status = napi_define_class(env, PHOTO_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               PhotoSessionNapiConstructor, nullptr,
                               photo_session_props.size(),
                               photo_session_props.data(), &ctorObj);
    if (status == napi_ok) {
        status = NapiRefManager::CreateMemSafetyRef(env, ctorObj, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, PHOTO_SESSION_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value PhotoSessionNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSession_ = CameraManager::GetInstance()->CreateCaptureSession(SceneMode::CAPTURE);
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("Failed to create Photo session instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSession_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("success to create Photo session napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Photo session napi instance");
        }
    }
    MEDIA_ERR_LOG("Failed to create Photo session napi instance last");
    napi_get_undefined(env, &result);
    return result;
}

napi_value PhotoSessionNapi::CreatePhotoSessionForTransfer(napi_env env, sptr<PhotoSession> photoSession)
{
    MEDIA_INFO_LOG("CreatePhotoSessionForTransfer is called");
    CHECK_RETURN_RET_ELOG(photoSession == nullptr, nullptr,
        "CreatePhotoSessionForTransfer photoSession is nullptr");
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSession_ = photoSession;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSession_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_INFO_LOG("CreatePhotoSessionForTransfer success to create napi instance for transfer");
            return result;
        } else {
            MEDIA_ERR_LOG("CreatePhotoSessionForTransfer Failed to create napi instance for transfer");
        }
    }
    MEDIA_ERR_LOG("CreatePhotoSessionForTransfer Failed");
    napi_get_undefined(env, &result);
    return result;
}

napi_value PhotoSessionNapi::PhotoSessionNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PhotoSessionNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<PhotoSessionNapi> obj = std::make_unique<PhotoSessionNapi>();
        obj->env_ = env;
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("sCameraSession_ is null");
            return result;
        }
        obj->photoSession_ = static_cast<PhotoSession*>(sCameraSession_.GetRefPtr());
        obj->cameraSession_ = obj->photoSession_;
        if (obj->photoSession_ == nullptr) {
            MEDIA_ERR_LOG("photoSession_ is null");
            return result;
        }
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            PhotoSessionNapi::PhotoSessionNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("PhotoSessionNapi Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("PhotoSessionNapi call Failed!");
    return result;
}

void PhotoSessionNapi::RegisterPressureStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    MEDIA_INFO_LOG("PhotoSessionNapi::RegisterPressureStatusCallbackListener");
    if (pressureCallback_ == nullptr) {
        pressureCallback_ = std::make_shared<PressureCallbackListener>(env);
        cameraSession_->SetPressureCallback(pressureCallback_);
    }
    pressureCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoSessionNapi::UnregisterPressureStatusCallbackListener(
    const std::string &eventName, napi_env env, napi_value callback, const std::vector<napi_value> &args)
{
    MEDIA_INFO_LOG("PhotoSessionNapi::UnregisterPressureStatusCallbackListener");
    CHECK_RETURN_ELOG(pressureCallback_ == nullptr, "pressureCallback is null");
    pressureCallback_->RemoveCallbackRef(eventName, callback);
    if (pressureCallback_->GetCallbackCount(eventName) == 0) {
        cameraSession_->UnSetPressureCallback();
        pressureCallback_ = nullptr;
    }
}

void PhotoSessionNapi::RegisterCameraSwitchRequestCallbackListener(
    const std::string &eventName, napi_env env, napi_value callback, const std::vector<napi_value> &args, bool isOnce)
{
    MEDIA_INFO_LOG("PhotoSessionNapi::RegisterCameraSwitchRequestCallbackListener is enter");
    if (cameraSwitchSessionNapiCallback_ == nullptr) {
        cameraSwitchSessionNapiCallback_ = std::make_shared<CameraSwitchRequestCallbackListener>(env);
        cameraSession_->SetCameraSwitchRequestCallback(cameraSwitchSessionNapiCallback_);
    }
    cameraSwitchSessionNapiCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoSessionNapi::UnregisterCameraSwitchRequestCallbackListener(
    const std::string &eventName, napi_env env, napi_value callback, const std::vector<napi_value> &args)
{
    MEDIA_INFO_LOG("PhotoSessionNapi::UnregisterCameraSwitchRequestCallbackListener is enter");
    if (cameraSwitchSessionNapiCallback_ == nullptr) {
        MEDIA_INFO_LOG("cameraSwitchSessionNapiCallback_ is null");
        return;
    }
    cameraSwitchSessionNapiCallback_->RemoveCallbackRef(eventName, callback);
    if (cameraSwitchSessionNapiCallback_->GetCallbackCount(eventName) == 0) {
        cameraSession_->UnSetCameraSwitchRequestCallback();
        cameraSwitchSessionNapiCallback_ = nullptr;
    }
}

extern "C" {
napi_value GetPhotoSessionNapi(napi_env env, sptr<PhotoSession> photoSession)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    return PhotoSessionNapi::CreatePhotoSessionForTransfer(env, photoSession);
}
bool GetNativePhotoSession(void *photoSessionNapiPtr, sptr<CaptureSession> &nativeSession)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    CHECK_RETURN_RET_ELOG(photoSessionNapiPtr == nullptr,
        false, "%{public}s photoSessionNapiPtr is nullptr", __func__);
    nativeSession = reinterpret_cast<PhotoSessionNapi*>(photoSessionNapiPtr)->cameraSession_;
    return true;
}
}
} // namespace CameraStandard
} // namespace OHOS