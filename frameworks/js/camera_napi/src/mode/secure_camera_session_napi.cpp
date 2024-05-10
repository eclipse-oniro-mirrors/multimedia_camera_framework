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

#include "mode/secure_camera_session_napi.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

thread_local napi_ref SecureCameraSessionNapi::sConstructor_ = nullptr;

SecureCameraSessionNapi::SecureCameraSessionNapi() : env_(nullptr), wrapper_(nullptr)
{
}
SecureCameraSessionNapi::~SecureCameraSessionNapi()
{
    MEDIA_DEBUG_LOG("~SecureCameraSessionNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (secureCameraSession_) {
        secureCameraSession_ = nullptr;
    }
}
void SecureCameraSessionNapi::SecureCameraSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("SecureCameraSessionNapiDestructor is called");
    SecureCameraSessionNapi* cameraObj = reinterpret_cast<SecureCameraSessionNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}
napi_value SecureCameraSessionNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    std::vector<napi_property_descriptor> manual_exposure_props = {
            DECLARE_NAPI_FUNCTION("addSecureOutput", SecureCameraSessionNapi::AddSecureOutput)
    };
    std::vector<std::vector<napi_property_descriptor>> descriptors = {camera_process_props, stabilization_props,
        flash_props, auto_exposure_props, focus_props, zoom_props, filter_props, beauty_props,
        color_effect_props, macro_props, color_management_props, manual_exposure_props};
    std::vector<napi_property_descriptor> secure_camera_session_props =
        CameraNapiUtils::GetPropertyDescriptor(descriptors);
    status = napi_define_class(env, SECURE_CAMERA_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
        SecureCameraSessionNapiConstructor, nullptr,
        secure_camera_session_props.size(),
        secure_camera_session_props.data(), &ctorObj);
    if (status == napi_ok) {
        int32_t refCount = 1;
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, SECURE_CAMERA_SESSION_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value SecureCameraSessionNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSession_ = CameraManager::GetInstance()->CreateCaptureSession(SceneMode::SECURE);
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("Failed to create Camera session instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSession_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("success to create Camera session napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Camera session napi instance");
        }
    }
    MEDIA_ERR_LOG("Failed to create Camera session napi instance last");
    napi_get_undefined(env, &result);
    return result;
}

napi_value SecureCameraSessionNapi::AddSecureOutput(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("AddSecureOutput is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_ONE, argv, ADD_OUTPUT)) {
        return result;
    }

    napi_get_undefined(env, &result);
    SecureCameraSessionNapi* secureCameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&secureCameraSessionNapi));
    if (status == napi_ok && secureCameraSessionNapi != nullptr) {
        sptr<CaptureOutput> cameraOutput = nullptr;
        MEDIA_INFO_LOG("AddSecureOutput GetJSArgsForCameraOutput is called");
        result = GetJSArgsForCameraOutput(env, argc, argv, cameraOutput);
        int32_t ret = secureCameraSessionNapi->secureCameraSession_->AddSecureOutput(cameraOutput);
        if (!CameraNapiUtils::CheckError(env, ret)) {
            return nullptr;
        }
    } else {
        MEDIA_ERR_LOG("AddOutput call Failed!");
    }
    return result;
}

napi_value SecureCameraSessionNapi::SecureCameraSessionNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SecureCameraSessionNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<SecureCameraSessionNapi> obj = std::make_unique<SecureCameraSessionNapi>();
        obj->env_ = env;
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("sCameraSession_ is null");
            return result;
        }
        obj->secureCameraSession_ = static_cast<SecureCameraSession*>(sCameraSession_.GetRefPtr());
        obj->cameraSession_ = obj->secureCameraSession_;
        if (obj->secureCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("secureCameraSession_ is null");
            return result;
        }
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           SecureCameraSessionNapi::SecureCameraSessionNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("SecureCameraSessionNapi Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("SecureCameraSessionNapi call Failed!");
    return result;
}
} // namespace CameraStandard
} // namespace OHOS