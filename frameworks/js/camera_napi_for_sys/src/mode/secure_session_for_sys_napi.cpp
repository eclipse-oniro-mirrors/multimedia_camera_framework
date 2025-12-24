/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "mode/secure_session_for_sys_napi.h"

#include "input/camera_manager_for_sys.h"
#include "session/secure_camera_session.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

thread_local napi_ref SecureSessionForSysNapi::sConstructor_ = nullptr;

SecureSessionForSysNapi::SecureSessionForSysNapi() : env_(nullptr) {}
SecureSessionForSysNapi::~SecureSessionForSysNapi()
{
    MEDIA_DEBUG_LOG("~SecureSessionForSysNapi is called");
}
void SecureSessionForSysNapi::SecureSessionForSysNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("SecureSessionForSysNapiDestructor is called");
    SecureSessionForSysNapi* cameraObj = reinterpret_cast<SecureSessionForSysNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}
void SecureSessionForSysNapi::Init(napi_env env)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    std::vector<napi_property_descriptor> add_secure_output_props = {
            DECLARE_NAPI_FUNCTION("addSecureOutput", SecureSessionForSysNapi::AddSecureOutput)
    };
    std::vector<std::vector<napi_property_descriptor>> descriptors = { camera_process_props,
        CameraSessionForSysNapi::camera_process_sys_props, stabilization_props, flash_props,
        CameraSessionForSysNapi::flash_sys_props, auto_exposure_props, focus_props,
        CameraSessionForSysNapi::focus_sys_props, zoom_props, CameraSessionForSysNapi::zoom_sys_props,
        filter_props, beauty_sys_props, color_effect_sys_props, macro_props, color_management_props,
        add_secure_output_props, white_balance_props };
    std::vector<napi_property_descriptor> secure_camera_session_props =
        CameraNapiUtils::GetPropertyDescriptor(descriptors);
    status = napi_define_class(env, SECURE_CAMERA_SESSION_FOR_SYS_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
        SecureSessionForSysNapiConstructor, nullptr,
        secure_camera_session_props.size(),
        secure_camera_session_props.data(), &ctorObj);
    CHECK_RETURN_ELOG(status != napi_ok, "SecureSessionForSysNapi defined class failed");
    status = NapiRefManager::CreateMemSafetyRef(env, ctorObj, &sConstructor_);
    CHECK_RETURN_ELOG(status != napi_ok, "SecureSessionForSysNapi Init failed");
    MEDIA_DEBUG_LOG("SecureSessionForSysNapi Init success");
}

napi_value SecureSessionForSysNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    if (sConstructor_ == nullptr) {
        SecureSessionForSysNapi::Init(env);
        CHECK_RETURN_RET_ELOG(sConstructor_ == nullptr, result, "sConstructor_ is null");
    }
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSessionForSys_ =
            CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::SECURE);
        if (sCameraSessionForSys_ == nullptr) {
            MEDIA_ERR_LOG("Failed to create Camera session instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSessionForSys_ = nullptr;
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

napi_value SecureSessionForSysNapi::SecureSessionForSysNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SecureSessionForSysNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<SecureSessionForSysNapi> obj = std::make_unique<SecureSessionForSysNapi>();
        obj->env_ = env;
        CHECK_RETURN_RET_ELOG(sCameraSessionForSys_ == nullptr, result, "sCameraSessionForSys_ is null");
        obj->secureCameraSessionForSys_ = static_cast<SecureCameraSessionForSys*>(sCameraSessionForSys_.GetRefPtr());
        obj->cameraSessionForSys_ = obj->secureCameraSessionForSys_;
        obj->cameraSession_ = obj->secureCameraSessionForSys_;
        CHECK_RETURN_RET_ELOG(obj->secureCameraSessionForSys_ == nullptr, result, "secureCameraSessionForSys_ is null");
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           SecureSessionForSysNapi::SecureSessionForSysNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("SecureSessionForSysNapi Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("SecureSessionForSysNapi call Failed!");
    return result;
}

napi_value SecureSessionForSysNapi::AddSecureOutput(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("AddSecureOutput is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    CHECK_RETURN_RET(!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_ONE, argv, ADD_OUTPUT), result);

    napi_get_undefined(env, &result);
    SecureSessionForSysNapi* secureSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&secureSessionForSysNapi));
    if (status == napi_ok && secureSessionForSysNapi != nullptr) {
        sptr<CaptureOutput> cameraOutput = nullptr;
        MEDIA_INFO_LOG("AddSecureOutput GetJSArgsForCameraOutput is called");
        result = GetJSArgsForCameraOutput(env, argc, argv, cameraOutput);
        CHECK_EXECUTE(cameraOutput == nullptr, NAPI_ASSERT(env, false, "type mismatch"));
        int32_t ret = secureSessionForSysNapi->secureCameraSessionForSys_->AddSecureOutput(cameraOutput);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, ret), nullptr);
    } else {
        MEDIA_ERR_LOG("AddOutput call Failed!");
    }
    return result;
}

} // namespace CameraStandard
} // namespace OHOS