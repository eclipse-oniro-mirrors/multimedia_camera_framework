/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "input/camera_pre_launch_config_napi.h"
#include "input/camera_info_napi.h"

namespace OHOS {
namespace CameraStandard {
thread_local napi_ref CameraPrelaunchConfigNapi::sConstructor_ = nullptr;
thread_local PrelaunchConfig* CameraPrelaunchConfigNapi::sPrelaunchConfig_ = nullptr;

CameraPrelaunchConfigNapi::CameraPrelaunchConfigNapi() : prelaunchConfig_(nullptr), env_(nullptr), wrapper_(nullptr)
{
}

CameraPrelaunchConfigNapi::~CameraPrelaunchConfigNapi()
{
    MEDIA_DEBUG_LOG("~CameraPrelaunchConfigNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (sPrelaunchConfig_) {
        sPrelaunchConfig_ = nullptr;
    }
}

void CameraPrelaunchConfigNapi::CameraPrelaunchConfigNapiDestructor(
    napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CameraPrelaunchConfigNapiDestructor is called");
    CameraPrelaunchConfigNapi* cameraPrelaunchConfigNapi = reinterpret_cast<CameraPrelaunchConfigNapi*>(nativeObject);
    if (cameraPrelaunchConfigNapi != nullptr) {
        MEDIA_INFO_LOG("CameraPrelaunchConfigNapiDestructor ~");
        delete cameraPrelaunchConfigNapi;
    }
}

napi_value CameraPrelaunchConfigNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_INFO_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    napi_property_descriptor prelaunch_config_props[] = {
        DECLARE_NAPI_GETTER("cameraDevice", GetPrelaunchCameraDevice),
        DECLARE_NAPI_GETTER("restoreParamType", GetRestoreParamType),
        DECLARE_NAPI_GETTER("activeTime", GetActiveTime),
        DECLARE_NAPI_GETTER("settingParam", GetSettingParam),
    };
    status = napi_define_class(env, CAMERA_PRELAUNCH_CONFIG_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
        CameraPrelaunchConfigNapiConstructor, nullptr,
        sizeof(prelaunch_config_props) / sizeof(prelaunch_config_props[PARAM0]),
        prelaunch_config_props, &ctorObj);
    if (status == napi_ok) {
        int32_t refCount = 1;
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_PRELAUNCH_CONFIG_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

// Constructor callback
napi_value CameraPrelaunchConfigNapi::CameraPrelaunchConfigNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraPrelaunchConfigNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CameraPrelaunchConfigNapi> obj = std::make_unique<CameraPrelaunchConfigNapi>();
        obj->env_ = env;
        obj->prelaunchConfig_ = sPrelaunchConfig_;
        MEDIA_INFO_LOG("CameraPrelaunchConfigNapiConstructor cameraId = %{public}s",
            obj->prelaunchConfig_->GetCameraDevice()->GetID().c_str());
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            CameraPrelaunchConfigNapi::CameraPrelaunchConfigNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("CameraPrelaunchConfigNapiConstructor call Failed!");
    return result;
}

napi_value CameraPrelaunchConfigNapi::GetPrelaunchCameraDevice(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetPrelaunchCameraDevice is called");
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraPrelaunchConfigNapi* obj = nullptr;
    sptr<CameraDevice> cameraDevice;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        cameraDevice = obj->prelaunchConfig_->GetCameraDevice();
        MEDIA_INFO_LOG("GetPrelaunchCameraDevice cameraId = %{public}s",
            obj->prelaunchConfig_->GetCameraDevice()->GetID().c_str());
        jsResult = CameraDeviceNapi::CreateCameraObj(env, cameraDevice);
        return jsResult;
    }
    MEDIA_ERR_LOG("GetPrelaunchCameraDevice call Failed!");
    return undefinedResult;
}

napi_value CameraPrelaunchConfigNapi::GetRestoreParamType(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetCameraProfileSize is called");
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraPrelaunchConfigNapi* obj = nullptr;
    napi_value thisVar = nullptr;
    RestoreParamType restoreParamType;

    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        restoreParamType = obj->prelaunchConfig_->GetRestoreParamType();
        status = napi_create_int32(env, restoreParamType, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        } else {
            MEDIA_ERR_LOG("Failed to get CameraProfileHeight!, errorCode : %{public}d", status);
        }
    }
    MEDIA_ERR_LOG("GetCameraProfileSize call Failed!");
    return undefinedResult;
}

napi_value CameraPrelaunchConfigNapi::GetActiveTime(napi_env env, napi_callback_info info)
{
        MEDIA_DEBUG_LOG("GetActiveTime is called");
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraPrelaunchConfigNapi* obj = nullptr;
    int32_t activeTime;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        activeTime = obj->prelaunchConfig_->GetActiveTime();
        status = napi_create_int32(env, activeTime, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        } else {
            MEDIA_ERR_LOG("Failed to get CameraProfileHeight!, errorCode : %{public}d", status);
        }
    }
    return undefinedResult;
}

napi_value CameraPrelaunchConfigNapi::GetSettingParam(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetCameraProfileSize is called");
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraPrelaunchConfigNapi* obj = nullptr;
    SettingParam settingParam;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        settingParam.skinSmoothLevel = obj->prelaunchConfig_->GetSettingParam().skinSmoothLevel;
        settingParam.faceSlender = obj->prelaunchConfig_->GetSettingParam().faceSlender;
        settingParam.skinTone = obj->prelaunchConfig_->GetSettingParam().skinTone;
        jsResult = CameraSettingParamNapi::CreateCameraSettingParam(env, settingParam);
        return jsResult;
    }
    MEDIA_ERR_LOG("GetCameraProfileSize call Failed!");
    return undefinedResult;
}
} // namespace CameraStandard
} // namespace OHOS