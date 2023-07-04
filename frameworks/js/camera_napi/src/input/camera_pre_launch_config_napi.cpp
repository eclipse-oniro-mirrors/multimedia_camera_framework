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
thread_local napi_ref CameraPreLaunchConfigNapi::sConstructor_ = nullptr;
thread_local PreLaunchConfig* CameraPreLaunchConfigNapi::sPreLaunchConfig_ = nullptr;

CameraPreLaunchConfigNapi::CameraPreLaunchConfigNapi() : env_(nullptr), wrapper_(nullptr)
{
}

CameraPreLaunchConfigNapi::~CameraPreLaunchConfigNapi()
{
    MEDIA_DEBUG_LOG("~CameraPreLaunchConfigNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (sPreLaunchConfig_) {
        sPreLaunchConfig_ = nullptr;
    }
}

void CameraPreLaunchConfigNapi::CameraPreLaunchConfigNapiDestructor(
    napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CameraPreLaunchConfigNapiDestructor is called");
    CameraPreLaunchConfigNapi* cameraPreLaunchConfigNapi = reinterpret_cast<CameraPreLaunchConfigNapi*>(nativeObject);
    if (cameraPreLaunchConfigNapi != nullptr) {
        MEDIA_INFO_LOG("CameraPreLaunchConfigNapiDestructor ~");
        cameraPreLaunchConfigNapi->~CameraPreLaunchConfigNapi();
    }
}

napi_value CameraPreLaunchConfigNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_INFO_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    napi_property_descriptor prelaunch_config_props[] = {
        DECLARE_NAPI_GETTER("cameraDevice", GetPreLaunchCameraDevice)
    };
    status = napi_define_class(env, CAMERA_PRELAUNCH_CONFIG_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
        CameraPreLaunchConfigNapiConstructor, nullptr,
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
napi_value CameraPreLaunchConfigNapi::CameraPreLaunchConfigNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraProfileNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CameraPreLaunchConfigNapi> obj = std::make_unique<CameraPreLaunchConfigNapi>();
        obj->env_ = env;
        obj->preLaunchConfig_ = sPreLaunchConfig_;
        MEDIA_INFO_LOG("CameraPreLaunchConfigNapiConstructor cameraId = %{public}s",
            obj->preLaunchConfig_->GetCameraDevice()->GetID().c_str());
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            CameraPreLaunchConfigNapi::CameraPreLaunchConfigNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("CameraPreLaunchConfigNapiConstructor call Failed!");
    return result;
}

napi_value CameraPreLaunchConfigNapi::GetPreLaunchCameraDevice(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetCameraProfileSize is called");
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraPreLaunchConfigNapi* obj = nullptr;
    sptr<CameraDevice> cameraDevice;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        cameraDevice = obj->preLaunchConfig_->GetCameraDevice();
        MEDIA_INFO_LOG("GetPreLaunchCameraDevice cameraId = %{public}s",
            obj->preLaunchConfig_->GetCameraDevice()->GetID().c_str());
        jsResult = CameraDeviceNapi::CreateCameraObj(env, cameraDevice);
        return jsResult;
    }
    MEDIA_ERR_LOG("GetCameraProfileSize call Failed!");
    return undefinedResult;
}
} // namespace CameraStandard
} // namespace OHOS