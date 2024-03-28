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

#include "input/camera_setting_param_napi.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

thread_local napi_ref CameraSettingParamNapi::sConstructor_ = nullptr;
thread_local SettingParam* CameraSettingParamNapi::sCameraSettingParam_ = nullptr;

CameraSettingParamNapi::CameraSettingParamNapi() : cameraSettingParam_(nullptr), env_(nullptr), wrapper_(nullptr)
{
}

CameraSettingParamNapi::~CameraSettingParamNapi()
{
    MEDIA_DEBUG_LOG("~CameraSettingParamNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (cameraSettingParam_) {
        cameraSettingParam_ = nullptr;
    }
}

void CameraSettingParamNapi::CameraSettingParamNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CameraSettingParamNapiDestructor is called");
    CameraSettingParamNapi* cameraSettingParam_ = reinterpret_cast<CameraSettingParamNapi*>(nativeObject);
    if (cameraSettingParam_ != nullptr) {
        delete cameraSettingParam_;
    }
}

napi_value CameraSettingParamNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor camera_size_props[] = {
        DECLARE_NAPI_GETTER("skinSmoothLevel", GetCameraSmoothLevel),
        DECLARE_NAPI_GETTER("faceSlender", GetCameraFaceSlender),
        DECLARE_NAPI_GETTER("skinTone", GetCameraSkinTone)
    };

    status = napi_define_class(env, CAMERA_SETTINGPARAM_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
        CameraSettingParamNapiConstructor, nullptr,
        sizeof(camera_size_props) / sizeof(camera_size_props[PARAM0]),
        camera_size_props, &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_SETTINGPARAM_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

// Constructor callback
napi_value CameraSettingParamNapi::CameraSettingParamNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraSettingParamNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CameraSettingParamNapi> obj = std::make_unique<CameraSettingParamNapi>();
        obj->env_ = env;
        obj->cameraSettingParam_= sCameraSettingParam_;
        MEDIA_INFO_LOG("CameraSettingParamNapiConstructor "
            "settingParam.skinSmoothLevel= %{public}d, settingParam.faceSlender = %{public}d",
            obj->cameraSettingParam_->skinSmoothLevel, obj->cameraSettingParam_->faceSlender);
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            CameraSettingParamNapi::CameraSettingParamNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("CameraSettingParamNapiConstructor call Failed!");
    return result;
}

napi_value CameraSettingParamNapi::CreateCameraSettingParam(napi_env env, SettingParam &cameraSettingParam)
{
    MEDIA_DEBUG_LOG("CreateCameraSettingParam is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        std::unique_ptr<SettingParam> settingParamPtr = std::make_unique<SettingParam>();
        settingParamPtr->skinSmoothLevel = cameraSettingParam.skinSmoothLevel;
        settingParamPtr->faceSlender = cameraSettingParam.faceSlender;
        settingParamPtr->skinTone = cameraSettingParam.skinTone;
        MEDIA_INFO_LOG("CreateCameraSettingParam skinSmoothLevel = %{public}d,"
            "settingParama.faceSlender = %{public}d", settingParamPtr->skinSmoothLevel, settingParamPtr->faceSlender);
        sCameraSettingParam_ = reinterpret_cast<SettingParam*>(settingParamPtr.get());
        MEDIA_INFO_LOG("CreateCameraSettingParam skinSmoothLevel = %{public}d, faceSlender = %{public}d",
            settingParamPtr->skinSmoothLevel, settingParamPtr->faceSlender);
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Camera obj instance");
        }
    }
    MEDIA_ERR_LOG("CreateCameraSettingParam call Failed!");
    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraSettingParamNapi::GetCameraSmoothLevel(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetCameraSmoothLevel is called");
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraSettingParamNapi* obj = nullptr;
    uint32_t cameraSkinSmoothLevel = 0;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        cameraSkinSmoothLevel = static_cast<uint32_t>(obj->cameraSettingParam_->skinSmoothLevel);
        MEDIA_INFO_LOG("GetCameraSettingParam skinSmoothLevel = %{public}d",
            obj->cameraSettingParam_->skinSmoothLevel);
        status = napi_create_uint32(env, cameraSkinSmoothLevel, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        } else {
            MEDIA_ERR_LOG("Failed to get GetCameraBeauty!, errorCode : %{public}d", status);
        }
    }
    MEDIA_ERR_LOG("GetCameraBeauty call Failed!");
    return undefinedResult;
}

napi_value CameraSettingParamNapi::GetCameraFaceSlender(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetCameraColorEffect is called");
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraSettingParamNapi* obj = nullptr;
    uint32_t cameraFaceSlender = 0;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        cameraFaceSlender = static_cast<uint32_t>(obj->cameraSettingParam_->faceSlender);
        MEDIA_INFO_LOG("GetCameraColorEffect cameraFaceSlender = %{public}d",
            obj->cameraSettingParam_->faceSlender);
        status = napi_create_uint32(env, cameraFaceSlender, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        } else {
            MEDIA_ERR_LOG("Failed to get GetCameraColorEffect!, errorCode : %{public}d", status);
        }
    }
    MEDIA_ERR_LOG("GetCameraColorEffect call Failed!");
    return undefinedResult;
}

napi_value CameraSettingParamNapi::GetCameraSkinTone(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetCameraColorEffect is called");
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    CameraSettingParamNapi* obj = nullptr;
    uint32_t cameraSkinTone = 0;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status != napi_ok || thisVar == nullptr) {
        MEDIA_ERR_LOG("Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        cameraSkinTone = static_cast<uint32_t>(obj->cameraSettingParam_->skinTone);
        MEDIA_INFO_LOG("GetCameraColorEffect skinTone = %{public}d", obj->cameraSettingParam_->skinTone);
        status = napi_create_uint32(env, cameraSkinTone, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        } else {
            MEDIA_ERR_LOG("Failed to get GetCameraColorEffect!, errorCode : %{public}d", status);
        }
    }
    MEDIA_ERR_LOG("GetCameraColorEffect call Failed!");
    return undefinedResult;
}
} // namespace CameraStandard
} // namespace OHOS
