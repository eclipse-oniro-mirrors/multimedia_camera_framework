/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "mode/night_session_napi.h"
#include "uv.h"
namespace OHOS {
namespace CameraStandard {
using namespace std;

thread_local napi_ref NightSessionNapi::sConstructor_ = nullptr;

NightSessionNapi::NightSessionNapi() : env_(nullptr), wrapper_(nullptr)
{
}
NightSessionNapi::~NightSessionNapi()
{
    MEDIA_DEBUG_LOG("~NightSessionNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (nightSession_) {
        nightSession_ = nullptr;
    }
}
void NightSessionNapi::NightSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("NightSessionNapiDestructor is called");
    NightSessionNapi* cameraObj = reinterpret_cast<NightSessionNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}
napi_value NightSessionNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    std::vector<napi_property_descriptor> manual_exposure_props = {
        DECLARE_NAPI_FUNCTION("getSupportedExposureRange", NightSessionNapi::GetSupportedExposureRange),
        DECLARE_NAPI_FUNCTION("getExposure", NightSessionNapi::GetExposure),
        DECLARE_NAPI_FUNCTION("setExposure", NightSessionNapi::SetExposure)
    };
    std::vector<std::vector<napi_property_descriptor>> descriptors = {camera_process_props, stabilization_props,
        flash_props, auto_exposure_props, focus_props, zoom_props, filter_props, beauty_props,
        color_effect_props, macro_props, color_management_props, manual_exposure_props};
    std::vector<napi_property_descriptor> night_session_props = CameraNapiUtils::GetPropertyDescriptor(descriptors);
    status = napi_define_class(env, NIGHT_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               NightSessionNapiConstructor, nullptr,
                               night_session_props.size(),
                               night_session_props.data(), &ctorObj);
    if (status == napi_ok) {
        int32_t refCount = 1;
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, NIGHT_SESSION_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value NightSessionNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSession_ = CameraManager::GetInstance()->CreateCaptureSession(SceneMode::NIGHT);
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

napi_value NightSessionNapi::GetSupportedExposureRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedExposureRange is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    NightSessionNapi* nightSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&nightSessionNapi));
    if (status == napi_ok && nightSessionNapi != nullptr) {
        std::vector<uint32_t> vecExposureList;
        int32_t retCode = nightSessionNapi->nightSession_->GetExposureRange(vecExposureList);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        if (vecExposureList.empty() || napi_create_array(env, &result) != napi_ok) {
            return result;
        }
        for (size_t i = 0; i < vecExposureList.size(); i++) {
            uint32_t exposure = vecExposureList[i];
            MEDIA_DEBUG_LOG("EXPOSURE_RANGE : exposure = %{public}d", vecExposureList[i]);
            napi_value value;
            napi_create_uint32(env, exposure, &value);
            napi_set_element(env, result, i, value);
        }
        MEDIA_DEBUG_LOG("EXPOSURE_RANGE ExposureList size : %{public}zu", vecExposureList.size());
    } else {
        MEDIA_ERR_LOG("GetExposureBiasRange call Failed!");
    }
    return result;
}

napi_value NightSessionNapi::GetExposure(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetExposure is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    NightSessionNapi* nightSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&nightSessionNapi));
    if (status == napi_ok && nightSessionNapi!= nullptr) {
        uint32_t exposureValue;
        int32_t retCode = nightSessionNapi->nightSession_->GetExposure(exposureValue);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        MEDIA_DEBUG_LOG("GetExposure : exposure = %{public}d", exposureValue);
        napi_create_uint32(env, exposureValue, &result);
    } else {
        MEDIA_ERR_LOG("GetExposure call Failed!");
    }
    return result;
}

napi_value NightSessionNapi::SetExposure(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetExposure is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    NightSessionNapi* nightSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&nightSessionNapi));
    if (status == napi_ok && nightSessionNapi != nullptr) {
        uint32_t exposureValue;
        napi_get_value_uint32(env, argv[PARAM0], &exposureValue);
        MEDIA_DEBUG_LOG("SetExposure : exposure = %{public}d", exposureValue);
        nightSessionNapi->nightSession_->LockForControl();
        int32_t retCode = nightSessionNapi->nightSession_->SetExposure(exposureValue);
        nightSessionNapi->nightSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
    } else {
        MEDIA_ERR_LOG("SetExposure call Failed!");
    }
    return result;
}

napi_value NightSessionNapi::NightSessionNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("NightSessionNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<NightSessionNapi> obj = std::make_unique<NightSessionNapi>();
        obj->env_ = env;
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("sCameraSession_ is null");
            return result;
        }
        obj->nightSession_ = static_cast<NightSession*>(sCameraSession_.GetRefPtr());
        obj->cameraSession_ = obj->nightSession_;
        if (obj->nightSession_ == nullptr) {
            MEDIA_ERR_LOG("nightSession_ is null");
            return result;
        }
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            NightSessionNapi::NightSessionNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("NightSessionNapi Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("NightSessionNapi call Failed!");
    return result;
}
} // namespace CameraStandard
} // namespace OHOS