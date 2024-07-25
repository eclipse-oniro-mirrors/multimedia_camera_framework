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
 
#include "camera_napi_param_parser.h"
#include "camera_napi_security_utils.h"
#include "capture_session.h"
#include "mode/light_painting_session_napi.h"
 
namespace OHOS {
namespace CameraStandard {
using namespace std;
 
thread_local napi_ref LightPaintingSessionNapi::sConstructor_ = nullptr;
 
LightPaintingSessionNapi::LightPaintingSessionNapi() : env_(nullptr), wrapper_(nullptr)
{
}
LightPaintingSessionNapi::~LightPaintingSessionNapi()
{
    MEDIA_INFO_LOG("~LightPaintingSessionNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (lightPaintingSession_) {
        lightPaintingSession_ = nullptr;
    }
}
void LightPaintingSessionNapi::LightPaintingSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_INFO_LOG("LightPaintingSessionNapiDestructor is called");
    LightPaintingSessionNapi* cameraObj = reinterpret_cast<LightPaintingSessionNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}
napi_value LightPaintingSessionNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_INFO_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    std::vector<napi_property_descriptor> light_painting_props = {
        DECLARE_NAPI_FUNCTION("getSupportedLightPaintings", GetSupportedLightPaintings),
        DECLARE_NAPI_FUNCTION("getLightPainting", GetLightPainting),
        DECLARE_NAPI_FUNCTION("setLightPainting", SetLightPainting),
        DECLARE_NAPI_FUNCTION("triggerLighting", TriggerLighting)
    };
    std::vector<std::vector<napi_property_descriptor>> descriptors = {camera_process_props,
        color_effect_props, focus_props, manual_focus_props, zoom_props, light_painting_props};
    std::vector<napi_property_descriptor> light_painting_session_props =
        CameraNapiUtils::GetPropertyDescriptor(descriptors);
    status = napi_define_class(env, LIGHT_PAINTING_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               LightPaintingSessionNapiConstructor, nullptr,
                               light_painting_session_props.size(),
                               light_painting_session_props.data(), &ctorObj);
    if (status == napi_ok) {
        int32_t refCount = 1;
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, LIGHT_PAINTING_SESSION_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}
 
napi_value LightPaintingSessionNapi::CreateCameraSession(napi_env env)
{
    MEDIA_INFO_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSession_ = CameraManager::GetInstance()->CreateCaptureSession(SceneMode::LIGHT_PAINTING);
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("Failed to create light painting session instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSession_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("success to create light painting session napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create light painting session napi instance");
        }
    } else {
        MEDIA_ERR_LOG("Failed to create napi reference value instance");
    }
    MEDIA_ERR_LOG("Failed to create light painting session napi instance last");
    napi_get_undefined(env, &result);
    return result;
}
 
napi_value LightPaintingSessionNapi::LightPaintingSessionNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("LightPaintingSessionNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;
 
    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
 
    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<LightPaintingSessionNapi> obj = std::make_unique<LightPaintingSessionNapi>();
        obj->env_ = env;
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("sCameraSession_ is null");
            return result;
        }
        obj->lightPaintingSession_ = static_cast<LightPaintingSession*>(sCameraSession_.GetRefPtr());
        obj->cameraSession_ = obj->lightPaintingSession_;
        if (obj->lightPaintingSession_ == nullptr) {
            MEDIA_ERR_LOG("lightPaintingSession_ is null");
            return result;
        }
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            LightPaintingSessionNapi::LightPaintingSessionNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("LightPaintingSessionNapi Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("LightPaintingSessionNapi call Failed!");
    return result;
}
 
napi_value LightPaintingSessionNapi::GetSupportedLightPaintings(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetSupportedLightPaintings is called!");
        return nullptr;
    }
    MEDIA_INFO_LOG("GetSupportedLightPaintings is called");
    napi_status status;
    auto result = CameraNapiUtils::GetUndefinedValue(env);
 
    LightPaintingSessionNapi* lightPaintingSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, lightPaintingSessionNapi);
    if (lightPaintingSessionNapi->lightPaintingSession_ == nullptr) {
        MEDIA_ERR_LOG("GetSupportedLightPaintings get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return result;
    }
    status = napi_create_array(env, &result);
    std::vector<LightPaintingType> lightPaintingTypes;
    int32_t retCode = lightPaintingSessionNapi->lightPaintingSession_->GetSupportedLightPaintings(lightPaintingTypes);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("GetSupportedLightPaintings fail %{public}d", retCode);
        return nullptr;
    }
    if (!lightPaintingTypes.empty() && status == napi_ok) {
        for (size_t i = 0; i < lightPaintingTypes.size(); i++) {
            int lightPaintingType = lightPaintingTypes[i];
            napi_value value;
            napi_create_int32(env, lightPaintingType, &value);
            napi_set_element(env, result, i, value);
        }
    }
    return result;
}
 
napi_value LightPaintingSessionNapi::GetLightPainting(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetSupportedLightPaintings is called!");
        return nullptr;
    }
    MEDIA_INFO_LOG("GetLightPainting is called");
    napi_status status;
    auto result = CameraNapiUtils::GetUndefinedValue(env);
 
    LightPaintingSessionNapi* lightPaintingSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, lightPaintingSessionNapi);
    if (lightPaintingSessionNapi->lightPaintingSession_ == nullptr) {
        MEDIA_ERR_LOG("GetSupportedLightPaintings get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return result;
    }
    LightPaintingType lightPainting;
    int32_t retCode = lightPaintingSessionNapi->lightPaintingSession_->GetLightPainting(lightPainting);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("GetLightPainting fail %{public}d", retCode);
    }
    status = napi_create_int32(env, lightPainting, &result);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to get GetLightPainting!, errorCode : %{public}d", status);
    }
    return result;
}
 
napi_value LightPaintingSessionNapi::SetLightPainting(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetSupportedLightPaintings is called!");
        return nullptr;
    }
    MEDIA_INFO_LOG("SetLightPainting is called");
    auto result = CameraNapiUtils::GetUndefinedValue(env);
 
    LightPaintingSessionNapi* lightPaintingSessionNapi = nullptr;
    int32_t lightPaintingType;
    CameraNapiParamParser jsParamParser(env, info, lightPaintingSessionNapi, lightPaintingType);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("SetLightPainting parse parameter occur error");
        return result;
    }
    if (lightPaintingSessionNapi->lightPaintingSession_ == nullptr) {
        MEDIA_ERR_LOG("SetLightPainting get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return result;
    }
    lightPaintingSessionNapi->lightPaintingSession_->LockForControl();
    MEDIA_INFO_LOG("SetLightPainting is called native");
    int32_t retCode = lightPaintingSessionNapi->
        lightPaintingSession_->SetLightPainting(static_cast<LightPaintingType>(lightPaintingType));
    lightPaintingSessionNapi->lightPaintingSession_->UnlockForControl();
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("SetLightPainting fail %{public}d", retCode);
    }
    return result;
}
 
napi_value LightPaintingSessionNapi::TriggerLighting(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetSupportedLightPaintings is called!");
        return nullptr;
    }
    MEDIA_INFO_LOG("TriggerLighting is called");
    auto result = CameraNapiUtils::GetUndefinedValue(env);
 
    LightPaintingSessionNapi* lightPaintingSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, lightPaintingSessionNapi);
    if (lightPaintingSessionNapi->lightPaintingSession_ == nullptr) {
        MEDIA_ERR_LOG("TriggerLighting get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return result;
    }
    lightPaintingSessionNapi->lightPaintingSession_->LockForControl();
    int32_t retCode = lightPaintingSessionNapi->lightPaintingSession_->TriggerLighting();
    lightPaintingSessionNapi->lightPaintingSession_->UnlockForControl();
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("TriggerLighting fail %{public}d", retCode);
    }
    return result;
}
} // namespace CameraStandard
} // namespace OHOS