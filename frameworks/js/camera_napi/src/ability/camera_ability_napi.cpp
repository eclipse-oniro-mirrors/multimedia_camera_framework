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

#include "ability/camera_ability_napi.h"
#include "camera_log.h"
#include "camera_napi_utils.h"
#include "napi/native_common.h"
#include "napi/native_api.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
thread_local sptr<CameraAbility> CameraFunctionsNapi::sCameraAbility_ = nullptr;
thread_local napi_ref CameraFunctionsNapi::sPhotoConstructor_ = nullptr;
thread_local napi_ref CameraFunctionsNapi::sPhotoConflictConstructor_ = nullptr;
thread_local napi_ref CameraFunctionsNapi::sPortraitPhotoConstructor_ = nullptr;
thread_local napi_ref CameraFunctionsNapi::sPortraitPhotoConflictConstructor_ = nullptr;
thread_local napi_ref CameraFunctionsNapi::sVideoConstructor_ = nullptr;
thread_local napi_ref CameraFunctionsNapi::sVideoConflictConstructor_ = nullptr;

const std::map<FunctionsType, const char*> CameraFunctionsNapi::functionsNameMap_ = {
    {FunctionsType::PHOTO_FUNCTIONS, PHOTO_ABILITY_NAPI_CLASS_NAME},
    {FunctionsType::PHOTO_CONFLICT_FUNCTIONS, PHOTO_CONFLICT_ABILITY_NAPI_CLASS_NAME},
    {FunctionsType::PORTRAIT_PHOTO_FUNCTIONS, PORTRAIT_PHOTO_ABILITY_NAPI_CLASS_NAME},
    {FunctionsType::PORTRAIT_PHOTO_CONFLICT_FUNCTIONS, PORTRAIT_PHOTO_CONFLICT_ABILITY_NAPI_CLASS_NAME},
    {FunctionsType::VIDEO_FUNCTIONS, VIDEO_ABILITY_NAPI_CLASS_NAME},
    {FunctionsType::VIDEO_CONFLICT_FUNCTIONS, VIDEO_CONFLICT_ABILITY_NAPI_CLASS_NAME}
};

const std::vector<napi_property_descriptor> CameraFunctionsNapi::flash_query_props = {
    DECLARE_NAPI_FUNCTION("hasFlash", CameraFunctionsNapi::HasFlash),
    DECLARE_NAPI_FUNCTION("isFlashModeSupported", CameraFunctionsNapi::IsFlashModeSupported),
    DECLARE_NAPI_FUNCTION("isLcdFlashSupported", CameraFunctionsNapi::IsLcdFlashSupported),
};

const std::vector<napi_property_descriptor> CameraFunctionsNapi::auto_exposure_query_props = {
    DECLARE_NAPI_FUNCTION("isExposureModeSupported", CameraFunctionsNapi::IsExposureModeSupported),
    DECLARE_NAPI_FUNCTION("getExposureBiasRange", CameraFunctionsNapi::GetExposureBiasRange)
};

const std::vector<napi_property_descriptor> CameraFunctionsNapi::focus_query_props = {
    DECLARE_NAPI_FUNCTION("isFocusModeSupported", CameraFunctionsNapi::IsFocusModeSupported)
};

const std::vector<napi_property_descriptor> CameraFunctionsNapi::zoom_query_props = {
    DECLARE_NAPI_FUNCTION("getZoomRatioRange", CameraFunctionsNapi::GetZoomRatioRange)
};

const std::vector<napi_property_descriptor> CameraFunctionsNapi::beauty_query_props = {
    DECLARE_NAPI_FUNCTION("getSupportedBeautyTypes", CameraFunctionsNapi::GetSupportedBeautyTypes),
    DECLARE_NAPI_FUNCTION("getSupportedBeautyRange", CameraFunctionsNapi::GetSupportedBeautyRange)
};

const std::vector<napi_property_descriptor> CameraFunctionsNapi::color_effect_query_props = {
    DECLARE_NAPI_FUNCTION("getSupportedColorEffects", CameraFunctionsNapi::GetSupportedColorEffects)
};

const std::vector<napi_property_descriptor> CameraFunctionsNapi::color_management_query_props = {
    DECLARE_NAPI_FUNCTION("getSupportedColorSpaces", CameraFunctionsNapi::GetSupportedColorSpaces)
};

const std::vector<napi_property_descriptor> CameraFunctionsNapi::macro_query_props = {
    DECLARE_NAPI_FUNCTION("isMacroSupported", CameraFunctionsNapi::IsMacroSupported)
};

const std::vector<napi_property_descriptor> CameraFunctionsNapi::portrait_query_props = {
    DECLARE_NAPI_FUNCTION("getSupportedPortraitEffects", CameraFunctionsNapi::GetSupportedPortraitEffects)
};

const std::vector<napi_property_descriptor> CameraFunctionsNapi::aperture_query_props = {
    DECLARE_NAPI_FUNCTION("getSupportedVirtualApertures", CameraFunctionsNapi::GetSupportedVirtualApertures),
    DECLARE_NAPI_FUNCTION("getSupportedPhysicalApertures", CameraFunctionsNapi::GetSupportedPhysicalApertures)
};

const std::vector<napi_property_descriptor> CameraFunctionsNapi::stabilization_query_props = {
    DECLARE_NAPI_FUNCTION("isVideoStabilizationModeSupported", CameraFunctionsNapi::IsVideoStabilizationModeSupported)
};

const std::vector<napi_property_descriptor> CameraFunctionsNapi::manual_exposure_query_props = {
    DECLARE_NAPI_FUNCTION("getSupportedExposureRange", CameraFunctionsNapi::GetSupportedExposureRange),
};

const std::vector<napi_property_descriptor> CameraFunctionsNapi::features_query_props = {
    DECLARE_NAPI_FUNCTION("isSceneFeatureSupported", CameraFunctionsNapi::IsFeatureSupported),
};

const std::map<FunctionsType, Descriptor> CameraFunctionsNapi::functionsDescMap_ = {
    {FunctionsType::PHOTO_FUNCTIONS, {flash_query_props, auto_exposure_query_props, focus_query_props, zoom_query_props,
        beauty_query_props, color_effect_query_props, color_management_query_props, macro_query_props,
        manual_exposure_query_props, features_query_props}},
    {FunctionsType::PORTRAIT_PHOTO_FUNCTIONS, {flash_query_props, auto_exposure_query_props, focus_query_props,
        zoom_query_props, beauty_query_props, color_effect_query_props, color_management_query_props,
        portrait_query_props, aperture_query_props, features_query_props}},
    {FunctionsType::VIDEO_FUNCTIONS, {flash_query_props, auto_exposure_query_props, focus_query_props, zoom_query_props,
        stabilization_query_props, beauty_query_props, color_effect_query_props, color_management_query_props,
        macro_query_props, manual_exposure_query_props, features_query_props}},
    {FunctionsType::PHOTO_CONFLICT_FUNCTIONS, {zoom_query_props, macro_query_props}},
    {FunctionsType::PORTRAIT_PHOTO_CONFLICT_FUNCTIONS, {zoom_query_props, portrait_query_props, aperture_query_props}},
    {FunctionsType::VIDEO_CONFLICT_FUNCTIONS, {zoom_query_props, macro_query_props}}};

napi_value CameraFunctionsNapi::Init(napi_env env, napi_value exports, FunctionsType type)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;
    std::vector<std::vector<napi_property_descriptor>> descriptors;
    auto nameIt = functionsNameMap_.find(type);
    if  (nameIt == functionsNameMap_.end()) {
        MEDIA_ERR_LOG("Init call Failed, className not find");
        return nullptr;
    }
    auto className = nameIt->second;

    auto descIt = functionsDescMap_.find(type);
    if  (descIt == functionsDescMap_.end()) {
        MEDIA_ERR_LOG("Init call Failed, descriptors not find");
        return nullptr;
    }
    std::vector<napi_property_descriptor> camera_ability_props = CameraNapiUtils::GetPropertyDescriptor(descIt->second);

    status = napi_define_class(env, className, NAPI_AUTO_LENGTH,
                               CameraFunctionsNapiConstructor, nullptr,
                               camera_ability_props.size(),
                               camera_ability_props.data(), &ctorObj);
    if (status == napi_ok) {
        if (type == FunctionsType::PHOTO_FUNCTIONS) {
            status = napi_create_reference(env, ctorObj, refCount, &sPhotoConstructor_);
        } else if (type == FunctionsType::PHOTO_CONFLICT_FUNCTIONS) {
            status = napi_create_reference(env, ctorObj, refCount, &sPhotoConflictConstructor_);
        } else if (type == FunctionsType::PORTRAIT_PHOTO_FUNCTIONS) {
            status = napi_create_reference(env, ctorObj, refCount, &sPortraitPhotoConstructor_);
        } else if (type == FunctionsType::PORTRAIT_PHOTO_CONFLICT_FUNCTIONS) {
            status = napi_create_reference(env, ctorObj, refCount, &sPortraitPhotoConflictConstructor_);
        } else if (type == FunctionsType::VIDEO_FUNCTIONS) {
            status = napi_create_reference(env, ctorObj, refCount, &sVideoConstructor_);
        } else if (type == FunctionsType::VIDEO_CONFLICT_FUNCTIONS) {
            status = napi_create_reference(env, ctorObj, refCount, &sVideoConflictConstructor_);
        } else {
            return nullptr;
        }

        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, className, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed");
    return nullptr;
}

napi_value CameraFunctionsNapi::CreateCameraFunctions(napi_env env, sptr<CameraAbility> functions, FunctionsType type)
{
    MEDIA_DEBUG_LOG("CreateCameraFunctions is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    if (type == FunctionsType::PHOTO_FUNCTIONS) {
        status = napi_get_reference_value(env, sPhotoConstructor_, &constructor);
    } else if (type == FunctionsType::PHOTO_CONFLICT_FUNCTIONS) {
        status = napi_get_reference_value(env, sPhotoConflictConstructor_, &constructor);
    } else if (type == FunctionsType::PORTRAIT_PHOTO_FUNCTIONS) {
        status = napi_get_reference_value(env, sPortraitPhotoConstructor_, &constructor);
    } else if (type == FunctionsType::PORTRAIT_PHOTO_CONFLICT_FUNCTIONS) {
        status = napi_get_reference_value(env, sPortraitPhotoConflictConstructor_, &constructor);
    } else if (type == FunctionsType::VIDEO_FUNCTIONS) {
        status = napi_get_reference_value(env, sVideoConstructor_, &constructor);
    } else if (type == FunctionsType::VIDEO_CONFLICT_FUNCTIONS) {
        status = napi_get_reference_value(env, sVideoConflictConstructor_, &constructor);
    } else {
        MEDIA_ERR_LOG("CreateCameraFunctions call Failed type not find");
        napi_get_undefined(env, &result);
        return result;
    }

    if (status == napi_ok) {
        sCameraAbility_ = functions;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraAbility_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create camera functions instance");
        }
    }
    MEDIA_ERR_LOG("CreateCameraFunctions call Failed");
    napi_get_undefined(env, &result);
    return result;
}

CameraFunctionsNapi::CameraFunctionsNapi() : env_(nullptr), wrapper_(nullptr) {}

CameraFunctionsNapi::~CameraFunctionsNapi()
{
    MEDIA_DEBUG_LOG("~CameraFunctionsNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (cameraAbility_) {
        cameraAbility_ = nullptr;
    }
}

napi_value CameraFunctionsNapi::CameraFunctionsNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraFunctionsNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CameraFunctionsNapi> obj = std::make_unique<CameraFunctionsNapi>();
        obj->env_ = env;
        obj->cameraAbility_ = sCameraAbility_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            CameraFunctionsNapi::CameraFunctionsNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("CameraFunctionsNapiConstructor call Failed");
    return result;
}

void CameraFunctionsNapi::CameraFunctionsNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CameraFunctionsNapiDestructor is called");
    CameraFunctionsNapi* cameraAbilityNapi = reinterpret_cast<CameraFunctionsNapi*>(nativeObject);
    if (cameraAbilityNapi != nullptr) {
        delete cameraAbilityNapi;
    }
}

template<typename U>
napi_value CameraFunctionsNapi::HandleQuery(napi_env env, napi_callback_info info, napi_value thisVar, U queryFunction)
{
    napi_status status;
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    CameraFunctionsNapi* napiObj = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&napiObj));
    if (status == napi_ok && napiObj != nullptr && napiObj->GetNativeObj() != nullptr) {
        auto queryResult = queryFunction(napiObj->GetNativeObj());
        if constexpr(std::is_same_v<decltype(queryResult), bool>) {
            napi_get_boolean(env, queryResult, &result);
        } else if constexpr(std::is_same_v<decltype(queryResult), std::vector<int32_t>>
                         || std::is_enum_v<typename decltype(queryResult)::value_type>) {
            status = napi_create_array(env, &result);
            CHECK_ERROR_RETURN_RET_LOG(status != napi_ok, result, "napi_create_array call Failed!");
            for (size_t i = 0; i < queryResult.size(); i++) {
                int32_t value = queryResult[i];
                napi_value element;
                napi_create_int32(env, value, &element);
                napi_set_element(env, result, i, element);
            }
        } else if constexpr(std::is_same_v<decltype(queryResult), std::vector<uint32_t>>) {
            status = napi_create_array(env, &result);
            CHECK_ERROR_RETURN_RET_LOG(status != napi_ok, result, "napi_create_array call Failed!");
            for (size_t i = 0; i < queryResult.size(); i++) {
                uint32_t value = queryResult[i];
                napi_value element;
                napi_create_uint32(env, value, &element);
                napi_set_element(env, result, i, element);
            }
        } else if constexpr(std::is_same_v<decltype(queryResult), std::vector<float>>) {
            status = napi_create_array(env, &result);
            CHECK_ERROR_RETURN_RET_LOG(status != napi_ok, result, "napi_create_array call Failed!");
            for (size_t i = 0; i < queryResult.size(); i++) {
                float value = queryResult[i];
                napi_value element;
                napi_create_double(env, CameraNapiUtils::FloatToDouble(value), &element);
                napi_set_element(env, result, i, element);
            }
        } else {
            MEDIA_ERR_LOG("Unhandled type in HandleQuery");
        }
    } else {
        MEDIA_ERR_LOG("Query function call Failed!");
    }
    return result;
}

napi_value CameraFunctionsNapi::HasFlash(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("HasFlash is called");
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->HasFlash();
    });
}

napi_value CameraFunctionsNapi::IsFlashModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsFlashModeSupported is called");
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return HandleQuery(env, info, thisVar, [env, argv](auto ability) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        FlashMode flashMode = (FlashMode)value;
        return ability->IsFlashModeSupported(flashMode);
    });
}

napi_value CameraFunctionsNapi::IsLcdFlashSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsLcdFlashSupported is called");
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return HandleQuery(env, info, thisVar, [env, argv](auto ability) {
        return ability->IsLcdFlashSupported();
    });
}

napi_value CameraFunctionsNapi::IsExposureModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsExposureModeSupported is called");
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return HandleQuery(env, info, thisVar, [env, argv](auto ability) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        ExposureMode exposureMode = (ExposureMode)value;
        return ability->IsExposureModeSupported(exposureMode);
    });
}

napi_value CameraFunctionsNapi::GetExposureBiasRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetExposureBiasRange is called");
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->GetExposureBiasRange();
    });
}

napi_value CameraFunctionsNapi::IsFocusModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsFocusModeSupported is called");
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return HandleQuery(env, info, thisVar, [env, argv](auto ability) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        FocusMode focusMode = (FocusMode)value;
        return ability->IsFocusModeSupported(focusMode);
    });
}

napi_value CameraFunctionsNapi::GetZoomRatioRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetZoomRatioRange is called");
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->GetZoomRatioRange();
    });
}

napi_value CameraFunctionsNapi::GetSupportedBeautyTypes(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedBeautyTypes is called");
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->GetSupportedBeautyTypes();
    });
}

napi_value CameraFunctionsNapi::GetSupportedBeautyRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedBeautyRange is called");
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return HandleQuery(env, info, thisVar, [env, argv](auto ability) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        BeautyType beautyType = (BeautyType)value;
        return ability->GetSupportedBeautyRange(beautyType);
    });
}

napi_value CameraFunctionsNapi::GetSupportedColorEffects(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedColorEffects is called");
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->GetSupportedColorEffects();
    });
}

napi_value CameraFunctionsNapi::GetSupportedColorSpaces(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedColorSpaces is called.");
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->GetSupportedColorSpaces();
    });
}

napi_value CameraFunctionsNapi::IsMacroSupported(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->IsMacroSupported();
    });
}

napi_value CameraFunctionsNapi::GetSupportedPortraitEffects(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->GetSupportedPortraitEffects();
    });
}

napi_value CameraFunctionsNapi::GetSupportedVirtualApertures(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    
    return HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->GetSupportedVirtualApertures();
    });
}

napi_value CameraFunctionsNapi::GetSupportedPhysicalApertures(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedPhysicalApertures is called");
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_status status;
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    status = napi_create_array(env, &result);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("napi_create_array call Failed!");
        return result;
    }
    CameraFunctionsNapi*  cameraAbilityNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraAbilityNapi));
    if (status == napi_ok && cameraAbilityNapi != nullptr && cameraAbilityNapi->GetNativeObj() !=nullptr) {
        std::vector<std::vector<float>> physicalApertures =
            cameraAbilityNapi->GetNativeObj()->GetSupportedPhysicalApertures();
        MEDIA_INFO_LOG("GetSupportedPhysicalApertures len = %{public}zu", physicalApertures.size());
        if (!physicalApertures.empty()) {
            result = CameraNapiUtils::ProcessingPhysicalApertures(env, physicalApertures);
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedPhysicalApertures call Failed!");
    }
    return result;
}

napi_value CameraFunctionsNapi::IsVideoStabilizationModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsVideoStabilizationModeSupported is called");
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return HandleQuery(env, info, thisVar, [env, argv](auto ability) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        VideoStabilizationMode stabilizationMode = (VideoStabilizationMode)value;
        return ability->IsVideoStabilizationModeSupported(stabilizationMode);
    });
}

napi_value CameraFunctionsNapi::GetSupportedExposureRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedExposureRange is called");
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->GetSupportedExposureRange();
    });
}

napi_value CameraFunctionsNapi::IsFeatureSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsFeatureSupported is called");
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return HandleQuery(env, info, thisVar, [env, argv](auto ability) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        SceneFeature sceneFeature = (SceneFeature)value;
        return ability->IsFeatureSupported(sceneFeature);
    });
}
} // namespace CameraStandard
} // namespace OHOS