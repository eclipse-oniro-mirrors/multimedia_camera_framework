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
#include "camera_napi_post_process_utils.h"
#include "camera_napi_utils.h"
#include "napi/native_common.h"
#include "napi/native_api.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
thread_local sptr<CameraAbility> CameraAbilityNapi::sCameraAbility_ = nullptr;
thread_local napi_ref CameraAbilityNapi::sConstructor_ = nullptr;
thread_local napi_ref PhotoAbilityNapi::sConstructor_ = nullptr;
thread_local napi_ref PortraitPhotoAbilityNapi::sConstructor_ = nullptr;
thread_local napi_ref VideoAbilityNapi::sConstructor_ = nullptr;
thread_local napi_ref PhotoConflictAbilityNapi::sConstructor_ = nullptr;
thread_local napi_ref PortraitPhotoConflictAbilityNapi::sConstructor_ = nullptr;
thread_local napi_ref VideoConflictAbilityNapi::sConstructor_ = nullptr;

const std::vector<napi_property_descriptor> CameraAbilityNapi::flash_query_props = {
    DECLARE_NAPI_FUNCTION("hasFlash", CameraAbilityNapi::HasFlash),
    DECLARE_NAPI_FUNCTION("isFlashModeSupported", CameraAbilityNapi::IsFlashModeSupported)
};

const std::vector<napi_property_descriptor> CameraAbilityNapi::auto_exposure_query_props = {
    DECLARE_NAPI_FUNCTION("isExposureModeSupported", CameraAbilityNapi::IsExposureModeSupported),
    DECLARE_NAPI_FUNCTION("getExposureBiasRange", CameraAbilityNapi::GetExposureBiasRange)
};

const std::vector<napi_property_descriptor> CameraAbilityNapi::focus_query_props = {
    DECLARE_NAPI_FUNCTION("isFocusModeSupported", CameraAbilityNapi::IsFocusModeSupported)
};

const std::vector<napi_property_descriptor> CameraAbilityNapi::zoom_query_props = {
    DECLARE_NAPI_FUNCTION("getZoomRatioRange", CameraAbilityNapi::GetZoomRatioRange)
};

const std::vector<napi_property_descriptor> CameraAbilityNapi::beauty_query_props = {
    DECLARE_NAPI_FUNCTION("getSupportedBeautyTypes", CameraAbilityNapi::GetSupportedBeautyTypes),
    DECLARE_NAPI_FUNCTION("getSupportedBeautyRange", CameraAbilityNapi::GetSupportedBeautyRange)
};

const std::vector<napi_property_descriptor> CameraAbilityNapi::color_effect_query_props = {
    DECLARE_NAPI_FUNCTION("getSupportedColorEffects", CameraAbilityNapi::GetSupportedColorEffects)
};

const std::vector<napi_property_descriptor> CameraAbilityNapi::color_management_query_props = {
    DECLARE_NAPI_FUNCTION("getSupportedColorSpaces", CameraAbilityNapi::GetSupportedColorSpaces)
};

const std::vector<napi_property_descriptor> CameraAbilityNapi::macro_query_props = {
    DECLARE_NAPI_FUNCTION("isMacroSupported", CameraAbilityNapi::IsMacroSupported)
};

const std::vector<napi_property_descriptor> CameraAbilityNapi::portrait_query_props = {
    DECLARE_NAPI_FUNCTION("getSupportedPortraitEffects", CameraAbilityNapi::GetSupportedPortraitEffects)
};

const std::vector<napi_property_descriptor> CameraAbilityNapi::aperture_query_props = {
    DECLARE_NAPI_FUNCTION("getSupportedVirtualApertures", CameraAbilityNapi::GetSupportedVirtualApertures),
    DECLARE_NAPI_FUNCTION("getSupportedPhysicalApertures", CameraAbilityNapi::GetSupportedPhysicalApertures)
};

const std::vector<napi_property_descriptor> CameraAbilityNapi::stabilization_query_props = {
    DECLARE_NAPI_FUNCTION("isVideoStabilizationModeSupported", CameraAbilityNapi::IsVideoStabilizationModeSupported)
};

const std::vector<napi_property_descriptor> CameraAbilityNapi::manual_exposure_props = {
    DECLARE_NAPI_FUNCTION("getSupportedExposureRange", CameraAbilityNapi::GetSupportedExposureRange),
};

const std::vector<napi_property_descriptor> CameraAbilityNapi::features_props = {
    DECLARE_NAPI_FUNCTION("isSceneFeatureSupported", CameraAbilityNapi::IsFeatureSupported),
};

napi_value CameraAbilityNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    std::vector<std::vector<napi_property_descriptor>> descriptors = { flash_query_props,
        auto_exposure_query_props, focus_query_props, zoom_query_props, beauty_query_props,
        color_effect_query_props, color_management_query_props };
    std::vector<napi_property_descriptor> camera_ability_props = CameraNapiUtils::GetPropertyDescriptor(descriptors);

    status = napi_define_class(env, CAMERA_ABILITY_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               CameraAbilityNapiConstructor, nullptr,
                               camera_ability_props.size(),
                               camera_ability_props.data(), &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_ABILITY_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed");
    return nullptr;
}

napi_value CameraAbilityNapi::CreateCameraAbility(napi_env env, sptr<CameraAbility> cameraAbility)
{
    MEDIA_DEBUG_LOG("CreateCameraAbility is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraAbility_ = cameraAbility;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraAbility_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Camera Ability instance");
        }
    }
    MEDIA_ERR_LOG("CreateCameraAbility call Failed");
    napi_get_undefined(env, &result);
    return result;
}

CameraAbilityNapi::CameraAbilityNapi() : env_(nullptr), wrapper_(nullptr) {}

CameraAbilityNapi::~CameraAbilityNapi()
{
    MEDIA_DEBUG_LOG("~CameraAbilityNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (cameraAbility_) {
        cameraAbility_ = nullptr;
    }
}

napi_value CameraAbilityNapi::CameraAbilityNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraAbilityNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CameraAbilityNapi> obj = std::make_unique<CameraAbilityNapi>();
        obj->env_ = env;
        obj->cameraAbility_ = sCameraAbility_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            CameraAbilityNapi::CameraAbilityNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("CameraAbilityNapiConstructor call Failed");
    return result;
}

void CameraAbilityNapi::CameraAbilityNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CameraAbilityNapiDestructor is called");
    CameraAbilityNapi* cameraAbilityNapi = reinterpret_cast<CameraAbilityNapi*>(nativeObject);
    if (cameraAbilityNapi != nullptr) {
        delete cameraAbilityNapi;
    }
}

napi_value CameraAbilityNapi::HasFlash(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("HasFlash is called");
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return CameraAbilityProcessor<CameraAbilityNapi>::HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->HasFlash();
    });
}

napi_value CameraAbilityNapi::IsFlashModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsFlashModeSupported is called");
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return CameraAbilityProcessor<CameraAbilityNapi>::HandleQuery(env, info, thisVar, [env, argv](auto ability) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        FlashMode flashMode = (FlashMode)value;
        return ability->IsFlashModeSupported(flashMode);
    });
}

napi_value CameraAbilityNapi::IsExposureModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsExposureModeSupported is called");
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return CameraAbilityProcessor<CameraAbilityNapi>::HandleQuery(env, info, thisVar, [env, argv](auto ability) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        ExposureMode exposureMode = (ExposureMode)value;
        return ability->IsExposureModeSupported(exposureMode);
    });
}

napi_value CameraAbilityNapi::GetExposureBiasRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetExposureBiasRange is called");
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return CameraAbilityProcessor<CameraAbilityNapi>::HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->GetExposureBiasRange();
    });
}

napi_value CameraAbilityNapi::IsFocusModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsFocusModeSupported is called");
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return CameraAbilityProcessor<CameraAbilityNapi>::HandleQuery(env, info, thisVar, [env, argv](auto ability) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        FocusMode focusMode = (FocusMode)value;
        return ability->IsFocusModeSupported(focusMode);
    });
}

napi_value CameraAbilityNapi::GetZoomRatioRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetZoomRatioRange is called");
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return CameraAbilityProcessor<CameraAbilityNapi>::HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->GetZoomRatioRange();
    });
}

napi_value CameraAbilityNapi::GetSupportedBeautyTypes(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedBeautyTypes is called");
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return CameraAbilityProcessor<CameraAbilityNapi>::HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->GetSupportedBeautyTypes();
    });
}

napi_value CameraAbilityNapi::GetSupportedBeautyRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedBeautyRange is called");
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return CameraAbilityProcessor<CameraAbilityNapi>::HandleQuery(env, info, thisVar, [env, argv](auto ability) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        BeautyType beautyType = (BeautyType)value;
        return ability->GetSupportedBeautyRange(beautyType);
    });
}

napi_value CameraAbilityNapi::GetSupportedColorEffects(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedColorEffects is called");
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return CameraAbilityProcessor<CameraAbilityNapi>::HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->GetSupportedColorEffects();
    });
}

napi_value CameraAbilityNapi::GetSupportedColorSpaces(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedColorSpaces is called.");
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return CameraAbilityProcessor<CameraAbilityNapi>::HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->GetSupportedColorSpaces();
    });
}

napi_value CameraAbilityNapi::IsMacroSupported(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return CameraAbilityProcessor<CameraAbilityNapi>::HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->IsMacroSupported();
    });
}

napi_value CameraAbilityNapi::GetSupportedPortraitEffects(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return CameraAbilityProcessor<CameraAbilityNapi>::HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->GetSupportedPortraitEffects();
    });
}

napi_value CameraAbilityNapi::GetSupportedVirtualApertures(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    
    return CameraAbilityProcessor<CameraAbilityNapi>::HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->GetSupportedVirtualApertures();
    });
}

napi_value CameraAbilityNapi::GetSupportedPhysicalApertures(napi_env env, napi_callback_info info)
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
    CameraAbilityNapi*  cameraAbilityNapi = nullptr;
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

napi_value CameraAbilityNapi::IsVideoStabilizationModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsVideoStabilizationModeSupported is called");
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return CameraAbilityProcessor<CameraAbilityNapi>::HandleQuery(env, info, thisVar, [env, argv](auto ability) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        VideoStabilizationMode stabilizationMode = (VideoStabilizationMode)value;
        return ability->IsVideoStabilizationModeSupported(stabilizationMode);
    });
}

napi_value CameraAbilityNapi::GetSupportedExposureRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedExposureRange is called");
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return CameraAbilityProcessor<CameraAbilityNapi>::HandleQuery(env, info, thisVar, [](auto ability) {
        return ability->GetSupportedExposureRange();
    });
}

napi_value CameraAbilityNapi::IsFeatureSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsFeatureSupported is called");
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    return CameraAbilityProcessor<CameraAbilityNapi>::HandleQuery(env, info, thisVar, [env, argv](auto ability) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        SceneFeature sceneFeature = (SceneFeature)value;
        return ability->IsFeatureSupported(sceneFeature);
    });
}

napi_value PhotoAbilityNapi::CreatePhotoAbility(napi_env env, sptr<CameraAbility> photoAbility)
{
    MEDIA_DEBUG_LOG("CreatePhotoAbility is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraAbility_ = photoAbility;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraAbility_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Photo Ability instance");
        }
    }
    MEDIA_ERR_LOG("CreatePhotoAbility call Failed");
    napi_get_undefined(env, &result);
    return result;
}

PhotoAbilityNapi::PhotoAbilityNapi() : env_(nullptr), wrapper_(nullptr) {}

PhotoAbilityNapi::~PhotoAbilityNapi()
{
    MEDIA_DEBUG_LOG("~PhotoAbilityNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

void PhotoAbilityNapi::PhotoAbilityNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("PhotoAbilityNapiDestructor is called");
    PhotoAbilityNapi* photoAbilityNapi = reinterpret_cast<PhotoAbilityNapi*>(nativeObject);
    if (photoAbilityNapi != nullptr) {
        delete photoAbilityNapi;
    }
}

napi_value PhotoAbilityNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    std::vector<std::vector<napi_property_descriptor>> descriptors = { flash_query_props, auto_exposure_query_props,
        focus_query_props, zoom_query_props, beauty_query_props, color_effect_query_props, color_management_query_props,
        macro_query_props, manual_exposure_props, features_props };
    std::vector<napi_property_descriptor> photo_ability_props = CameraNapiUtils::GetPropertyDescriptor(descriptors);

    status = napi_define_class(env, PHOTO_ABILITY_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               PhotoAbilityNapiConstructor, nullptr,
                               photo_ability_props.size(),
                               photo_ability_props.data(), &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, PHOTO_ABILITY_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed");
    return nullptr;
}

napi_value PhotoAbilityNapi::PhotoAbilityNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PhotoAbilityNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<PhotoAbilityNapi> obj = std::make_unique<PhotoAbilityNapi>();
        obj->env_ = env;
        obj->cameraAbility_ = sCameraAbility_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            PhotoAbilityNapi::PhotoAbilityNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("PhotoAbilityNapiConstructor call Failed");
    return result;
}

PortraitPhotoAbilityNapi::PortraitPhotoAbilityNapi() : env_(nullptr), wrapper_(nullptr) {}

PortraitPhotoAbilityNapi::~PortraitPhotoAbilityNapi()
{
    MEDIA_DEBUG_LOG("~PortraitPhotoAbilityNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

napi_value PortraitPhotoAbilityNapi::PortraitPhotoAbilityNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PortraitPhotoAbilityNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<PortraitPhotoAbilityNapi> obj = std::make_unique<PortraitPhotoAbilityNapi>();
        obj->env_ = env;
        obj->cameraAbility_ = sCameraAbility_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            PortraitPhotoAbilityNapi::PortraitPhotoAbilityNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("PortraitPhotoAbilityNapi call Failed");
    return result;
}

void PortraitPhotoAbilityNapi::PortraitPhotoAbilityNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("PortraitPhotoAbilityNapiDestructor is called");
    PortraitPhotoAbilityNapi* portraitPhotoAbilityNapi = reinterpret_cast<PortraitPhotoAbilityNapi*>(nativeObject);
    if (portraitPhotoAbilityNapi != nullptr) {
        delete portraitPhotoAbilityNapi;
    }
}

napi_value PortraitPhotoAbilityNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    std::vector<std::vector<napi_property_descriptor>> descriptors = { flash_query_props, auto_exposure_query_props,
        focus_query_props, zoom_query_props, beauty_query_props, color_effect_query_props, color_management_query_props,
        portrait_query_props, aperture_query_props, features_props };
    auto portrait_photo_ability_props = CameraNapiUtils::GetPropertyDescriptor(descriptors);

    status = napi_define_class(env, PORTRAIT_PHOTO_ABILITY_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               PortraitPhotoAbilityNapiConstructor, nullptr,
                               portrait_photo_ability_props.size(),
                               portrait_photo_ability_props.data(), &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, PORTRAIT_PHOTO_ABILITY_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed");
    return nullptr;
}

napi_value PortraitPhotoAbilityNapi::CreatePortraitPhotoAbility(napi_env env, sptr<CameraAbility> portraitAbility)
{
    MEDIA_DEBUG_LOG("CreatePortraitPhotoAbility is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraAbility_ = portraitAbility;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraAbility_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Portrait Photo Ability instance");
        }
    }
    MEDIA_ERR_LOG("CreatePortraitPhotoAbility call Failed");
    napi_get_undefined(env, &result);
    return result;
}

napi_value VideoAbilityNapi::CreateVideoAbility(napi_env env, sptr<CameraAbility> videoAbility)
{
    MEDIA_DEBUG_LOG("CreateVideoAbility is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraAbility_ = videoAbility;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraAbility_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Video Ability instance");
        }
    }
    MEDIA_ERR_LOG("CreateVideoAbility call Failed");
    napi_get_undefined(env, &result);
    return result;
}

VideoAbilityNapi::VideoAbilityNapi() : env_(nullptr), wrapper_(nullptr) {}

VideoAbilityNapi::~VideoAbilityNapi()
{
    MEDIA_DEBUG_LOG("~VideoAbilityNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

void VideoAbilityNapi::VideoAbilityNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("VideoAbilityNapiDestructor is called");
    VideoAbilityNapi* videoAbilityNapi = reinterpret_cast<VideoAbilityNapi*>(nativeObject);
    if (videoAbilityNapi != nullptr) {
        delete videoAbilityNapi;
    }
}

napi_value VideoAbilityNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    std::vector<std::vector<napi_property_descriptor>> descriptors = { flash_query_props, auto_exposure_query_props,
        focus_query_props, zoom_query_props, stabilization_query_props, beauty_query_props, color_effect_query_props,
        color_management_query_props, macro_query_props, manual_exposure_props, features_props };
    std::vector<napi_property_descriptor> video_ability_props = CameraNapiUtils::GetPropertyDescriptor(descriptors);

    status = napi_define_class(env, VIDEO_ABILITY_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               VideoAbilityNapiConstructor, nullptr,
                               video_ability_props.size(),
                               video_ability_props.data(), &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, VIDEO_ABILITY_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed");
    return nullptr;
}

napi_value VideoAbilityNapi::VideoAbilityNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("VideoAbilityNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<VideoAbilityNapi> obj = std::make_unique<VideoAbilityNapi>();
        obj->env_ = env;
        obj->cameraAbility_ = sCameraAbility_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            VideoAbilityNapi::VideoAbilityNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("VideoAbilityNapiConstructor call Failed");
    return result;
}

napi_value PhotoConflictAbilityNapi::CreatePhotoConflictAbility(napi_env env, sptr<CameraAbility> photoConflictAbility)
{
    MEDIA_DEBUG_LOG("CreatePhotoConflictAbility is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraAbility_ = photoConflictAbility;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraAbility_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Photo Conflict Ability instance");
        }
    }
    MEDIA_ERR_LOG("CreatePhotoConflictAbility call Failed");
    napi_get_undefined(env, &result);
    return result;
}

PhotoConflictAbilityNapi::PhotoConflictAbilityNapi() : env_(nullptr), wrapper_(nullptr) {}

PhotoConflictAbilityNapi::~PhotoConflictAbilityNapi()
{
    MEDIA_DEBUG_LOG("~PhotoConflictAbilityNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

void PhotoConflictAbilityNapi::PhotoConflictAbilityNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("PhotoConflictAbilityNapiDestructor is called");
    PhotoConflictAbilityNapi* photoConflictAbilityNapi = reinterpret_cast<PhotoConflictAbilityNapi*>(nativeObject);
    if (photoConflictAbilityNapi != nullptr) {
        delete photoConflictAbilityNapi;
    }
}

napi_value PhotoConflictAbilityNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    std::vector<std::vector<napi_property_descriptor>> descriptors = { zoom_query_props, macro_query_props };
    auto photo_conflict_ability_props = CameraNapiUtils::GetPropertyDescriptor(descriptors);

    status = napi_define_class(env, PHOTO_CONFLICT_ABILITY_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               PhotoConflictAbilityNapiConstructor, nullptr,
                               photo_conflict_ability_props.size(),
                               photo_conflict_ability_props.data(), &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, PHOTO_CONFLICT_ABILITY_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed");
    return nullptr;
}

napi_value PhotoConflictAbilityNapi::PhotoConflictAbilityNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PhotoConflictAbilityNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<PhotoConflictAbilityNapi> obj = std::make_unique<PhotoConflictAbilityNapi>();
        obj->env_ = env;
        obj->cameraAbility_ = sCameraAbility_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            PhotoConflictAbilityNapi::PhotoConflictAbilityNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("PhotoConflictAbilityNapiConstructor call Failed");
    return result;
}

napi_value PortraitPhotoConflictAbilityNapi::CreatePortraitPhotoConflictAbility(napi_env env,
    sptr<CameraAbility> portraitConflictAbility)
{
    MEDIA_DEBUG_LOG("CreatePortraitPhotoConflictAbility is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraAbility_ = portraitConflictAbility;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraAbility_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Portrait Photo Conflict Ability instance");
        }
    }
    MEDIA_ERR_LOG("CreatePortraitPhotoConflictAbility call Failed");
    napi_get_undefined(env, &result);
    return result;
}

PortraitPhotoConflictAbilityNapi::PortraitPhotoConflictAbilityNapi() : env_(nullptr), wrapper_(nullptr) {}

PortraitPhotoConflictAbilityNapi::~PortraitPhotoConflictAbilityNapi()
{
    MEDIA_DEBUG_LOG("~PortraitPhotoConflictAbilityNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

void PortraitPhotoConflictAbilityNapi::PortraitPhotoConflictAbilityNapiDestructor(napi_env env,
                                                                                  void* nativeObject,
                                                                                  void* finalize_hint)
{
    MEDIA_DEBUG_LOG("PortraitPhotoConflictAbilityNapiDestructor is called");
    PortraitPhotoConflictAbilityNapi* portraitPhotoConflictAbilityNapi =
        reinterpret_cast<PortraitPhotoConflictAbilityNapi*>(nativeObject);
    if (portraitPhotoConflictAbilityNapi != nullptr) {
        delete portraitPhotoConflictAbilityNapi;
    }
}

napi_value PortraitPhotoConflictAbilityNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    std::vector<std::vector<napi_property_descriptor>> descriptors = { zoom_query_props, portrait_query_props,
        aperture_query_props };
    auto portrait_photo_conflict_ability_props = CameraNapiUtils::GetPropertyDescriptor(descriptors);

    status = napi_define_class(env, PORTRAIT_PHOTO_CONFLICT_ABILITY_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               PortraitPhotoConflictAbilityNapiConstructor, nullptr,
                               portrait_photo_conflict_ability_props.size(),
                               portrait_photo_conflict_ability_props.data(), &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, PORTRAIT_PHOTO_CONFLICT_ABILITY_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed");
    return nullptr;
}

napi_value PortraitPhotoConflictAbilityNapi::PortraitPhotoConflictAbilityNapiConstructor(napi_env env,
                                                                                         napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PortraitPhotoConflictAbilityNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<PortraitPhotoConflictAbilityNapi> obj = std::make_unique<PortraitPhotoConflictAbilityNapi>();
        obj->env_ = env;
        obj->cameraAbility_ = sCameraAbility_;

        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            PortraitPhotoConflictAbilityNapi::PortraitPhotoConflictAbilityNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("PortraitPhotoConflictAbilityNapiConstructor call Failed");
    return result;
}

napi_value VideoConflictAbilityNapi::CreateVideoConflictAbility(napi_env env, sptr<CameraAbility> videoConflictAbility)
{
    MEDIA_DEBUG_LOG("CreateVideoConflictAbility is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraAbility_ = videoConflictAbility;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraAbility_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Video Conflict Ability instance");
        }
    }
    MEDIA_ERR_LOG("CreateVideoConflictAbility call Failed");
    napi_get_undefined(env, &result);
    return result;
}

VideoConflictAbilityNapi::VideoConflictAbilityNapi() : env_(nullptr), wrapper_(nullptr) {}

VideoConflictAbilityNapi::~VideoConflictAbilityNapi()
{
    MEDIA_DEBUG_LOG("~VideoConflictAbilityNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

void VideoConflictAbilityNapi::VideoConflictAbilityNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("VideoConflictAbilityNapiDestructor is called");
    VideoConflictAbilityNapi* videoConflictAbilityNapi = reinterpret_cast<VideoConflictAbilityNapi*>(nativeObject);
    if (videoConflictAbilityNapi != nullptr) {
        delete videoConflictAbilityNapi;
    }
}

napi_value VideoConflictAbilityNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    std::vector<std::vector<napi_property_descriptor>> descriptors = { zoom_query_props, macro_query_props };
    auto video_conflict_ability_props = CameraNapiUtils::GetPropertyDescriptor(descriptors);

    status = napi_define_class(env, VIDEO_CONFLICT_ABILITY_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               VideoConflictAbilityNapiConstructor, nullptr,
                               video_conflict_ability_props.size(),
                               video_conflict_ability_props.data(), &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, VIDEO_CONFLICT_ABILITY_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed");
    return nullptr;
}

napi_value VideoConflictAbilityNapi::VideoConflictAbilityNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("VideoConflictAbilityNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<VideoConflictAbilityNapi> obj = std::make_unique<VideoConflictAbilityNapi>();
        obj->env_ = env;
        obj->cameraAbility_ = sCameraAbility_;

        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            VideoConflictAbilityNapi::VideoConflictAbilityNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("VideoConflictAbilityNapiConstructor call Failed");
    return result;
}
} // namespace CameraStandard
} // namespace OHOS