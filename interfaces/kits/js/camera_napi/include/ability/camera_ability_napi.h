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

#ifndef CAMERA_ABILITY_NAPI_H
#define CAMERA_ABILITY_NAPI_H

#include "napi/native_api.h"
#include "ability/camera_ability.h"

namespace OHOS {
namespace CameraStandard {

using Descriptor = std::vector<std::vector<napi_property_descriptor>>;

enum class FunctionsType {
    PHOTO_FUNCTIONS = 0,
    PHOTO_CONFLICT_FUNCTIONS,
    PORTRAIT_PHOTO_FUNCTIONS,
    PORTRAIT_PHOTO_CONFLICT_FUNCTIONS,
    VIDEO_FUNCTIONS,
    VIDEO_CONFLICT_FUNCTIONS
};

static const char PHOTO_ABILITY_NAPI_CLASS_NAME[] = "PhotoFunctions";
static const char PORTRAIT_PHOTO_ABILITY_NAPI_CLASS_NAME[] = "PortraitPhotoFunctions";
static const char VIDEO_ABILITY_NAPI_CLASS_NAME[] = "VideoFunctions";
static const char PHOTO_CONFLICT_ABILITY_NAPI_CLASS_NAME[] = "PhotoConflictFunctions";
static const char PORTRAIT_PHOTO_CONFLICT_ABILITY_NAPI_CLASS_NAME[] = "PortraitPhotoConflictFunctions";
static const char VIDEO_CONFLICT_ABILITY_NAPI_CLASS_NAME[] = "VideoConflictFunctions";

class CameraFunctionsNapi {
public:
    static napi_value Init(napi_env env, napi_value exports, FunctionsType type);
    static napi_value CreateCameraFunctions(napi_env env, sptr<CameraAbility> functions, FunctionsType type);

    CameraFunctionsNapi();
    ~CameraFunctionsNapi();

    static napi_value CameraFunctionsNapiConstructor(napi_env env, napi_callback_info info);
    static void CameraFunctionsNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);

    // FlashQuery
    static napi_value HasFlash(napi_env env, napi_callback_info info);
    static napi_value IsFlashModeSupported(napi_env env, napi_callback_info info);
    static napi_value IsLcdFlashSupported(napi_env env, napi_callback_info info);

    // AutoExposureQuery
    static napi_value IsExposureModeSupported(napi_env env, napi_callback_info info);
    static napi_value GetExposureBiasRange(napi_env env, napi_callback_info info);
    // FocusQuery
    static napi_value IsFocusModeSupported(napi_env env, napi_callback_info info);
    // ZoomQuery
    static napi_value GetZoomRatioRange(napi_env env, napi_callback_info info);
    // BeautyQuery
    static napi_value GetSupportedBeautyTypes(napi_env env, napi_callback_info info);
    static napi_value GetSupportedBeautyRange(napi_env env, napi_callback_info info);
    // ColorEffectQuery
    static napi_value GetSupportedColorEffects(napi_env env, napi_callback_info info);
    // ColorManagementQuery
    static napi_value GetSupportedColorSpaces(napi_env env, napi_callback_info info);
    // MacroQuery
    static napi_value IsMacroSupported(napi_env env, napi_callback_info info);
    // PortraitQuery
    static napi_value GetSupportedPortraitEffects(napi_env env, napi_callback_info info);
    // ApertureQuery
    static napi_value GetSupportedVirtualApertures(napi_env env, napi_callback_info info);
    static napi_value GetSupportedPhysicalApertures(napi_env env, napi_callback_info info);
    // StabilizationQuery
    static napi_value IsVideoStabilizationModeSupported(napi_env env, napi_callback_info info);
    // ManualExposureQuery
    static napi_value GetSupportedExposureRange(napi_env env, napi_callback_info info);
    // SceneDetectionQuery
    static napi_value IsFeatureSupported(napi_env env, napi_callback_info info);

    template<typename U>
    static napi_value HandleQuery(napi_env env, napi_callback_info info, napi_value thisVar, U queryFunction);

    sptr<CameraAbility> GetNativeObj() { return cameraAbility_; }
    napi_env env_;
    napi_ref wrapper_;
    sptr<CameraAbility> cameraAbility_;
    static thread_local napi_ref sConstructor_;

    static thread_local napi_ref sPhotoConstructor_;
    static thread_local napi_ref sPhotoConflictConstructor_;
    static thread_local napi_ref sPortraitPhotoConstructor_;
    static thread_local napi_ref sPortraitPhotoConflictConstructor_;
    static thread_local napi_ref sVideoConstructor_;
    static thread_local napi_ref sVideoConflictConstructor_;

    static thread_local sptr<CameraAbility> sCameraAbility_;

    static const std::vector<napi_property_descriptor> flash_query_props;
    static const std::vector<napi_property_descriptor> auto_exposure_query_props;
    static const std::vector<napi_property_descriptor> focus_query_props;
    static const std::vector<napi_property_descriptor> zoom_query_props;
    static const std::vector<napi_property_descriptor> beauty_query_props;
    static const std::vector<napi_property_descriptor> color_effect_query_props;
    static const std::vector<napi_property_descriptor> color_management_query_props;
    static const std::vector<napi_property_descriptor> macro_query_props;
    static const std::vector<napi_property_descriptor> portrait_query_props;
    static const std::vector<napi_property_descriptor> aperture_query_props;
    static const std::vector<napi_property_descriptor> stabilization_query_props;
    static const std::vector<napi_property_descriptor> manual_exposure_query_props;
    static const std::vector<napi_property_descriptor> features_query_props;

    static const std::map<FunctionsType, const char*> functionsNameMap_;
    static const std::map<FunctionsType, Descriptor> functionsDescMap_;
};
}
}
#endif /* CAMERA_ABILITY_NAPI_H */