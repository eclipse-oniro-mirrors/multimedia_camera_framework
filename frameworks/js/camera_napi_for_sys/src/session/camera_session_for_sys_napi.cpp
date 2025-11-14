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

#include "session/camera_session_for_sys_napi.h"

#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_napi_object_types.h"
#include "camera_napi_utils.h"
#include "camera_napi_param_parser.h"
#include "capture_scene_const.h"
#include "input/camera_device.h"
#include "input/camera_manager.h"
#include "input/camera_manager_for_sys.h"
#include "mode/aperture_video_session_napi.h"
#include "mode/fluorescence_photo_session_napi.h"
#include "mode/high_res_photo_session_napi.h"
#include "mode/light_painting_session_napi.h"
#include "mode/macro_photo_session_napi.h"
#include "mode/macro_video_session_napi.h"
#include "mode/night_session_napi.h"
#include "mode/panorama_session_napi.h"
#include "mode/photo_session_for_sys_napi.h"
#include "mode/portrait_session_napi.h"
#include "mode/profession_session_napi.h"
#include "mode/quick_shot_photo_session_napi.h"
#include "mode/secure_session_for_sys_napi.h"
#include "mode/slow_motion_session_napi.h"
#include "mode/time_lapse_photo_session_napi.h"
#include "mode/video_session_for_sys_napi.h"
#include "napi/native_node_api.h"


namespace OHOS {
namespace CameraStandard {
thread_local sptr<CaptureSessionForSys> CameraSessionForSysNapi::sCameraSessionForSys_ = nullptr;

const std::map<SceneMode, FunctionsType> CameraSessionForSysNapi::modeToFunctionTypeMap_ = {
    {SceneMode::CAPTURE, FunctionsType::PHOTO_FUNCTIONS},
    {SceneMode::VIDEO, FunctionsType::VIDEO_FUNCTIONS},
    {SceneMode::PORTRAIT, FunctionsType::PORTRAIT_PHOTO_FUNCTIONS}
};

const std::map<SceneMode, FunctionsType> CameraSessionForSysNapi::modeToConflictFunctionTypeMap_ = {
    {SceneMode::CAPTURE, FunctionsType::PHOTO_CONFLICT_FUNCTIONS},
    {SceneMode::VIDEO, FunctionsType::VIDEO_CONFLICT_FUNCTIONS},
    {SceneMode::PORTRAIT, FunctionsType::PORTRAIT_PHOTO_CONFLICT_FUNCTIONS}
};

const std::vector<napi_property_descriptor> CameraSessionForSysNapi::camera_process_sys_props = {
    DECLARE_NAPI_FUNCTION("setUsage", CameraSessionForSysNapi::SetUsage)
};

const std::vector<napi_property_descriptor> CameraSessionForSysNapi::camera_output_capability_sys_props = {
    DECLARE_NAPI_FUNCTION("getCameraOutputCapabilities", CameraSessionForSysNapi::GetCameraOutputCapabilities)
};

const std::vector<napi_property_descriptor> CameraSessionForSysNapi::camera_ability_sys_props = {
    DECLARE_NAPI_FUNCTION("getSessionFunctions", CameraSessionForSysNapi::GetSessionFunctions),
    DECLARE_NAPI_FUNCTION("getSessionConflictFunctions", CameraSessionForSysNapi::GetSessionConflictFunctions)
};

const std::vector<napi_property_descriptor> CameraSessionForSysNapi::focus_sys_props = {
    DECLARE_NAPI_FUNCTION("isFocusRangeTypeSupported", CameraSessionForSysNapi::IsFocusRangeTypeSupported),
    DECLARE_NAPI_FUNCTION("getFocusRange", CameraSessionForSysNapi::GetFocusRange),
    DECLARE_NAPI_FUNCTION("setFocusRange", CameraSessionForSysNapi::SetFocusRange),
    DECLARE_NAPI_FUNCTION("isFocusDrivenTypeSupported", CameraSessionForSysNapi::IsFocusDrivenTypeSupported),
    DECLARE_NAPI_FUNCTION("getFocusDriven", CameraSessionForSysNapi::GetFocusDriven),
    DECLARE_NAPI_FUNCTION("setFocusDriven", CameraSessionForSysNapi::SetFocusDriven)
};

const std::vector<napi_property_descriptor> CameraSessionForSysNapi::flash_sys_props = {
    DECLARE_NAPI_FUNCTION("isLcdFlashSupported", CameraSessionForSysNapi::IsLcdFlashSupported),
    DECLARE_NAPI_FUNCTION("enableLcdFlash", CameraSessionForSysNapi::EnableLcdFlash)
};

const std::vector<napi_property_descriptor> CameraSessionForSysNapi::zoom_sys_props = {
    DECLARE_NAPI_FUNCTION("prepareZoom", CameraSessionForSysNapi::PrepareZoom),
    DECLARE_NAPI_FUNCTION("unprepareZoom", CameraSessionForSysNapi::UnPrepareZoom),
    DECLARE_NAPI_FUNCTION("getZoomPointInfos", CameraSessionForSysNapi::GetZoomPointInfos)
};

const std::vector<napi_property_descriptor> CameraSessionForSysNapi::manual_focus_sys_props = {
    DECLARE_NAPI_FUNCTION("getFocusDistance", CameraSessionForSysNapi::GetFocusDistance),
    DECLARE_NAPI_FUNCTION("setFocusDistance", CameraSessionForSysNapi::SetFocusDistance),
};

const std::vector<napi_property_descriptor> CameraSessionForSysNapi::beauty_sys_props = {
    DECLARE_NAPI_FUNCTION("getSupportedBeautyTypes", CameraSessionForSysNapi::GetSupportedBeautyTypes),
    DECLARE_NAPI_FUNCTION("getSupportedBeautyRange", CameraSessionForSysNapi::GetSupportedBeautyRange),
    DECLARE_NAPI_FUNCTION("getBeauty", CameraSessionForSysNapi::GetBeauty),
    DECLARE_NAPI_FUNCTION("setBeauty", CameraSessionForSysNapi::SetBeauty),
    DECLARE_NAPI_FUNCTION("getSupportedPortraitThemeTypes", CameraSessionForSysNapi::GetSupportedPortraitThemeTypes),
    DECLARE_NAPI_FUNCTION("isPortraitThemeSupported", CameraSessionForSysNapi::IsPortraitThemeSupported),
    DECLARE_NAPI_FUNCTION("setPortraitThemeType", CameraSessionForSysNapi::SetPortraitThemeType)
};

const std::vector<napi_property_descriptor> CameraSessionForSysNapi::color_effect_sys_props = {
    DECLARE_NAPI_FUNCTION("getSupportedColorEffects", CameraSessionForSysNapi::GetSupportedColorEffects),
    DECLARE_NAPI_FUNCTION("getColorEffect", CameraSessionForSysNapi::GetColorEffect),
    DECLARE_NAPI_FUNCTION("setColorEffect", CameraSessionForSysNapi::SetColorEffect)
};

const std::vector<napi_property_descriptor> CameraSessionForSysNapi::depth_fusion_sys_props = {
    DECLARE_NAPI_FUNCTION("isDepthFusionSupported", CameraSessionForSysNapi::IsDepthFusionSupported),
    DECLARE_NAPI_FUNCTION("getDepthFusionThreshold", CameraSessionForSysNapi::GetDepthFusionThreshold),
    DECLARE_NAPI_FUNCTION("isDepthFusionEnabled", CameraSessionForSysNapi::IsDepthFusionEnabled),
    DECLARE_NAPI_FUNCTION("enableDepthFusion", CameraSessionForSysNapi::EnableDepthFusion)
};

const std::vector<napi_property_descriptor> CameraSessionForSysNapi::scene_detection_sys_props = {
    DECLARE_NAPI_FUNCTION("isSceneFeatureSupported", CameraSessionForSysNapi::IsFeatureSupported),
    DECLARE_NAPI_FUNCTION("enableSceneFeature", CameraSessionForSysNapi::EnableFeature)
};

const std::vector<napi_property_descriptor> CameraSessionForSysNapi::effect_suggestion_sys_props = {
    DECLARE_NAPI_FUNCTION("isEffectSuggestionSupported", CameraSessionForSysNapi::IsEffectSuggestionSupported),
    DECLARE_NAPI_FUNCTION("enableEffectSuggestion", CameraSessionForSysNapi::EnableEffectSuggestion),
    DECLARE_NAPI_FUNCTION("getSupportedEffectSuggestionType",
        CameraSessionForSysNapi::GetSupportedEffectSuggestionType),
    DECLARE_NAPI_FUNCTION("getSupportedEffectSuggestionTypes",
        CameraSessionForSysNapi::GetSupportedEffectSuggestionType),
    DECLARE_NAPI_FUNCTION("setEffectSuggestionStatus", CameraSessionForSysNapi::SetEffectSuggestionStatus),
    DECLARE_NAPI_FUNCTION("updateEffectSuggestion", CameraSessionForSysNapi::UpdateEffectSuggestion)
};

const std::vector<napi_property_descriptor> CameraSessionForSysNapi::aperture_sys_props = {
    DECLARE_NAPI_FUNCTION("getSupportedVirtualApertures", CameraSessionForSysNapi::GetSupportedVirtualApertures),
    DECLARE_NAPI_FUNCTION("getVirtualAperture", CameraSessionForSysNapi::GetVirtualAperture),
    DECLARE_NAPI_FUNCTION("setVirtualAperture", CameraSessionForSysNapi::SetVirtualAperture),

    DECLARE_NAPI_FUNCTION("getSupportedPhysicalApertures", CameraSessionForSysNapi::GetSupportedPhysicalApertures),
    DECLARE_NAPI_FUNCTION("getPhysicalAperture", CameraSessionForSysNapi::GetPhysicalAperture),
    DECLARE_NAPI_FUNCTION("setPhysicalAperture", CameraSessionForSysNapi::SetPhysicalAperture)
};

const std::vector<napi_property_descriptor> CameraSessionForSysNapi::color_reservation_sys_props = {
    DECLARE_NAPI_FUNCTION("getSupportedColorReservationTypes",
        CameraSessionForSysNapi::GetSupportedColorReservationTypes),
    DECLARE_NAPI_FUNCTION("getColorReservation", CameraSessionForSysNapi::GetColorReservation),
    DECLARE_NAPI_FUNCTION("setColorReservation", CameraSessionForSysNapi::SetColorReservation)
};

CameraSessionForSysNapi::~CameraSessionForSysNapi()
{
    MEDIA_INFO_LOG("CameraSessionForSysNapi::~CameraSessionForSysNapi");
}

napi_value CameraSessionForSysNapi::SetUsage(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetUsage is called");
 
    uint32_t usageType;
    bool enabled;
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi, usageType, enabled);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::SetUsage parse parameter occur error");
 
    cameraSessionForSysNapi->cameraSessionForSys_->LockForControl();
    cameraSessionForSysNapi->cameraSessionForSys_->SetUsage(static_cast<UsageType>(usageType), enabled);
    cameraSessionForSysNapi->cameraSessionForSys_->UnlockForControl();
    
    MEDIA_DEBUG_LOG("CameraSessionForSysNapi::SetUsage success");
 
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionForSysNapi::GetCameraOutputCapabilities(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetCameraOutputCapabilities is called");

    size_t argSize = CameraNapiUtils::GetNapiArgs(env, info);
    if (argSize != ARGS_ONE) {
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "Invalid argument.");
        return nullptr;
    }

    std::string cameraId;
    CameraNapiObject cameraInfoObj { { { "cameraId", &cameraId } } };
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi, cameraInfoObj);

    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "Create cameraInput invalid argument!"),
        nullptr, "CameraSessionForSysNapi::GetCameraOutputCapabilities invalid argument");

    sptr<CameraDevice> cameraInfo = CameraManager::GetInstance()->GetCameraDeviceFromId(cameraId);
    if (cameraInfo == nullptr) {
        MEDIA_ERR_LOG("cameraInfo is null");
        CameraNapiUtils::ThrowError(env, SERVICE_FATL_ERROR, "cameraInfo is null.");
        return nullptr;
    }

    std::vector<sptr<CameraOutputCapability>> caplist =
        cameraSessionForSysNapi->cameraSessionForSys_->GetCameraOutputCapabilities(cameraInfo);
    CHECK_RETURN_RET_ELOG(caplist.empty(), nullptr, "caplist is empty");

    napi_value capArray;
    napi_status status = napi_create_array(env, &capArray);
    CHECK_RETURN_RET_ELOG(status != napi_ok, nullptr, "Failed to create napi array");

    for (size_t i = 0; i < caplist.size(); i++) {
        if (caplist[i] == nullptr) {
            continue;
        }
        caplist[i]->RemoveDuplicatesProfiles();
        napi_value cap = CameraNapiObjCameraOutputCapability(*caplist[i]).GenerateNapiValue(env);
        CHECK_RETURN_RET_ELOG(cap == nullptr || napi_set_element(env, capArray, i, cap) != napi_ok, nullptr,
            "Failed to create camera napi wrapper object");
    }

    return capArray;
}

void ParseSize(napi_env env, napi_value root, Size& size)
{
    MEDIA_DEBUG_LOG("ParseSize is called");
    napi_value res = nullptr;
    CHECK_EXECUTE(napi_get_named_property(env, root, "width", &res) == napi_ok,
        napi_get_value_uint32(env, res, &size.width));

    CHECK_EXECUTE(napi_get_named_property(env, root, "height", &res) == napi_ok,
        napi_get_value_uint32(env, res, &size.height));
}

void ParseProfile(napi_env env, napi_value root, Profile& profile)
{
    MEDIA_DEBUG_LOG("ParseProfile is called");
    napi_value res = nullptr;

    CHECK_EXECUTE(napi_get_named_property(env, root, "size", &res) == napi_ok, ParseSize(env, res, profile.size_));

    int32_t intValue = 0;
    if (napi_get_named_property(env, root, "format", &res) == napi_ok) {
        napi_get_value_int32(env, res, &intValue);
        profile.format_ = static_cast<CameraFormat>(intValue);
    }
}

void ParseVideoProfile(napi_env env, napi_value root, VideoProfile& profile)
{
    MEDIA_DEBUG_LOG("ParseVideoProfile is called");
    napi_value res = nullptr;

    CHECK_EXECUTE(napi_get_named_property(env, root, "size", &res) == napi_ok, ParseSize(env, res, profile.size_));

    int32_t intValue = 0;
    if (napi_get_named_property(env, root, "format", &res) == napi_ok) {
        napi_get_value_int32(env, res, &intValue);
        profile.format_ = static_cast<CameraFormat>(intValue);
    }

    if (napi_get_named_property(env, root, "frameRateRange", &res) == napi_ok) {
        const int32_t LENGTH = 2;
        std::vector<int32_t> rateRanges(LENGTH);
        napi_value value;

        CHECK_EXECUTE(napi_get_named_property(env, res, "min", &value) == napi_ok,
            napi_get_value_int32(env, value, &rateRanges[0]));
        CHECK_EXECUTE(napi_get_named_property(env, res, "max", &value) == napi_ok,
            napi_get_value_int32(env, value, &rateRanges[1]));
        profile.framerates_ = rateRanges;
    }
}


void ParseProfileList(napi_env env, napi_value arrayParam, std::vector<Profile> &profiles)
{
    uint32_t length = 0;
    napi_get_array_length(env, arrayParam, &length);
    for (uint32_t i = 0; i < length; ++i) {
        napi_value value;
        napi_get_element(env, arrayParam, i, &value);
        Profile profile; // 在栈上创建 Profile 对象
        ParseProfile(env, value, profile);
        profiles.push_back(profile);
    }
}

void ParseVideoProfileList(napi_env env, napi_value arrayParam, std::vector<VideoProfile> &profiles)
{
    uint32_t length = 0;
    napi_get_array_length(env, arrayParam, &length);
    for (uint32_t i = 0; i < length; ++i) {
        napi_value value;
        napi_get_element(env, arrayParam, i, &value);
        VideoProfile profile;
        ParseVideoProfile(env, value, profile);
        profiles.push_back(profile);
    }
}

void ParseCameraOutputCapability(napi_env env, napi_value root,
    std::vector<Profile>& previewProfiles,
    std::vector<Profile>& photoProfiles,
    std::vector<VideoProfile>& videoProfiles)
{
    previewProfiles.clear();
    photoProfiles.clear();
    videoProfiles.clear();
    napi_value res = nullptr;

    CHECK_EXECUTE(napi_get_named_property(env, root, "previewProfiles", &res) == napi_ok,
        ParseProfileList(env, res, previewProfiles));
    CHECK_EXECUTE(napi_get_named_property(env, root, "photoProfiles", &res) == napi_ok,
        ParseProfileList(env, res, photoProfiles));
    CHECK_EXECUTE(napi_get_named_property(env, root, "videoProfiles", &res) == napi_ok,
        ParseVideoProfileList(env, res, videoProfiles));
}

napi_value CameraSessionForSysNapi::GetSessionFunctions(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetSessionFunctions is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    std::vector<Profile> previewProfiles;
    std::vector<Profile> photoProfiles;
    std::vector<VideoProfile> videoProfiles;
    ParseCameraOutputCapability(env, argv[PARAM0], previewProfiles, photoProfiles, videoProfiles);
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionForSysNapi));
    CHECK_RETURN_RET_ELOG(status != napi_ok || cameraSessionForSysNapi == nullptr, nullptr,
        "napi_unwrap failure!");

    auto session = cameraSessionForSysNapi->cameraSessionForSys_;
    SceneMode mode = session->GetMode();
    auto cameraFunctionsList = session->GetSessionFunctions(previewProfiles, photoProfiles, videoProfiles);
    auto it = modeToFunctionTypeMap_.find(mode);
    if (it != modeToFunctionTypeMap_.end()) {
        result = CreateFunctionsJSArray(env, cameraFunctionsList, it->second);
    } else {
        MEDIA_ERR_LOG("GetSessionFunctions failed due to unsupported mode: %{public}d", mode);
    }
    return result;
}

napi_value CameraSessionForSysNapi::GetSessionConflictFunctions(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetSessionConflictFunctions is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);

    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionForSysNapi));
    CHECK_RETURN_RET_ELOG(status != napi_ok || cameraSessionForSysNapi == nullptr, nullptr,
        "napi_unwrap failure!");

    auto session = cameraSessionForSysNapi->cameraSessionForSys_;
    SceneMode mode = session->GetMode();
    auto conflictFunctionsList = session->GetSessionConflictFunctions();
    auto it = modeToConflictFunctionTypeMap_.find(mode);
    if (it != modeToConflictFunctionTypeMap_.end()) {
        result = CreateFunctionsJSArray(env, conflictFunctionsList, it->second);
    } else {
        MEDIA_ERR_LOG("GetSessionConflictFunctions failed due to unsupported mode: %{public}d", mode);
    }
    return result;
}

napi_value CameraSessionForSysNapi::CreateFunctionsJSArray(
    napi_env env, std::vector<sptr<CameraAbility>> functionsList, FunctionsType type)
{
    MEDIA_DEBUG_LOG("CreateFunctionsJSArray is called");
    napi_value functionsArray = nullptr;
    napi_value functions = nullptr;
    napi_status status;

    CHECK_PRINT_ELOG(functionsList.empty(), "functionsList is empty");

    status = napi_create_array(env, &functionsArray);
    CHECK_RETURN_RET_ELOG(status != napi_ok, functionsArray, "napi_create_array failed");

    size_t j = 0;
    for (size_t i = 0; i < functionsList.size(); i++) {
        functions = CameraFunctionsNapi::CreateCameraFunctions(env, functionsList[i], type);
        CHECK_RETURN_RET_ELOG((functions == nullptr) ||
            napi_set_element(env, functionsArray, j++, functions) != napi_ok, nullptr,
            "failed to create functions object napi wrapper object");
    }
    MEDIA_INFO_LOG("create functions count = %{public}zu", j);
    return functionsArray;
}

napi_value CameraSessionForSysNapi::IsLcdFlashSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsLcdFlashSupported is called");
    CAMERA_SYNC_TRACE;
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"),
        result, "IsLcdFlashSupported parse parameter occur error");
    if (cameraSessionForSysNapi != nullptr && cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        bool isSupported = cameraSessionForSysNapi->cameraSessionForSys_->IsLcdFlashSupported();
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsLcdFlashSupported call Failed!");
    }
    return result;
}

napi_value CameraSessionForSysNapi::EnableLcdFlash(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("EnableLcdFlash is called");
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    bool isEnable;
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi, isEnable);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), result,
        "EnableLcdFlash parse parameter occur error");

    if (cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        MEDIA_INFO_LOG("EnableLcdFlash:%{public}d", isEnable);
        cameraSessionForSysNapi->cameraSessionForSys_->LockForControl();
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->EnableLcdFlash(isEnable);
        cameraSessionForSysNapi->cameraSessionForSys_->UnlockForControl();
        CHECK_RETURN_RET_ELOG(!CameraNapiUtils::CheckError(env, retCode), result,
            "EnableLcdFlash fail %{public}d", retCode);
    } else {
        MEDIA_ERR_LOG("EnableLcdFlash get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return result;
    }
    return result;
}

napi_value CameraSessionForSysNapi::IsFocusRangeTypeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsFocusRangeTypeSupported is called");
    int32_t focusRangeType = 0;
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi, focusRangeType);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::IsFocusRangeTypeSupported parse parameter occur error");

    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (cameraSessionForSysNapi != nullptr && cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        bool isSupported = false;
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->IsFocusRangeTypeSupported(
            static_cast<FocusRangeType>(focusRangeType), isSupported);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsFocusRangeTypeSupported get native object fail");
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return nullptr;
    }
    return result;
}

napi_value CameraSessionForSysNapi::GetFocusRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetFocusRange is called");
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::GetFocusRange parse parameter occur error");

    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (cameraSessionForSysNapi != nullptr && cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        FocusRangeType focusRangeType = FocusRangeType::FOCUS_RANGE_TYPE_AUTO;
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->GetFocusRange(focusRangeType);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        napi_create_int32(env, focusRangeType, &result);
    } else {
        MEDIA_ERR_LOG("GetFocusRange get native object fail");
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return nullptr;
    }
    return result;
}

napi_value CameraSessionForSysNapi::SetFocusRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetFocusRange is called");
    int32_t focusRangeType = 0;
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi, focusRangeType);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::SetFocusRange parse parameter occur error");
    if (cameraSessionForSysNapi != nullptr && cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        cameraSessionForSysNapi->cameraSessionForSys_->LockForControl();
        int retCode =
            cameraSessionForSysNapi->cameraSessionForSys_->SetFocusRange(static_cast<FocusRangeType>(focusRangeType));
        cameraSessionForSysNapi->cameraSessionForSys_->UnlockForControl();
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
    } else {
        MEDIA_ERR_LOG("SetFocusRange get native object fail");
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return nullptr;
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionForSysNapi::IsFocusDrivenTypeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsFocusDrivenTypeSupported is called");
    int32_t focusDrivenType = 0;
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi, focusDrivenType);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::IsFocusDrivenTypeSupported parse parameter occur error");

    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (cameraSessionForSysNapi != nullptr && cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        bool isSupported = false;
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->IsFocusDrivenTypeSupported(
            static_cast<FocusDrivenType>(focusDrivenType), isSupported);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsFocusDrivenTypeSupported get native object fail");
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return nullptr;
    }
    return result;
}

napi_value CameraSessionForSysNapi::GetFocusDriven(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetFocusDriven is called");
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::GetFocusDriven parse parameter occur error");

    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (cameraSessionForSysNapi != nullptr && cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        FocusDrivenType focusDrivenType = FocusDrivenType::FOCUS_DRIVEN_TYPE_AUTO;
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->GetFocusDriven(focusDrivenType);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        napi_create_int32(env, focusDrivenType, &result);
    } else {
        MEDIA_ERR_LOG("GetFocusDriven get native object fail");
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return nullptr;
    }
    return result;
}

napi_value CameraSessionForSysNapi::SetFocusDriven(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetFocusDriven is called");
    int32_t focusDrivenType = 0;
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi, focusDrivenType);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::SetFocusDriven parse parameter occur error");
    if (cameraSessionForSysNapi != nullptr && cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        cameraSessionForSysNapi->cameraSessionForSys_->LockForControl();
        int retCode =
            cameraSessionForSysNapi->cameraSessionForSys_->
            SetFocusDriven(static_cast<FocusDrivenType>(focusDrivenType));
        cameraSessionForSysNapi->cameraSessionForSys_->UnlockForControl();
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
    } else {
        MEDIA_ERR_LOG("SetFocusDriven get native object fail");
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return nullptr;
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionForSysNapi::GetFocusDistance(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetFocusDistance is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    MEDIA_DEBUG_LOG("CameraSessionForSysNapi::GetFocusDistance get js args");
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionForSysNapi));
    if (status == napi_ok && cameraSessionForSysNapi != nullptr &&
        cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        float distance;
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->GetFocusDistance(distance);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        napi_create_double(env, distance, &result);
    } else {
        MEDIA_ERR_LOG("GetFocusDistance call Failed!");
    }
    return result;
}

napi_value CameraSessionForSysNapi::SetFocusDistance(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetFocusDistance is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionForSysNapi));
    if (status == napi_ok && cameraSessionForSysNapi != nullptr &&
        cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        double value;
        napi_get_value_double(env, argv[PARAM0], &value);
        float distance = static_cast<float>(value);
        cameraSessionForSysNapi->cameraSessionForSys_->LockForControl();
        cameraSessionForSysNapi->cameraSessionForSys_->SetFocusDistance(distance);
        MEDIA_INFO_LOG("CameraSessionForSysNapi::SetFocusDistance set focusDistance:%{public}f!", distance);
        cameraSessionForSysNapi->cameraSessionForSys_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetFocusDistance call Failed!");
    }
    return result;
}

napi_value CameraSessionForSysNapi::PrepareZoom(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PrepareZoom is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;

    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionForSysNapi));
    if (status == napi_ok && cameraSessionForSysNapi != nullptr &&
        cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        cameraSessionForSysNapi->cameraSessionForSys_->LockForControl();
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->PrepareZoom();
        cameraSessionForSysNapi->cameraSessionForSys_->UnlockForControl();
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
    } else {
        MEDIA_ERR_LOG("PrepareZoom call Failed!");
    }
    return result;
}

napi_value CameraSessionForSysNapi::UnPrepareZoom(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PrepareZoom is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;

    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionForSysNapi));
    if (status == napi_ok && cameraSessionForSysNapi != nullptr &&
        cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        cameraSessionForSysNapi->cameraSessionForSys_->LockForControl();
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->UnPrepareZoom();
        cameraSessionForSysNapi->cameraSessionForSys_->UnlockForControl();
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
    } else {
        MEDIA_ERR_LOG("PrepareZoom call Failed!");
    }
    return result;
}

napi_value CameraSessionForSysNapi::GetZoomPointInfos(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetZoomPointInfos is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);

    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionForSysNapi));
    if (status == napi_ok && cameraSessionForSysNapi != nullptr) {
        std::vector<ZoomPointInfo> vecZoomPointInfoList;
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->GetZoomPointInfos(vecZoomPointInfoList);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        MEDIA_INFO_LOG("CameraSessionForSysNapi::GetZoomPointInfos len = %{public}zu",
            vecZoomPointInfoList.size());

        if (!vecZoomPointInfoList.empty() && napi_create_array(env, &result) == napi_ok) {
            for (size_t i = 0; i < vecZoomPointInfoList.size(); i++) {
                ZoomPointInfo zoomPointInfo = vecZoomPointInfoList[i];
                napi_value value;
                napi_value zoomRatio;
                napi_value equivalentFocus;
                napi_create_object(env, &value);
                napi_create_double(env, CameraNapiUtils::FloatToDouble(zoomPointInfo.zoomRatio), &zoomRatio);
                napi_set_named_property(env, value, "zoomRatio", zoomRatio);
                napi_create_double(env, zoomPointInfo.equivalentFocalLength, &equivalentFocus);
                napi_set_named_property(env, value, "equivalentFocalLength", equivalentFocus);
                napi_set_element(env, result, i, value);
            }
        } else {
            MEDIA_ERR_LOG("vecSupportedZoomRatioList is empty or failed to create array!");
        }
    } else {
        MEDIA_ERR_LOG("GetZoomPointInfos call Failed!");
    }
    return result;
}

napi_value CameraSessionForSysNapi::GetSupportedBeautyTypes(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedBeautyTypes is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    MEDIA_DEBUG_LOG("CameraSessionForSysNapi::GetSupportedBeautyTypes get js args");
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    status = napi_create_array(env, &result);
    CHECK_RETURN_RET_ELOG(status != napi_ok, result, "napi_create_array call Failed!");
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionForSysNapi));
    if (status == napi_ok && cameraSessionForSysNapi != nullptr &&
        cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        std::vector<BeautyType> beautyTypes = cameraSessionForSysNapi->cameraSessionForSys_->GetSupportedBeautyTypes();
        MEDIA_INFO_LOG("CameraSessionForSysNapi::GetSupportedBeautyTypes len = %{public}zu",
            beautyTypes.size());
        if (!beautyTypes.empty() && status == napi_ok) {
            for (size_t i = 0; i < beautyTypes.size(); i++) {
                BeautyType beautyType = beautyTypes[i];
                napi_value value;
                napi_create_int32(env, beautyType, &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedBeautyTypes call Failed!");
    }
    return result;
}

napi_value CameraSessionForSysNapi::GetSupportedBeautyRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedBeautyRange is called");
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_status status;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    status = napi_create_array(env, &result);
    CHECK_RETURN_RET_ELOG(status != napi_ok, result, "napi_create_array call Failed!");
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionForSysNapi));
    if (status == napi_ok && cameraSessionForSysNapi != nullptr &&
        cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        int32_t beautyType;
        napi_get_value_int32(env, argv[PARAM0], &beautyType);
        std::vector<int32_t> beautyRanges =
            cameraSessionForSysNapi->cameraSessionForSys_->GetSupportedBeautyRange(static_cast<BeautyType>(beautyType));
        MEDIA_INFO_LOG("CameraSessionForSysNapi::GetSupportedBeautyRange beautyType = %{public}d, len = %{public}zu",
                       beautyType, beautyRanges.size());
        if (!beautyRanges.empty()) {
            for (size_t i = 0; i < beautyRanges.size(); i++) {
                int beautyRange = beautyRanges[i];
                napi_value value;
                napi_create_int32(env, beautyRange, &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedBeautyRange call Failed!");
    }
    return result;
}

napi_value CameraSessionForSysNapi::GetBeauty(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetBeauty is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionForSysNapi));
    if (status == napi_ok && cameraSessionForSysNapi != nullptr &&
        cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        int32_t beautyType;
        napi_get_value_int32(env, argv[PARAM0], &beautyType);
        int32_t beautyStrength =
            cameraSessionForSysNapi->cameraSessionForSys_->GetBeauty(static_cast<BeautyType>(beautyType));
        napi_create_int32(env, beautyStrength, &result);
    } else {
        MEDIA_ERR_LOG("GetBeauty call Failed!");
    }
    return result;
}

napi_value CameraSessionForSysNapi::SetBeauty(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetBeauty is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO];
    napi_value thisVar = nullptr;

    MEDIA_DEBUG_LOG("CameraSessionForSysNapi::SetBeauty get js args");
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionForSysNapi));
    if (status == napi_ok && cameraSessionForSysNapi != nullptr &&
        cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        int32_t beautyType;
        napi_get_value_int32(env, argv[PARAM0], &beautyType);
        int32_t beautyStrength;
        napi_get_value_int32(env, argv[PARAM1], &beautyStrength);
        cameraSessionForSysNapi->cameraSessionForSys_->LockForControl();
        cameraSessionForSysNapi->cameraSessionForSys_->SetBeauty(static_cast<BeautyType>(beautyType), beautyStrength);
        cameraSessionForSysNapi->cameraSessionForSys_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetBeauty call Failed!");
    }
    return result;
}

napi_value CameraSessionForSysNapi::GetSupportedPortraitThemeTypes(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedPortraitThemeTypes is called");
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::GetSupportedPortraitThemeTypes parse parameter occur error");

    napi_status status;
    napi_value result = nullptr;
    status = napi_create_array(env, &result);
    CHECK_RETURN_RET_ELOG(status != napi_ok, nullptr, "napi_create_array call Failed!");

    if (cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        std::vector<PortraitThemeType> themeTypes;
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->GetSupportedPortraitThemeTypes(themeTypes);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        MEDIA_INFO_LOG("CameraSessionForSysNapi::GetSupportedPortraitThemeTypes len = %{public}zu", themeTypes.size());
        if (!themeTypes.empty()) {
            for (size_t i = 0; i < themeTypes.size(); i++) {
                napi_value value;
                napi_create_int32(env, static_cast<int32_t>(themeTypes[i]), &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedPortraitThemeTypes call Failed!");
    }
    return result;
}

napi_value CameraSessionForSysNapi::SetPortraitThemeType(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraSessionForSysNapi::SetPortraitThemeType is called");
    int32_t type = 0;
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi, type);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::SetPortraitThemeType parse parameter occur error");

    if (cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        PortraitThemeType portraitThemeType = static_cast<PortraitThemeType>(type);
        MEDIA_INFO_LOG("CameraSessionForSysNapi::SetPortraitThemeType:%{public}d", portraitThemeType);
        cameraSessionForSysNapi->cameraSessionForSys_->LockForControl();
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->SetPortraitThemeType(portraitThemeType);
        cameraSessionForSysNapi->cameraSessionForSys_->UnlockForControl();
        CHECK_RETURN_RET_ELOG(!CameraNapiUtils::CheckError(env, retCode), nullptr,
            "CameraSessionForSysNapi::SetPortraitThemeType fail %{public}d", retCode);
    } else {
        MEDIA_ERR_LOG("CameraSessionForSysNapi::SetPortraitThemeType get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return nullptr;
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionForSysNapi::IsPortraitThemeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraSessionForSysNapi::IsPortraitThemeSupported is called");
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::IsPortraitThemeSupported parse parameter occur error");
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        bool isSupported;
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->IsPortraitThemeSupported(isSupported);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("CameraSessionForSysNapi::IsPortraitThemeSupported get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return nullptr;
    }
    return result;
}

napi_value CameraSessionForSysNapi::GetSupportedColorEffects(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedColorEffects is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    MEDIA_DEBUG_LOG("CameraSessionForSysNapi::GetSupportedColorEffects get js args");
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    status = napi_create_array(env, &result);
    CHECK_RETURN_RET_ELOG(status != napi_ok, result, "napi_create_array call Failed!");
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionForSysNapi));
    if (status == napi_ok && cameraSessionForSysNapi != nullptr &&
        cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        std::vector<ColorEffect> colorEffects =
            cameraSessionForSysNapi->cameraSessionForSys_->GetSupportedColorEffects();
        if (!colorEffects.empty()) {
            for (size_t i = 0; i < colorEffects.size(); i++) {
                int colorEffect = colorEffects[i];
                napi_value value;
                napi_create_int32(env, colorEffect, &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedColorEffects call Failed!");
    }
    return result;
}

napi_value CameraSessionForSysNapi::GetColorEffect(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetColorEffect is called");
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    napi_status status;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionForSysNapi));
    if (status == napi_ok && cameraSessionForSysNapi != nullptr &&
        cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        ColorEffect colorEffect = cameraSessionForSysNapi->cameraSessionForSys_->GetColorEffect();
        napi_create_int32(env, colorEffect, &result);
    } else {
        MEDIA_ERR_LOG("GetColorEffect call Failed!");
    }
    return result;
}

napi_value CameraSessionForSysNapi::SetColorEffect(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetColorEffect is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionForSysNapi));
    if (status == napi_ok && cameraSessionForSysNapi != nullptr &&
        cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        int32_t colorEffectNumber;
        napi_get_value_int32(env, argv[PARAM0], &colorEffectNumber);
        ColorEffect colorEffect = (ColorEffect)colorEffectNumber;
        cameraSessionForSysNapi->cameraSessionForSys_->LockForControl();
        cameraSessionForSysNapi->cameraSessionForSys_->SetColorEffect(static_cast<ColorEffect>(colorEffect));
        cameraSessionForSysNapi->cameraSessionForSys_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetColorEffect call Failed!");
    }
    return result;
}

napi_value CameraSessionForSysNapi::IsDepthFusionSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraSessionForSysNapi::IsDepthFusionSupported is called");
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::IsDepthFusionSupported parse parameter occur error");
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        bool isSupported = cameraSessionForSysNapi->cameraSessionForSys_->IsDepthFusionSupported();
        napi_get_boolean(env, isSupported, &result);
        return result;
    } else {
        MEDIA_ERR_LOG("CameraSessionForSysNapi::IsDepthFusionSupported call Failed!");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return nullptr;
    }
    return result;
}

napi_value CameraSessionForSysNapi::GetDepthFusionThreshold(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraSessionForSysNapi::GetDepthFusionThreshold is called");
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::IsDepthFusionSupported parse parameter occur error");
    napi_value result = nullptr;
    if (cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        std::vector<float> vecDepthFusionThreshold;
        int32_t retCode =
            cameraSessionForSysNapi->cameraSessionForSys_->GetDepthFusionThreshold(vecDepthFusionThreshold);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        MEDIA_INFO_LOG("CameraSessionForSysNapi::GetDepthFusionThreshold len = %{public}zu",
            vecDepthFusionThreshold.size());

        if (!vecDepthFusionThreshold.empty() && napi_create_array(env, &result) == napi_ok) {
            for (size_t i = 0; i < vecDepthFusionThreshold.size(); i++) {
                float depthFusion = vecDepthFusionThreshold[i];
                napi_value value;
                napi_create_double(env, CameraNapiUtils::FloatToDouble(depthFusion), &value);
                napi_set_element(env, result, i, value);
            }
        } else {
            MEDIA_ERR_LOG("vecDepthFusionThreshold is empty or failed to create array!");
        }
    } else {
        MEDIA_ERR_LOG("CameraSessionForSysNapi::GetDepthFusionThreshold call Failed!");
        return nullptr;
    }
    return result;
}

napi_value CameraSessionForSysNapi::IsDepthFusionEnabled(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraSessionForSysNapi::IsDepthFusionEnabled is called");
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::IsDepthFusionEnabled parse parameter occur error");
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        bool isEnabled = cameraSessionForSysNapi->cameraSessionForSys_->IsDepthFusionEnabled();
        napi_get_boolean(env, isEnabled, &result);
        MEDIA_INFO_LOG("CameraSessionForSysNapi::IsDepthFusionEnabled:%{public}d", isEnabled);
    } else {
        MEDIA_ERR_LOG("CameraSessionForSysNapi::IsDepthFusionEnabled get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return nullptr;
    }
    return result;
}

napi_value CameraSessionForSysNapi::EnableDepthFusion(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraSessionForSysNapi::EnableDepthFusion is called");
    bool isEnabledDepthFusion;
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi, isEnabledDepthFusion);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::EnabledDepthFusion parse parameter occur error");
    
    if (cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        MEDIA_INFO_LOG("CameraSessionForSysNapi::EnableDepthFusion:%{public}d", isEnabledDepthFusion);
        cameraSessionForSysNapi->cameraSessionForSys_->LockForControl();
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->EnableDepthFusion(isEnabledDepthFusion);
        cameraSessionForSysNapi->cameraSessionForSys_->UnlockForControl();
        CHECK_RETURN_RET_ELOG(!CameraNapiUtils::CheckError(env, retCode), nullptr,
            "CameraSessionForSysNapi::EnableDepthFusion fail %{public}d", retCode);
        MEDIA_INFO_LOG("CameraSessionForSysNapi::EnableDepthFusion success");
    } else {
        MEDIA_ERR_LOG("CameraSessionForSysNapi::EnableDepthFusion get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return nullptr;
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionForSysNapi::IsFeatureSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsFeatureSupported is called");
    int32_t sceneFeature;
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi, sceneFeature);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::IsFeatureSupported parse parameter occur error");

    napi_value result = nullptr;
    napi_get_boolean(env,
        cameraSessionForSysNapi->cameraSessionForSys_->IsFeatureSupported(static_cast<SceneFeature>(sceneFeature)),
        &result);
    return result;
}

napi_value CameraSessionForSysNapi::EnableFeature(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("EnableFeature is called");
    int32_t sceneFeature;
    bool isEnable;
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi, sceneFeature, isEnable);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::EnableFeature parse parameter occur error");

    MEDIA_INFO_LOG("CameraSessionForSysNapi::EnableFeature:%{public}d", isEnable);
    int32_t retCode =
        cameraSessionForSysNapi->cameraSessionForSys_->EnableFeature(static_cast<SceneFeature>(sceneFeature), isEnable);
    CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);

    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionForSysNapi::IsEffectSuggestionSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsEffectSuggestionSupported is called");
    napi_status status;
    napi_value effectResult = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &effectResult);
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionForSysNapi));
    if (status == napi_ok && cameraSessionForSysNapi != nullptr &&
        cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        bool isEffectSuggestionSupported = cameraSessionForSysNapi->cameraSessionForSys_->IsEffectSuggestionSupported();
        napi_get_boolean(env, isEffectSuggestionSupported, &effectResult);
    } else {
        MEDIA_ERR_LOG("IsEffectSuggestionSupported call Failed!");
    }
    return effectResult;
}

napi_value CameraSessionForSysNapi::EnableEffectSuggestion(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("EnableEffectSuggestion is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires one parameter");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    CHECK_RETURN_RET(valueType != napi_boolean && !CameraNapiUtils::CheckError(env, INVALID_ARGUMENT), result);
    napi_get_undefined(env, &result);
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionForSysNapi));
    if (status == napi_ok && cameraSessionForSysNapi != nullptr &&
        cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        bool enabled;
        napi_get_value_bool(env, argv[PARAM0], &enabled);
        MEDIA_INFO_LOG("CameraSessionForSysNapi::EnableEffectSuggestion:%{public}d", enabled);
        cameraSessionForSysNapi->cameraSessionForSys_->LockForControl();
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->EnableEffectSuggestion(enabled);
        cameraSessionForSysNapi->cameraSessionForSys_->UnlockForControl();
        CHECK_RETURN_RET(retCode != 0 && !CameraNapiUtils::CheckError(env, retCode), result);
    }
    return result;
}

napi_value CameraSessionForSysNapi::GetSupportedEffectSuggestionType(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedEffectSuggestionType is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    MEDIA_DEBUG_LOG("CameraSessionForSysNapi::GetSupportedEffectSuggestionType get js args");
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    status = napi_create_array(env, &result);
    CHECK_RETURN_RET_ELOG(status != napi_ok, result, "napi_create_array call Failed!");
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionForSysNapi));
    if (status == napi_ok && cameraSessionForSysNapi != nullptr &&
        cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        std::vector<EffectSuggestionType> effectSuggestionTypeList =
            cameraSessionForSysNapi->cameraSessionForSys_->GetSupportedEffectSuggestionType();
        if (!effectSuggestionTypeList.empty()) {
            for (size_t i = 0; i < effectSuggestionTypeList.size(); i++) {
                int type = effectSuggestionTypeList[i];
                napi_value value;
                napi_create_int32(env, type, &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedEffectSuggestionType call Failed!");
    }
    return result;
}

static void ParseEffectSuggestionStatus(napi_env env, napi_value arrayParam,
    std::vector<EffectSuggestionStatus> &effectSuggestionStatusList)
{
    MEDIA_DEBUG_LOG("ParseEffectSuggestionStatus is called");
    uint32_t length = 0;
    napi_value value;
    napi_get_array_length(env, arrayParam, &length);
    for (uint32_t i = 0; i < length; i++) {
        napi_get_element(env, arrayParam, i, &value);
        napi_value res = nullptr;
        EffectSuggestionStatus effectSuggestionStatus;
        int32_t intValue = 0;
        if (napi_get_named_property(env, value, "type", &res) == napi_ok) {
            napi_get_value_int32(env, res, &intValue);
            effectSuggestionStatus.type = static_cast<EffectSuggestionType>(intValue);
        }
        bool enabled = false;
        if (napi_get_named_property(env, value, "status", &res) == napi_ok) {
            napi_get_value_bool(env, res, &enabled);
            effectSuggestionStatus.status = enabled;
        }
        effectSuggestionStatusList.push_back(effectSuggestionStatus);
    }
}

napi_value CameraSessionForSysNapi::SetEffectSuggestionStatus(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("SetEffectSuggestionStatus is called");
    size_t argc = ARGS_ONE;
    napi_status status;
    napi_value result = nullptr;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    std::vector<EffectSuggestionStatus> effectSuggestionStatusList;
    ParseEffectSuggestionStatus(env, argv[PARAM0], effectSuggestionStatusList);

    napi_get_undefined(env, &result);
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionForSysNapi));
    if (status == napi_ok && cameraSessionForSysNapi != nullptr &&
        cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        cameraSessionForSysNapi->cameraSessionForSys_->LockForControl();
        int32_t retCode =
            cameraSessionForSysNapi->cameraSessionForSys_->SetEffectSuggestionStatus(effectSuggestionStatusList);
        cameraSessionForSysNapi->cameraSessionForSys_->UnlockForControl();
        CHECK_RETURN_RET(retCode != 0 && !CameraNapiUtils::CheckError(env, retCode), result);
    }
    return result;
}

napi_value CameraSessionForSysNapi::UpdateEffectSuggestion(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("UpdateEffectSuggestion is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = { 0, 0 };
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_TWO, "requires two parameter");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[PARAM0], &valueType);
    CHECK_RETURN_RET(valueType != napi_number && !CameraNapiUtils::CheckError(env, INVALID_ARGUMENT), result);
    napi_typeof(env, argv[PARAM1], &valueType);
    CHECK_RETURN_RET(valueType != napi_boolean && !CameraNapiUtils::CheckError(env, INVALID_ARGUMENT), result);

    napi_get_undefined(env, &result);
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionForSysNapi));
    if (status == napi_ok && cameraSessionForSysNapi != nullptr &&
        cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        auto effectSuggestionType = (EffectSuggestionType)value;
        bool enabled;
        napi_get_value_bool(env, argv[PARAM1], &enabled);
        MEDIA_INFO_LOG("CameraSessionForSysNapi::UpdateEffectSuggestion:%{public}d enabled:%{public}d",
            effectSuggestionType, enabled);
        cameraSessionForSysNapi->cameraSessionForSys_->LockForControl();
        int32_t retCode =
            cameraSessionForSysNapi->cameraSessionForSys_->UpdateEffectSuggestion(effectSuggestionType, enabled);
        cameraSessionForSysNapi->cameraSessionForSys_->UnlockForControl();
        CHECK_RETURN_RET(retCode != 0 && !CameraNapiUtils::CheckError(env, retCode), result);
    }
    return result;
}

napi_value CameraSessionForSysNapi::GetSupportedVirtualApertures(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedVirtualApertures is called");
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::GetSupportedVirtualApertures parse parameter occur error");

    napi_status status;
    napi_value result = nullptr;
    status = napi_create_array(env, &result);
    CHECK_RETURN_RET_ELOG(status != napi_ok, nullptr, "napi_create_array call Failed!");

    if (cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        std::vector<float> virtualApertures = {};
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->GetSupportedVirtualApertures(virtualApertures);
        MEDIA_INFO_LOG("GetSupportedVirtualApertures virtualApertures len = %{public}zu", virtualApertures.size());
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        if (!virtualApertures.empty()) {
            for (size_t i = 0; i < virtualApertures.size(); i++) {
                float virtualAperture = virtualApertures[i];
                napi_value value;
                napi_create_double(env, CameraNapiUtils::FloatToDouble(virtualAperture), &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedVirtualApertures call Failed!");
    }
    return result;
}

napi_value CameraSessionForSysNapi::GetVirtualAperture(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetVirtualAperture is called");
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::GetVirtualAperture parse parameter occur error");
    if (cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        float virtualAperture;
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->GetVirtualAperture(virtualAperture);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        napi_value result;
        napi_create_double(env, CameraNapiUtils::FloatToDouble(virtualAperture), &result);
        return result;
    } else {
        MEDIA_ERR_LOG("GetVirtualAperture call Failed!");
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionForSysNapi::SetVirtualAperture(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetVirtualAperture is called");
    double virtualAperture;
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi, virtualAperture);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::SetVirtualAperture parse parameter occur error");
    if (cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        cameraSessionForSysNapi->cameraSessionForSys_->LockForControl();
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->SetVirtualAperture((float)virtualAperture);
        MEDIA_INFO_LOG("SetVirtualAperture set virtualAperture %{public}f!", virtualAperture);
        cameraSessionForSysNapi->cameraSessionForSys_->UnlockForControl();
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
    } else {
        MEDIA_ERR_LOG("SetVirtualAperture call Failed!");
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionForSysNapi::GetSupportedPhysicalApertures(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedPhysicalApertures is called");
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::GetSupportedPhysicalApertures parse parameter occur error");

    napi_status status;
    napi_value result = nullptr;
    status = napi_create_array(env, &result);
    CHECK_RETURN_RET_ELOG(status != napi_ok, nullptr, "napi_create_array call Failed!");

    if (status == napi_ok && cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        std::vector<std::vector<float>> physicalApertures = {};
        int32_t retCode =
            cameraSessionForSysNapi->cameraSessionForSys_->GetSupportedPhysicalApertures(physicalApertures);
        MEDIA_INFO_LOG("GetSupportedPhysicalApertures len = %{public}zu", physicalApertures.size());
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        if (!physicalApertures.empty()) {
            result = CameraNapiUtils::ProcessingPhysicalApertures(env, physicalApertures);
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedPhysicalApertures call Failed!");
    }
    return result;
}

napi_value CameraSessionForSysNapi::GetPhysicalAperture(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetPhysicalAperture is called");
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::GetPhysicalAperture parse parameter occur error");

    if (cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        float physicalAperture = 0.0;
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->GetPhysicalAperture(physicalAperture);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        napi_value result = nullptr;
        napi_create_double(env, CameraNapiUtils::FloatToDouble(physicalAperture), &result);
        return result;
    } else {
        MEDIA_ERR_LOG("GetPhysicalAperture call Failed!");
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionForSysNapi::SetPhysicalAperture(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetPhysicalAperture is called");
    double physicalAperture;
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi, physicalAperture);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::SetPhysicalAperture parse parameter occur error");

    if (cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        cameraSessionForSysNapi->cameraSessionForSys_->LockForControl();
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->SetPhysicalAperture((float)physicalAperture);
        MEDIA_INFO_LOG("SetPhysicalAperture set physicalAperture %{public}f!", ConfusingNumber(physicalAperture));
        cameraSessionForSysNapi->cameraSessionForSys_->UnlockForControl();
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
    } else {
        MEDIA_ERR_LOG("SetPhysicalAperture call Failed!");
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value CameraSessionForSysNapi::GetSupportedColorReservationTypes(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedColorReservationTypes is called");
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::GetSupportedColorReservationTypes parse parameter occur error");

    napi_value result = nullptr;
    napi_status status = napi_create_array(env, &result);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("GetSupportedColorReservationTypes napi_create_array call Failed!");
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "napi_create_array call Failed!");
        return nullptr;
    }
    if (cameraSessionForSysNapi != nullptr && cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        std::vector<ColorReservationType> colorReservationTypes;
        int32_t retCode =
            cameraSessionForSysNapi->cameraSessionForSys_->GetSupportedColorReservationTypes(colorReservationTypes);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);

        MEDIA_INFO_LOG("CameraSessionForSysNapi::GetSupportedColorReservationTypes len = %{public}zu",
            colorReservationTypes.size());
        if (!colorReservationTypes.empty()) {
            for (size_t i = 0; i < colorReservationTypes.size(); i++) {
                ColorReservationType colorReservationType = colorReservationTypes[i];
                napi_value value;
                napi_create_int32(env, colorReservationType, &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedColorReservationTypes get native object fail");
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return nullptr;
    }
    return result;
}

napi_value CameraSessionForSysNapi::GetColorReservation(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetColorReservation is called");
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::GetColorReservation parse parameter occur error");

    auto result = CameraNapiUtils::GetUndefinedValue(env);
    if (cameraSessionForSysNapi != nullptr && cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        ColorReservationType colorReservationType = ColorReservationType::COLOR_RESERVATION_TYPE_NONE;
        int32_t retCode = cameraSessionForSysNapi->cameraSessionForSys_->GetColorReservation(colorReservationType);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        napi_create_int32(env, colorReservationType, &result);
    } else {
        MEDIA_ERR_LOG("GetColorReservation get native object fail");
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return nullptr;
    }
    return result;
}

napi_value CameraSessionForSysNapi::SetColorReservation(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetColorReservation is called");
    int32_t colorReservationType = 0;
    CameraSessionForSysNapi* cameraSessionForSysNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, cameraSessionForSysNapi, colorReservationType);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(PARAMETER_ERROR, "parse parameter occur error"), nullptr,
        "CameraSessionForSysNapi::SetColorReservation parse parameter occur error");
    if (cameraSessionForSysNapi != nullptr && cameraSessionForSysNapi->cameraSessionForSys_ != nullptr) {
        cameraSessionForSysNapi->cameraSessionForSys_->LockForControl();
        int retCode = cameraSessionForSysNapi->cameraSessionForSys_->SetColorReservation(
            static_cast<ColorReservationType>(colorReservationType));
        cameraSessionForSysNapi->cameraSessionForSys_->UnlockForControl();
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
    } else {
        MEDIA_ERR_LOG("SetColorReservation get native object fail");
        CameraNapiUtils::ThrowError(env, PARAMETER_ERROR, "get native object fail");
        return nullptr;
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

void CameraSessionForSysNapi::RegisterSlowMotionStateCb(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be unregistered in current session!");
}

void CameraSessionForSysNapi::UnregisterSlowMotionStateCb(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be unregistered in current session!");
}

void CameraSessionForSysNapi::RegisterExposureInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be registered in current session!");
}

void CameraSessionForSysNapi::UnregisterExposureInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be unregistered in current session!");
}

void CameraSessionForSysNapi::RegisterIsoInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be registered in current session!");
}

void CameraSessionForSysNapi::UnregisterIsoInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be unregistered in current session!");
}

void CameraSessionForSysNapi::RegisterApertureInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be registered in current session!");
}

void CameraSessionForSysNapi::UnregisterApertureInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be unregistered in current session!");
}

void CameraSessionForSysNapi::RegisterLuminationInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be registered in current session!");
}

void CameraSessionForSysNapi::UnregisterLuminationInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CameraNapiUtils::ThrowError(
        env, CameraErrorCode::OPERATION_NOT_ALLOWED, "this type callback can not be unregistered in current session!");
}

void CameraSessionForSysNapi::RegisterTryAEInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be registered in current session!");
}

void CameraSessionForSysNapi::UnregisterTryAEInfoCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be unregistered in current session!");
}

void CameraSessionForSysNapi::RegisterLightStatusCallbackListener(const std::string& eventName,
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be registered in current session!");
}

void CameraSessionForSysNapi::UnregisterLightStatusCallbackListener(const std::string& eventName,
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be unregistered in current session!");
}

void CameraSessionForSysNapi::RegisterFocusTrackingInfoCallbackListener(const std::string& eventName,
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be registered in current session!");
}

void CameraSessionForSysNapi::UnregisterFocusTrackingInfoCallbackListener(const std::string& eventName,
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CameraNapiUtils::ThrowError(env, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be unregistered in current session!");
}

void CameraSessionForSysNapi::RegisterLcdFlashStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CHECK_RETURN_ELOG(cameraSessionForSys_ == nullptr, "cameraSession is null!");
    if (lcdFlashStatusCallback_ == nullptr) {
        lcdFlashStatusCallback_ = std::make_shared<LcdFlashStatusCallbackListener>(env);
        cameraSessionForSys_->SetLcdFlashStatusCallback(lcdFlashStatusCallback_);
    }
    lcdFlashStatusCallback_->SaveCallbackReference(eventName, callback, isOnce);
    cameraSessionForSys_->LockForControl();
    cameraSessionForSys_->EnableLcdFlashDetection(true);
    cameraSessionForSys_->UnlockForControl();
}

void CameraSessionForSysNapi::UnregisterLcdFlashStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CHECK_RETURN_ELOG(lcdFlashStatusCallback_ == nullptr, "lcdFlashStatusCallback is null");
    lcdFlashStatusCallback_->RemoveCallbackRef(eventName, callback);
    if (lcdFlashStatusCallback_->IsEmpty("lcdFlashStatus")) {
        cameraSessionForSys_->LockForControl();
        cameraSessionForSys_->EnableLcdFlashDetection(false);
        cameraSessionForSys_->UnlockForControl();
    }
}

void CameraSessionForSysNapi::RegisterEffectSuggestionCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (effectSuggestionCallback_ == nullptr) {
        auto effectSuggestionCallback = std::make_shared<EffectSuggestionCallbackListener>(env);
        effectSuggestionCallback_ = effectSuggestionCallback;
        cameraSessionForSys_->SetEffectSuggestionCallback(effectSuggestionCallback);
    }
    effectSuggestionCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void CameraSessionForSysNapi::UnregisterEffectSuggestionCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (effectSuggestionCallback_ == nullptr) {
        MEDIA_ERR_LOG("effectSuggestionCallback is null");
    } else {
        effectSuggestionCallback_->RemoveCallbackRef(eventName, callback);
    }
}

void CameraSessionForSysNapi::RegisterFeatureDetectionStatusListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    int32_t featureType = SceneFeature::FEATURE_ENUM_MAX;
    CameraNapiParamParser jsParamParser(env, args, featureType);
    CHECK_RETURN_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "Invalid feature type"),
        "CameraSessionForSysNapi::RegisterFeatureDetectionStatusListener Invalid feature type");
    if (featureType < SceneFeature::FEATURE_ENUM_MIN || featureType >= SceneFeature::FEATURE_ENUM_MAX) {
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "scene feature invalid");
        MEDIA_ERR_LOG("CameraSessionForSysNapi::RegisterFeatureDetectionStatusListener scene feature invalid");
        return;
    }

    if (featureDetectionStatusCallback_ == nullptr) {
        featureDetectionStatusCallback_ = std::make_shared<FeatureDetectionStatusCallbackListener>(env);
        cameraSessionForSys_->SetFeatureDetectionStatusCallback(featureDetectionStatusCallback_);
    }

    if (featureType == SceneFeature::FEATURE_LOW_LIGHT_BOOST) {
        cameraSessionForSys_->LockForControl();
        cameraSessionForSys_->EnableLowLightDetection(true);
        cameraSessionForSys_->UnlockForControl();
    }
    if (featureType == SceneFeature::FEATURE_TRIPOD_DETECTION) {
        cameraSessionForSys_->LockForControl();
        cameraSessionForSys_->EnableTripodDetection(true);
        cameraSessionForSys_->UnlockForControl();
    }
    featureDetectionStatusCallback_->SaveCallbackReference(eventName + std::to_string(featureType), callback, isOnce);
}

void CameraSessionForSysNapi::UnregisterFeatureDetectionStatusListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CHECK_RETURN_ELOG(featureDetectionStatusCallback_ == nullptr, "featureDetectionStatusCallback_ is null");
    int32_t featureType = SceneFeature::FEATURE_ENUM_MAX;
    CameraNapiParamParser jsParamParser(env, args, featureType);
    CHECK_RETURN_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "Invalid feature type"),
        "CameraSessionForSysNapi::RegisterFeatureDetectionStatusListener Invalid feature type");
    if (featureType < SceneFeature::FEATURE_ENUM_MIN || featureType >= SceneFeature::FEATURE_ENUM_MAX) {
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "scene feature invalid");
        MEDIA_ERR_LOG("CameraSessionForSysNapi::RegisterFeatureDetectionStatusListener scene feature invalid");
        return;
    }

    featureDetectionStatusCallback_->RemoveCallbackRef(eventName + std::to_string(featureType), callback);

    if (featureType == SceneFeature::FEATURE_LOW_LIGHT_BOOST &&
        !featureDetectionStatusCallback_->IsFeatureSubscribed(SceneFeature::FEATURE_LOW_LIGHT_BOOST)) {
        cameraSessionForSys_->LockForControl();
        cameraSessionForSys_->EnableLowLightDetection(false);
        cameraSessionForSys_->UnlockForControl();
    }
    if (featureType == SceneFeature::FEATURE_TRIPOD_DETECTION &&
        !featureDetectionStatusCallback_->IsFeatureSubscribed(SceneFeature::FEATURE_TRIPOD_DETECTION)) {
        cameraSessionForSys_->LockForControl();
        cameraSessionForSys_->EnableTripodDetection(false);
        cameraSessionForSys_->UnlockForControl();
    }
}

void EffectSuggestionCallbackListener::OnEffectSuggestionCallbackAsync(EffectSuggestionType effectSuggestionType) const
{
    MEDIA_DEBUG_LOG("OnEffectSuggestionCallbackAsync is called");
    std::unique_ptr<EffectSuggestionCallbackInfo> callbackInfo =
        std::make_unique<EffectSuggestionCallbackInfo>(effectSuggestionType, shared_from_this());
    EffectSuggestionCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        EffectSuggestionCallbackInfo* callbackInfo = reinterpret_cast<EffectSuggestionCallbackInfo *>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            CHECK_EXECUTE(listener != nullptr,
                listener->OnEffectSuggestionCallback(callbackInfo->effectSuggestionType_));
            delete callbackInfo;
        }
    };
    std::string taskName = "EffectSuggestionCallbackListener::OnEffectSuggestionCallbackAsync"
        "[effectSuggestionType:" + std::to_string(effectSuggestionType) + "]";
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate, taskName.c_str())) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        callbackInfo.release();
    }
}

void EffectSuggestionCallbackListener::OnEffectSuggestionCallback(EffectSuggestionType effectSuggestionType) const
{
    MEDIA_DEBUG_LOG("OnEffectSuggestionCallback is called");

    ExecuteCallbackScopeSafe("effectSuggestionChange", [&]() {
        napi_value callbackObj;
        napi_value errCode;

        napi_create_int32(env_, effectSuggestionType, &callbackObj);
        errCode = CameraNapiUtils::GetUndefinedValue(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void EffectSuggestionCallbackListener::OnEffectSuggestionChange(EffectSuggestionType effectSuggestionType)
{
    MEDIA_DEBUG_LOG("OnEffectSuggestionChange is called, effectSuggestionType: %{public}d", effectSuggestionType);
    OnEffectSuggestionCallbackAsync(effectSuggestionType);
}

void LcdFlashStatusCallbackListener::OnLcdFlashStatusCallbackAsync(LcdFlashStatusInfo lcdFlashStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnLcdFlashStatusCallbackAsync is called");
    auto callbackInfo = std::make_unique<LcdFlashStatusStatusCallbackInfo>(lcdFlashStatusInfo, shared_from_this());
    LcdFlashStatusStatusCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        auto callbackInfo = reinterpret_cast<LcdFlashStatusStatusCallbackInfo*>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            CHECK_EXECUTE(listener != nullptr,
                listener->OnLcdFlashStatusCallback(callbackInfo->lcdFlashStatusInfo_));
            delete callbackInfo;
        }
    };
    std::string taskName = "LcdFlashStatusCallbackListener::OnLcdFlashStatusCallbackAsync"
        "[lcdCompensation:" + std::to_string(lcdFlashStatusInfo.lcdCompensation) +
        ", isLcdFlashNeeded:" + std::to_string(lcdFlashStatusInfo.isLcdFlashNeeded) + "]";
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate, taskName.c_str())) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        callbackInfo.release();
    }
}

void LcdFlashStatusCallbackListener::OnLcdFlashStatusCallback(LcdFlashStatusInfo lcdFlashStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnLcdFlashStatusCallback is called");

    ExecuteCallbackScopeSafe("lcdFlashStatus", [&]() {
        napi_value callbackObj;
        napi_value propValue;
        napi_value errCode;

        napi_create_object(env_, &callbackObj);
        napi_get_boolean(env_, lcdFlashStatusInfo.isLcdFlashNeeded, &propValue);
        napi_set_named_property(env_, callbackObj, "isLcdFlashNeeded", propValue);
        napi_create_int32(env_, lcdFlashStatusInfo.lcdCompensation, &propValue);
        napi_set_named_property(env_, callbackObj, "lcdCompensation", propValue);
        errCode = CameraNapiUtils::GetUndefinedValue(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void LcdFlashStatusCallbackListener::OnLcdFlashStatusChanged(LcdFlashStatusInfo lcdFlashStatusInfo)
{
    MEDIA_DEBUG_LOG("OnLcdFlashStatusChanged is called, isLcdFlashNeeded: %{public}d, lcdCompensation: %{public}d",
        lcdFlashStatusInfo.isLcdFlashNeeded, lcdFlashStatusInfo.lcdCompensation);
    OnLcdFlashStatusCallbackAsync(lcdFlashStatusInfo);
}

void FeatureDetectionStatusCallbackListener::OnFeatureDetectionStatusChangedCallbackAsync(
    SceneFeature feature, FeatureDetectionStatus status) const
{
    MEDIA_DEBUG_LOG("OnFeatureDetectionStatusChangedCallbackAsync is called");
    auto callbackInfo = std::make_unique<FeatureDetectionStatusCallbackInfo>(feature, status, shared_from_this());
    FeatureDetectionStatusCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        auto callbackInfo = reinterpret_cast<FeatureDetectionStatusCallbackInfo*>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            CHECK_EXECUTE(listener != nullptr,
                listener->OnFeatureDetectionStatusChangedCallback(callbackInfo->feature_, callbackInfo->status_));
            delete callbackInfo;
        }
    };
    std::string taskName = "FeatureDetectionStatusCallbackListener::OnFeatureDetectionStatusChangedCallbackAsync"
        "[sceneFeature:" + std::to_string(feature) + ", status:" + std::to_string(status) + "]";
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate, taskName.c_str())) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        callbackInfo.release();
    }
}

void FeatureDetectionStatusCallbackListener::OnFeatureDetectionStatusChangedCallback(
    SceneFeature feature, FeatureDetectionStatus status) const
{
    MEDIA_DEBUG_LOG("OnFeatureDetectionStatusChangedCallback is called");
    std::string eventName = "featureDetection" + std::to_string(static_cast<int32_t>(feature));
    std::string eventNameOld = "featureDetectionStatus" + std::to_string(static_cast<int32_t>(feature));

    napi_value result[ARGS_TWO] = { nullptr, nullptr };
    napi_value retVal;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_create_object(env_, &result[PARAM1]);

    napi_value featureNapiValue;
    napi_create_int32(env_, feature, &featureNapiValue);
    napi_set_named_property(env_, result[PARAM1], "featureType", featureNapiValue);

    napi_value statusValue;
    napi_get_boolean(env_, status == FeatureDetectionStatus::ACTIVE, &statusValue);
    napi_set_named_property(env_, result[PARAM1], "detected", statusValue);

    if (feature == SceneFeature::FEATURE_TRIPOD_DETECTION) {
        napi_value tripodStatusValue;
        auto fwkTripodStatus = GetFeatureStatus();
        napi_create_int32(env_, fwkTripodStatus, &tripodStatusValue);
        napi_set_named_property(env_, result[PARAM1], "tripodStatus", tripodStatusValue);
    }
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(eventName, callbackNapiPara);
    ExecuteCallback(eventNameOld, callbackNapiPara);
}

void FeatureDetectionStatusCallbackListener::OnFeatureDetectionStatusChanged(
    SceneFeature feature, FeatureDetectionStatus status)
{
    MEDIA_DEBUG_LOG(
        "OnFeatureDetectionStatusChanged is called,feature:%{public}d, status: %{public}d", feature, status);
    OnFeatureDetectionStatusChangedCallbackAsync(feature, status);
}

bool FeatureDetectionStatusCallbackListener::IsFeatureSubscribed(SceneFeature feature)
{
    std::string eventName = "featureDetection" + std::to_string(static_cast<int32_t>(feature));
    std::string eventNameOld = "featureDetectionStatus" + std::to_string(static_cast<int32_t>(feature));

    return !IsEmpty(eventName) || !IsEmpty(eventNameOld);
}

napi_value CameraSessionForSysNapi::CameraSessionNapiForSysConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraSessionNapiForSysConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CameraSessionForSysNapi> obj = std::make_unique<CameraSessionForSysNapi>();
        if (obj != nullptr) {
            obj->env_ = env;
            CHECK_RETURN_RET_ELOG(sCameraSessionForSys_ == nullptr, result, "sCameraSessionForSys_ is null");
            obj->cameraSession_ = sCameraSessionForSys_;
            obj->cameraSessionForSys_ = sCameraSessionForSys_;
            status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                               CameraSessionForSysNapi::CameraSessionNapiForSysDestructor, nullptr, nullptr);
            if (status == napi_ok) {
                obj.release();
                return thisVar;
            } else {
                MEDIA_ERR_LOG("CameraSessionNapiForSysConstructor Failure wrapping js to native napi");
            }
        }
    }
    MEDIA_ERR_LOG("CameraSessionNapiForSysConstructor call Failed!");
    return result;
}

void CameraSessionForSysNapi::CameraSessionNapiForSysDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CameraSessionNapiForSysDestructor is called");
}

void CameraSessionForSysNapi::Init(napi_env env)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    std::vector<std::vector<napi_property_descriptor>> descriptors = { camera_process_props,
        CameraSessionForSysNapi::camera_process_sys_props, stabilization_props, flash_props,
        CameraSessionForSysNapi::flash_sys_props, auto_exposure_props, focus_props,
        CameraSessionForSysNapi::focus_sys_props, zoom_props, CameraSessionForSysNapi::zoom_sys_props,
        filter_props, macro_props,  moon_capture_boost_props, color_management_props, preconfig_props,
        CameraSessionForSysNapi::camera_output_capability_sys_props, CameraSessionForSysNapi::beauty_sys_props,
        CameraSessionForSysNapi::color_effect_sys_props, CameraSessionForSysNapi::manual_focus_sys_props,
        CameraSessionForSysNapi::depth_fusion_sys_props, CameraSessionForSysNapi::scene_detection_sys_props };
    std::vector<napi_property_descriptor> camera_session_props = CameraNapiUtils::GetPropertyDescriptor(descriptors);
    status = napi_define_class(env, CAMERA_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               CameraSessionNapiForSysConstructor, nullptr,
                               camera_session_props.size(),
                               camera_session_props.data(), &ctorObj);
    CHECK_RETURN_ELOG(status != napi_ok, "CameraSessionForSysNapi defined class failed");
    status = NapiRefManager::CreateMemSafetyRef(env, ctorObj, &sConstructor_);
    CHECK_RETURN_ELOG(status != napi_ok, "CameraSessionForSysNapi Init failed");
    MEDIA_DEBUG_LOG("CameraSessionForSysNapi Init success");
}

napi_value CameraSessionForSysNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    if (sConstructor_ == nullptr) {
        CameraSessionForSysNapi::Init(env);
        CHECK_RETURN_RET_ELOG(sConstructor_ == nullptr, result, "sConstructor_ is null");
    }
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        int retCode =
            CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(sCameraSessionForSys_, SceneMode::NORMAL);
        CHECK_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
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

std::unordered_map<int32_t, std::function<napi_value(napi_env)>> g_sessionFactories4Sys_ = {
    {JsSceneMode::JS_CAPTURE, [] (napi_env env) {
        return PhotoSessionForSysNapi::CreateCameraSession(env); }},
    {JsSceneMode::JS_VIDEO, [] (napi_env env) {
        return VideoSessionForSysNapi::CreateCameraSession(env); }},
    {JsSceneMode::JS_SECURE_CAMERA, [] (napi_env env) {
        return SecureSessionForSysNapi::CreateCameraSession(env); }},
    {JsSceneMode::JS_PORTRAIT, [] (napi_env env) { return PortraitSessionNapi::CreateCameraSession(env); }},
    {JsSceneMode::JS_NIGHT, [] (napi_env env) { return NightSessionNapi::CreateCameraSession(env); }},
    {JsSceneMode::JS_SLOW_MOTION, [] (napi_env env) { return SlowMotionSessionNapi::CreateCameraSession(env); }},
    {JsSceneMode::JS_PROFESSIONAL_PHOTO, [] (napi_env env) {
        return ProfessionSessionNapi::CreateCameraSession(env, SceneMode::PROFESSIONAL_PHOTO); }},
    {JsSceneMode::JS_PROFESSIONAL_VIDEO, [] (napi_env env) {
        return ProfessionSessionNapi::CreateCameraSession(env, SceneMode::PROFESSIONAL_VIDEO); }},
    {JsSceneMode::JS_CAPTURE_MARCO, [] (napi_env env) {
        return MacroPhotoSessionNapi::CreateCameraSession(env); }},
    {JsSceneMode::JS_VIDEO_MARCO, [] (napi_env env) {
        return MacroVideoSessionNapi::CreateCameraSession(env); }},
    {JsSceneMode::JS_HIGH_RES_PHOTO, [] (napi_env env) {
        return HighResPhotoSessionNapi::CreateCameraSession(env); }},
    {JsSceneMode::JS_QUICK_SHOT_PHOTO, [] (napi_env env) {
        return QuickShotPhotoSessionNapi::CreateCameraSession(env); }},
    {JsSceneMode::JS_APERTURE_VIDEO, [] (napi_env env) {
        return ApertureVideoSessionNapi::CreateCameraSession(env); }},
    {JsSceneMode::JS_PANORAMA_PHOTO, [] (napi_env env) {
        return PanoramaSessionNapi::CreateCameraSession(env); }},
    {JsSceneMode::JS_LIGHT_PAINTING, [] (napi_env env) {
        return LightPaintingSessionNapi::CreateCameraSession(env); }},
    {JsSceneMode::JS_TIMELAPSE_PHOTO, [] (napi_env env) {
        return TimeLapsePhotoSessionNapi::CreateCameraSession(env); }},
    {JsSceneMode::JS_FLUORESCENCE_PHOTO, [] (napi_env env) {
        return FluorescencePhotoSessionNapi::CreateCameraSession(env); }},
};

extern "C" napi_value createSessionInstanceForSys(napi_env env, int32_t jsModeName)
{
    MEDIA_DEBUG_LOG("createSessionInstanceForSys is called");
    napi_value result = nullptr;
    if (g_sessionFactories4Sys_.find(jsModeName) != g_sessionFactories4Sys_.end()) {
        result = g_sessionFactories4Sys_[jsModeName](env);
    } else {
        MEDIA_ERR_LOG("createSessionInstanceForSys mode = %{public}d not supported", jsModeName);
        CameraNapiUtils::ThrowError(env, CameraErrorCode::INVALID_ARGUMENT, "Invalid js mode");
    }
    return result;
}

extern "C" napi_value createDeprecatedSessionInstanceForSys(napi_env env)
{
    MEDIA_DEBUG_LOG("createDeprecatedSessionInstanceForSys is called");
    napi_value result = nullptr;
    result = CameraSessionForSysNapi::CreateCameraSession(env);
    CHECK_RETURN_RET_ELOG(result == nullptr, result, "createDeprecatedSessionInstanceForSys failed");
    return result;
}
} // namespace CameraStandard
} // namespace OHOS
