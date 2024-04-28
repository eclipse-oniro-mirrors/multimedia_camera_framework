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

#include <cstddef>
#include <uv.h>
#include "js_native_api.h"
#include "mode/profession_session_napi.h"
#include "camera_napi_security_utils.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

thread_local napi_ref ProfessionSessionNapi::sConstructor_ = nullptr;

ProfessionSessionNapi::ProfessionSessionNapi() : env_(nullptr), wrapper_(nullptr)
{
}
ProfessionSessionNapi::~ProfessionSessionNapi()
{
    MEDIA_DEBUG_LOG("~ProfessionSessionNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (professionSession_) {
        professionSession_ = nullptr;
    }
    exposureInfoCallback_ = nullptr;
    isoInfoCallback_ = nullptr;
    apertureInfoCallback_ = nullptr;
    luminationInfoCallback_ = nullptr;
}

void ProfessionSessionNapi::ProfessionSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("ProfessionSessionNapiDestructor is called");
    ProfessionSessionNapi* cameraObj = reinterpret_cast<ProfessionSessionNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}

const std::vector<napi_property_descriptor> ProfessionSessionNapi::manual_exposure_funcs = {
    DECLARE_NAPI_FUNCTION("getSupportedMeteringModes", ProfessionSessionNapi::GetSupportedMeteringModes),
    DECLARE_NAPI_FUNCTION("isExposureMeteringModeSupported", ProfessionSessionNapi::IsMeteringModeSupported),
    DECLARE_NAPI_FUNCTION("getExposureMeteringMode", ProfessionSessionNapi::GetMeteringMode),
    DECLARE_NAPI_FUNCTION("setExposureMeteringMode", ProfessionSessionNapi::SetMeteringMode),

    DECLARE_NAPI_FUNCTION("getExposureDurationRange", ProfessionSessionNapi::GetExposureDurationRange),
    DECLARE_NAPI_FUNCTION("getExposureDuration", ProfessionSessionNapi::GetExposureDuration),
    DECLARE_NAPI_FUNCTION("setExposureDuration", ProfessionSessionNapi::SetExposureDuration),
};

const std::vector<napi_property_descriptor> ProfessionSessionNapi::manual_focus_funcs = {
    DECLARE_NAPI_FUNCTION("getSupportedFocusAssistFlashModes",
        ProfessionSessionNapi::GetSupportedFocusAssistFlashModes),
    DECLARE_NAPI_FUNCTION("isFocusAssistSupported", ProfessionSessionNapi::IsFocusAssistFlashModeSupported),
    DECLARE_NAPI_FUNCTION("getFocusAssistFlashMode", ProfessionSessionNapi::GetFocusAssistFlashMode),
    DECLARE_NAPI_FUNCTION("setFocusAssist", ProfessionSessionNapi::SetFocusAssistFlashMode),
};

const std::vector<napi_property_descriptor> ProfessionSessionNapi::manual_iso_props = {
    DECLARE_NAPI_FUNCTION("getISORange", ProfessionSessionNapi::GetIsoRange),
    DECLARE_NAPI_FUNCTION("isManualISOSupported", ProfessionSessionNapi::IsManualIsoSupported),
    DECLARE_NAPI_FUNCTION("getISO", ProfessionSessionNapi::GetISO),
    DECLARE_NAPI_FUNCTION("setISO", ProfessionSessionNapi::SetISO),
};

const std::vector<napi_property_descriptor> ProfessionSessionNapi::auto_wb_props = {
    DECLARE_NAPI_FUNCTION("getSupportedWhiteBalanceModes", ProfessionSessionNapi::GetSupportedWhiteBalanceModes),
    DECLARE_NAPI_FUNCTION("isWhiteBalanceModeSupported", ProfessionSessionNapi::IsWhiteBalanceModeSupported),
    DECLARE_NAPI_FUNCTION("getWhiteBalanceMode", ProfessionSessionNapi::GetWhiteBalanceMode),
    DECLARE_NAPI_FUNCTION("setWhiteBalanceMode", ProfessionSessionNapi::SetWhiteBalanceMode),
};

const std::vector<napi_property_descriptor> ProfessionSessionNapi::manual_wb_props = {
    DECLARE_NAPI_FUNCTION("getWhiteBalanceRange", ProfessionSessionNapi::GetManualWhiteBalanceRange),
    DECLARE_NAPI_FUNCTION("isManualWhiteBalanceSupported", ProfessionSessionNapi::IsManualWhiteBalanceSupported),
    DECLARE_NAPI_FUNCTION("getWhiteBalance", ProfessionSessionNapi::GetManualWhiteBalance),
    DECLARE_NAPI_FUNCTION("setWhiteBalance", ProfessionSessionNapi::SetManualWhiteBalance),
};

const std::vector<napi_property_descriptor> ProfessionSessionNapi::pro_session_props = {
    DECLARE_NAPI_FUNCTION("getSupportedExposureHintModes", ProfessionSessionNapi::GetSupportedExposureHintModes),
    DECLARE_NAPI_FUNCTION("getExposureHintMode", ProfessionSessionNapi::GetExposureHintMode),
    DECLARE_NAPI_FUNCTION("setExposureHintMode", ProfessionSessionNapi::SetExposureHintMode),

    DECLARE_NAPI_FUNCTION("getSupportedPhysicalApertures", ProfessionSessionNapi::GetSupportedPhysicalApertures),
    DECLARE_NAPI_FUNCTION("getPhysicalAperture", ProfessionSessionNapi::GetPhysicalAperture),
    DECLARE_NAPI_FUNCTION("setPhysicalAperture", ProfessionSessionNapi::SetPhysicalAperture),
    DECLARE_NAPI_FUNCTION("on", ProfessionSessionNapi::On),
    DECLARE_NAPI_FUNCTION("once", ProfessionSessionNapi::Once),
    DECLARE_NAPI_FUNCTION("off", ProfessionSessionNapi::Off),
};

napi_value ProfessionSessionNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    std::vector<napi_property_descriptor> manual_exposure_props = CameraSessionNapi::auto_exposure_props;
    manual_exposure_props.insert(manual_exposure_props.end(), ProfessionSessionNapi::manual_exposure_funcs.begin(),
                                 ProfessionSessionNapi::manual_exposure_funcs.end());
    std::vector<napi_property_descriptor> pro_manual_focus_props = CameraSessionNapi::manual_focus_props;
    pro_manual_focus_props.insert(pro_manual_focus_props.end(), ProfessionSessionNapi::manual_focus_funcs.begin(),
                                  ProfessionSessionNapi::manual_focus_funcs.end());
    std::vector<std::vector<napi_property_descriptor>> descriptors = {
        CameraSessionNapi::camera_process_props, CameraSessionNapi::zoom_props,
        CameraSessionNapi::color_effect_props, CameraSessionNapi::flash_props,
        CameraSessionNapi::focus_props, ProfessionSessionNapi::manual_iso_props,
        ProfessionSessionNapi::auto_wb_props, ProfessionSessionNapi::manual_wb_props,
        ProfessionSessionNapi::pro_session_props, manual_exposure_props, pro_manual_focus_props};
    std::vector<napi_property_descriptor> professional_session_props =
        CameraNapiUtils::GetPropertyDescriptor(descriptors);
    status = napi_define_class(env, PROFESSIONAL_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               ProfessionSessionNapiConstructor, nullptr,
                               professional_session_props.size(),
                               professional_session_props.data(), &ctorObj);
    if (status == napi_ok) {
        int32_t refCount = 1;
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, PROFESSIONAL_SESSION_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value ProfessionSessionNapi::CreateCameraSession(napi_env env, SceneMode mode)
{
    MEDIA_DEBUG_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSession_ = CameraManager::GetInstance()->CreateCaptureSession(mode);
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("Failed to create Profession session instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSession_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("success to create Profession session napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Profession session napi instance");
        }
    }
    MEDIA_ERR_LOG("Failed to create Profession session napi instance last");
    napi_get_undefined(env, &result);
    return result;
}

napi_value ProfessionSessionNapi::ProfessionSessionNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("ProfessionSessionNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<ProfessionSessionNapi> obj = std::make_unique<ProfessionSessionNapi>();
        obj->env_ = env;
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("sCameraSession_ is null");
            return result;
        }
        obj->professionSession_ = static_cast<ProfessionSession*>(sCameraSession_.GetRefPtr());
        obj->cameraSession_ = obj->professionSession_;
        if (obj->professionSession_ == nullptr) {
            MEDIA_ERR_LOG("professionSession_ is null");
            return result;
        }
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            ProfessionSessionNapi::ProfessionSessionNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("ProfessionSessionNapi Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("ProfessionSessionNapi call Failed!");
    return result;
}
// MeteringMode
napi_value ProfessionSessionNapi::GetSupportedMeteringModes(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedMeteringModes is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    status = napi_create_array(env, &result);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("napi_create_array call Failed!");
        return result;
    }
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        std::vector<MeteringMode> meteringModes;
        int32_t retCode = professionSessionNapi->professionSession_->GetSupportedMeteringModes(meteringModes);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        MEDIA_INFO_LOG("ProfessionSessionNapi::GetSupportedMeteringModes len = %{public}zu",
            meteringModes.size());
        if (!meteringModes.empty()) {
            for (size_t i = 0; i < meteringModes.size(); i++) {
                MeteringMode mode = meteringModes[i];
                napi_value value;
                napi_create_int32(env, mode, &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedMeteringModes call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::IsMeteringModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsMeteringModeSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        MeteringMode mode = (MeteringMode)value;
        bool isSupported;
        int32_t retCode = professionSessionNapi->professionSession_->IsMeteringModeSupported(mode, isSupported);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsMeteringModeSupported call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::GetMeteringMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetMeteringMode is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        MeteringMode mode;
        int32_t retCode = professionSessionNapi->professionSession_->GetMeteringMode(mode);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_int32(env, mode, &result);
    } else {
        MEDIA_ERR_LOG("GetMeteringMode call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::SetMeteringMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetMeteringMode is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        MeteringMode mode = static_cast<MeteringMode>(value);
        professionSessionNapi->professionSession_->LockForControl();
        professionSessionNapi->professionSession_->
                SetMeteringMode(static_cast<MeteringMode>(mode));
        MEDIA_INFO_LOG("ProfessionSessionNapi SetMeteringMode set meteringMode %{public}d!", mode);
        professionSessionNapi->professionSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetMeteringMode call Failed!");
    }
    return result;
}
// ExposureDuration
napi_value ProfessionSessionNapi::GetExposureDurationRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("getExposureDurationRange is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr) {
        std::vector<uint32_t> vecExposureList;
        int32_t retCode = professionSessionNapi->professionSession_->GetSensorExposureTimeRange(vecExposureList);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        if (vecExposureList.empty() || napi_create_array(env, &result) != napi_ok) {
            return result;
        }
        for (size_t i = 0; i < vecExposureList.size(); i++) {
            uint32_t exposure = vecExposureList[i];
            MEDIA_DEBUG_LOG("EXPOSURE_RANGE : exposureDuration = %{public}d", vecExposureList[i]);
            napi_value value;
            napi_create_uint32(env, exposure, &value);
            napi_set_element(env, result, i, value);
        }
        MEDIA_DEBUG_LOG("EXPOSURE_RANGE ExposureList size : %{public}zu", vecExposureList.size());
    } else {
        MEDIA_ERR_LOG("getExposureDurationRange call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::GetExposureDuration(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetExposureDuration is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi!= nullptr) {
        uint32_t exposureDurationValue;
        int32_t retCode = professionSessionNapi->professionSession_->GetSensorExposureTime(exposureDurationValue);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        MEDIA_DEBUG_LOG("GetExposureDuration : exposureDuration = %{public}d", exposureDurationValue);
        napi_create_uint32(env, exposureDurationValue, &result);
    } else {
        MEDIA_ERR_LOG("GetExposureDuration call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::SetExposureDuration(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetExposureDuration is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr) {
        uint32_t exposureDurationValue;
        napi_get_value_uint32(env, argv[PARAM0], &exposureDurationValue);
        MEDIA_DEBUG_LOG("SetExposureDuration : exposureDuration = %{public}d", exposureDurationValue);
        professionSessionNapi->professionSession_->LockForControl();
        int32_t retCode = professionSessionNapi->professionSession_->SetSensorExposureTime(exposureDurationValue);
        professionSessionNapi->professionSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
    } else {
        MEDIA_ERR_LOG("SetExposureDuration call Failed!");
    }
    return result;
}

// FocusAssistFlashMode
napi_value ProfessionSessionNapi::GetSupportedFocusAssistFlashModes(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedFocusAssistFlashModes is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    status = napi_create_array(env, &result);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("napi_create_array call Failed!");
        return result;
    }
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        std::vector<FocusAssistFlashMode> focusAssistFlashs;
        int32_t retCode =
            professionSessionNapi->professionSession_->GetSupportedFocusAssistFlashModes(focusAssistFlashs);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        MEDIA_INFO_LOG("ProfessionSessionNapi::GetSupportedFocusAssistFlashModes len = %{public}zu",
            focusAssistFlashs.size());
        if (!focusAssistFlashs.empty()) {
            for (size_t i = 0; i < focusAssistFlashs.size(); i++) {
                FocusAssistFlashMode mode = focusAssistFlashs[i];
                napi_value value;
                napi_create_int32(env, mode, &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedFocusAssistFlashModes call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::IsFocusAssistFlashModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsFocusAssistFlashModeSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        FocusAssistFlashMode mode = static_cast<FocusAssistFlashMode>(value);
        bool isSupported;
        int32_t retCode = professionSessionNapi->professionSession_->IsFocusAssistFlashModeSupported(mode, isSupported);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsFocusAssistFlashModeSupported call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::GetFocusAssistFlashMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetFocusAssistFlashMode is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        FocusAssistFlashMode mode;
        int32_t retCode = professionSessionNapi->professionSession_->GetFocusAssistFlashMode(mode);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_int32(env, mode, &result);
    } else {
        MEDIA_ERR_LOG("GetFocusAssistFlashMode call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::SetFocusAssistFlashMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetFocusAssistFlashMode is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        bool value;
        napi_get_value_bool(env, argv[PARAM0], &value);
        FocusAssistFlashMode mode = static_cast<FocusAssistFlashMode>(value);
        professionSessionNapi->professionSession_->LockForControl();
        professionSessionNapi->professionSession_->
                SetFocusAssistFlashMode(static_cast<FocusAssistFlashMode>(mode));
        MEDIA_INFO_LOG("ProfessionSessionNapi SetFocusAssistFlashMode set focusAssistFlash %{public}d!", mode);
        professionSessionNapi->professionSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetFocusAssistFlashMode call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::GetIsoRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetIsoRange is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);

    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr) {
        std::vector<int32_t> vecIsoList;
        int32_t retCode = professionSessionNapi->professionSession_->GetIsoRange(vecIsoList);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        MEDIA_INFO_LOG("ProfessionSessionNapi::GetIsoRange len = %{public}zu", vecIsoList.size());

        if (!vecIsoList.empty() && napi_create_array(env, &result) == napi_ok) {
            for (size_t i = 0; i < vecIsoList.size(); i++) {
                int32_t iso = vecIsoList[i];
                napi_value value;
                napi_create_int32(env, iso, &value);
                napi_set_element(env, result, i, value);
            }
        } else {
            MEDIA_ERR_LOG("vecIsoList is empty or failed to create array!");
        }
    } else {
        MEDIA_ERR_LOG("GetIsoRange call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::IsManualIsoSupported(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsManualIsoSupported is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("IsManualIsoSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        bool isSupported = professionSessionNapi->professionSession_->IsManualIsoSupported();
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsManualIsoSupported call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::GetISO(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetISO is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        int32_t iso;
        int32_t retCode = professionSessionNapi->professionSession_->GetISO(iso);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_int32(env, iso, &result);
    } else {
        MEDIA_ERR_LOG("GetISO call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::SetISO(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetISO is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        int32_t iso;
        napi_get_value_int32(env, argv[PARAM0], &iso);
        professionSessionNapi->professionSession_->LockForControl();
        professionSessionNapi->professionSession_->SetISO(iso);
        MEDIA_INFO_LOG("ProfessionSessionNapi::SetISO set iso:%{public}d", iso);
        professionSessionNapi->professionSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetISO call Failed!");
    }
    return result;
}

// ------------------------------------------------auto_awb_props-------------------------------------------------------
napi_value ProfessionSessionNapi::GetSupportedWhiteBalanceModes(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedWhiteBalanceModes is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    status = napi_create_array(env, &result);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("napi_create_array call Failed!");
        return result;
    }
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        std::vector<WhiteBalanceMode> whiteBalanceModes;
        int32_t retCode = professionSessionNapi->professionSession_->GetSupportedWhiteBalanceModes(whiteBalanceModes);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }

        MEDIA_INFO_LOG("ProfessionSessionNapi::GetSupportedWhiteBalanceModes len = %{public}zu",
            whiteBalanceModes.size());
        if (!whiteBalanceModes.empty()) {
            for (size_t i = 0; i < whiteBalanceModes.size(); i++) {
                WhiteBalanceMode whiteBalanceMode = whiteBalanceModes[i];
                napi_value value;
                napi_create_int32(env, whiteBalanceMode, &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedWhiteBalanceModes call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::IsWhiteBalanceModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("IsWhiteBalanceModeSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        WhiteBalanceMode mode = (WhiteBalanceMode)value;
        bool isSupported;
        int32_t retCode = professionSessionNapi->professionSession_->IsWhiteBalanceModeSupported(mode, isSupported);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsWhiteBalanceModeSupported call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::GetWhiteBalanceMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetWhiteBalanceMode is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        WhiteBalanceMode whiteBalanceMode;
        int32_t retCode = professionSessionNapi->professionSession_->GetWhiteBalanceMode(whiteBalanceMode);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_int32(env, whiteBalanceMode, &result);
    } else {
        MEDIA_ERR_LOG("GetWhiteBalanceMode call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::SetWhiteBalanceMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetWhiteBalanceMode is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        WhiteBalanceMode mode = (WhiteBalanceMode)value;
        professionSessionNapi->professionSession_->LockForControl();
        professionSessionNapi->professionSession_->SetWhiteBalanceMode(mode);
        MEDIA_INFO_LOG("ProfessionSessionNapi::SetWhiteBalanceMode set mode:%{public}d", value);
        professionSessionNapi->professionSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetWhiteBalanceMode call Failed!");
    }
    return result;
}

// -----------------------------------------------manual_awb_props------------------------------------------------------
napi_value ProfessionSessionNapi::GetManualWhiteBalanceRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetManualWhiteBalanceRange is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);

    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr) {
        std::vector<int32_t> whiteBalanceRange = {};
        int32_t retCode = professionSessionNapi->professionSession_->GetManualWhiteBalanceRange(whiteBalanceRange);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        MEDIA_INFO_LOG("ProfessionSessionNapi::GetManualWhiteBalanceRange len = %{public}zu", whiteBalanceRange.size());

        if (!whiteBalanceRange.empty() && napi_create_array(env, &result) == napi_ok) {
            for (size_t i = 0; i < whiteBalanceRange.size(); i++) {
                int32_t iso = whiteBalanceRange[i];
                napi_value value;
                napi_create_int32(env, iso, &value);
                napi_set_element(env, result, i, value);
            }
        } else {
            MEDIA_ERR_LOG("whiteBalanceRange is empty or failed to create array!");
        }
    } else {
        MEDIA_ERR_LOG("GetManualWhiteBalanceRange call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::IsManualWhiteBalanceSupported(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsManualIsoSupported is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("IsManualIsoSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        bool isSupported;
        int32_t retCode = professionSessionNapi->professionSession_->IsManualWhiteBalanceSupported(isSupported);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsManualIsoSupported call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::GetManualWhiteBalance(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetISO is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        int32_t wbValue;
        int32_t retCode = professionSessionNapi->professionSession_->GetManualWhiteBalance(wbValue);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_int32(env, wbValue, &result);
    } else {
        MEDIA_ERR_LOG("GetISO call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::SetManualWhiteBalance(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetISO is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        int32_t wbValue;
        napi_get_value_int32(env, argv[PARAM0], &wbValue);
        professionSessionNapi->professionSession_->LockForControl();
        professionSessionNapi->professionSession_->SetManualWhiteBalance(wbValue);
        MEDIA_INFO_LOG("ProfessionSessionNapi::SetManualWhiteBalance set wbValue:%{public}d", wbValue);
        professionSessionNapi->professionSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetManualWhiteBalance call Failed!");
    }
    return result;
}

// ExposureHintMode
napi_value ProfessionSessionNapi::GetSupportedExposureHintModes(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedExposureHintModes is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    status = napi_create_array(env, &result);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("napi_create_array call Failed!");
        return result;
    }
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        std::vector<ExposureHintMode> exposureHints;
        int32_t retCode =
            professionSessionNapi->professionSession_->GetSupportedExposureHintModes(exposureHints);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        MEDIA_INFO_LOG("ProfessionSessionNapi::GetSupportedExposureHintModes len = %{public}zu",
            exposureHints.size());
        if (!exposureHints.empty()) {
            for (size_t i = 0; i < exposureHints.size(); i++) {
                ExposureHintMode mode = exposureHints[i];
                napi_value value;
                napi_create_int32(env, mode, &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedExposureHintModes call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::GetExposureHintMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetExposureHintMode is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        ExposureHintMode mode = EXPOSURE_HINT_UNSUPPORTED;
        int32_t retCode = professionSessionNapi->professionSession_->GetExposureHintMode(mode);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_int32(env, mode, &result);
    } else {
        MEDIA_ERR_LOG("GetExposureHintMode call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::SetExposureHintMode(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetExposureHintMode is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        ExposureHintMode mode = static_cast<ExposureHintMode>(value);
        professionSessionNapi->professionSession_->LockForControl();
        professionSessionNapi->professionSession_->
                SetExposureHintMode(static_cast<ExposureHintMode>(mode));
        MEDIA_INFO_LOG("ProfessionSessionNapi SetExposureHintMode set exposureHint %{public}d!", mode);
        professionSessionNapi->professionSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetExposureHintMode call Failed!");
    }
    return result;
}

//Aperture
napi_value ProfessionSessionNapi::ProcessingPhysicalApertures(napi_env env,
    std::vector<std::vector<float>> physicalApertures)
{
    napi_value result = nullptr;
    napi_create_array(env, &result);
    size_t zoomRangeSize = 2;
    for (size_t i = 0; i < physicalApertures.size(); i++) {
        if (physicalApertures[i].size() <= zoomRangeSize) {
            continue;
        }
        napi_value zoomRange;
        napi_create_array(env, &zoomRange);
        napi_value physicalApertureRange;
        napi_create_array(env, &physicalApertureRange);
        for (size_t y = 0; y < physicalApertures[i].size(); y++) {
            if (y < zoomRangeSize) {
                napi_value value;
                napi_create_double(env, CameraNapiUtils::FloatToDouble(physicalApertures[i][y]), &value);
                napi_set_element(env, zoomRange, y, value);
                continue;
            }
            napi_value value;
            napi_create_double(env, CameraNapiUtils::FloatToDouble(physicalApertures[i][y]), &value);
            napi_set_element(env, physicalApertureRange, y - zoomRangeSize, value);
        }
        napi_value obj;
        napi_create_object(env, &obj);
        napi_set_named_property(env, obj, "zoomRange", zoomRange);
        napi_set_named_property(env, obj, "apertures", physicalApertureRange);
        napi_set_element(env, result, i, obj);
    }
    return result;
}

napi_value ProfessionSessionNapi::GetSupportedPhysicalApertures(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedPhysicalApertures is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    status = napi_create_array(env, &result);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("napi_create_array call Failed!");
        return result;
    }
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        std::vector<std::vector<float>> physicalApertures = {};
        int32_t retCode = professionSessionNapi->professionSession_->GetSupportedPhysicalApertures(physicalApertures);
        MEDIA_INFO_LOG("GetSupportedPhysicalApertures len = %{public}zu", physicalApertures.size());
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        if (!physicalApertures.empty()) {
            result = ProcessingPhysicalApertures(env, physicalApertures);
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedPhysicalApertures call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::GetPhysicalAperture(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetPhysicalAperture is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        float physicalAperture = 0.0;
        int32_t retCode = professionSessionNapi->professionSession_->GetPhysicalAperture(physicalAperture);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_double(env, CameraNapiUtils::FloatToDouble(physicalAperture), &result);
    } else {
        MEDIA_ERR_LOG("GetPhysicalAperture call Failed!");
    }
    return result;
}

napi_value ProfessionSessionNapi::SetPhysicalAperture(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetPhysicalAperture is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    ProfessionSessionNapi* professionSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&professionSessionNapi));
    if (status == napi_ok && professionSessionNapi != nullptr && professionSessionNapi->professionSession_ != nullptr) {
        double physicalAperture;
        napi_get_value_double(env, argv[PARAM0], &physicalAperture);
        professionSessionNapi->professionSession_->LockForControl();
        int32_t retCode = professionSessionNapi->professionSession_->SetPhysicalAperture((float)physicalAperture);
        MEDIA_INFO_LOG("SetPhysicalAperture set physicalAperture %{public}f!", ConfusingNumber(physicalAperture));
        professionSessionNapi->professionSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
    } else {
        MEDIA_ERR_LOG("SetPhysicalAperture call Failed!");
    }
    return result;
}

void ProfessionSessionNapi::RegisterAbilityChangeCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (abilityCallback_ == nullptr) {
        abilityCallback_ = std::make_shared<AbilityCallbackListener>(env);
        professionSession_->SetAbilityCallback(abilityCallback_);
    }
    abilityCallback_->SaveCallbackReference(callback, isOnce);
}

void ProfessionSessionNapi::UnregisterAbilityChangeCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (abilityCallback_ == nullptr) {
        MEDIA_ERR_LOG("abilityCallback is null");
    } else {
        abilityCallback_->RemoveCallbackRef(env, callback);
    }
}

void ProfessionSessionNapi::RegisterExposureInfoCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (exposureInfoCallback_ == nullptr) {
        exposureInfoCallback_ = std::make_shared<ExposureInfoCallbackListener>(env);
        professionSession_->SetExposureInfoCallback(exposureInfoCallback_);
    }
    exposureInfoCallback_->SaveCallbackReference(callback, isOnce);
}

void ProfessionSessionNapi::UnregisterExposureInfoCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (exposureInfoCallback_ == nullptr) {
        MEDIA_ERR_LOG("abilityCallback is null");
    } else {
        exposureInfoCallback_->RemoveCallbackRef(env, callback);
    }
}

void ProfessionSessionNapi::RegisterIsoInfoCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (isoInfoCallback_ == nullptr) {
        isoInfoCallback_ = std::make_shared<IsoInfoCallbackListener>(env);
        professionSession_->SetIsoInfoCallback(isoInfoCallback_);
    }
    isoInfoCallback_->SaveCallbackReference(callback, isOnce);
}

void ProfessionSessionNapi::UnregisterIsoInfoCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (isoInfoCallback_ == nullptr) {
        MEDIA_ERR_LOG("abilityCallback is null");
    } else {
        isoInfoCallback_->RemoveCallbackRef(env, callback);
    }
}

void ProfessionSessionNapi::RegisterApertureInfoCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (apertureInfoCallback_ == nullptr) {
        apertureInfoCallback_ = std::make_shared<ApertureInfoCallbackListener>(env);
        professionSession_->SetApertureInfoCallback(apertureInfoCallback_);
    }
    apertureInfoCallback_->SaveCallbackReference(callback, isOnce);
}

void ProfessionSessionNapi::UnregisterApertureInfoCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (apertureInfoCallback_ == nullptr) {
        MEDIA_ERR_LOG("apertureInfoCallback is null");
    } else {
        apertureInfoCallback_->RemoveCallbackRef(env, callback);
    }
}

void ProfessionSessionNapi::RegisterLuminationInfoCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (luminationInfoCallback_ == nullptr) {
        ExposureHintMode mode = EXPOSURE_HINT_MODE_ON;
        professionSession_->LockForControl();
        professionSession_->SetExposureHintMode(mode);
        professionSession_->UnlockForControl();
        MEDIA_INFO_LOG("ProfessionSessionNapi SetExposureHintMode set exposureHint %{public}d!", mode);
        luminationInfoCallback_ = std::make_shared<LuminationInfoCallbackListener>(env);
        professionSession_->SetLuminationInfoCallback(luminationInfoCallback_);
    }
    luminationInfoCallback_->SaveCallbackReference(callback, isOnce);
}

void ProfessionSessionNapi::UnregisterLuminationInfoCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (luminationInfoCallback_ == nullptr) {
        MEDIA_ERR_LOG("abilityCallback is null");
    } else {
        ExposureHintMode mode = EXPOSURE_HINT_MODE_OFF;
        professionSession_->LockForControl();
        professionSession_->SetExposureHintMode(mode);
        professionSession_->UnlockForControl();
        MEDIA_INFO_LOG("ProfessionSessionNapi SetExposureHintMode set exposureHint %{public}d!", mode);
        luminationInfoCallback_->RemoveCallbackRef(env, callback);
    }
}

void ExposureInfoCallbackListener::OnExposureInfoChangedCallbackAsync(ExposureInfo info) const
{
    MEDIA_DEBUG_LOG("OnExposureInfoChangedCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("failed to allocate work");
        return;
    }
    std::unique_ptr<ExposureInfoChangedCallback> callback = std::make_unique<ExposureInfoChangedCallback>(info, this);
    work->data = callback.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        ExposureInfoChangedCallback* callback = reinterpret_cast<ExposureInfoChangedCallback *>(work->data);
        if (callback) {
            callback->listener_->OnExposureInfoChangedCallback(callback->info_);
            delete callback;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callback.release();
    }
}

void ExposureInfoCallbackListener::OnExposureInfoChangedCallback(ExposureInfo info) const
{
    MEDIA_DEBUG_LOG("OnExposureInfoChangedCallback is called");
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
    napi_value callback = nullptr;
    napi_value retVal;
    for (auto it = baseCbList_.begin(); it != baseCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_get_undefined(env, &result[PARAM0]);
        napi_create_object(env, &result[PARAM1]);
        napi_value value;
        napi_create_uint32(env, info.exposureDurationValue, &value);
        napi_set_named_property(env, result[PARAM1], "exposureTimeValue", value);
        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_call_function(env_, nullptr, callback, ARGS_TWO, result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            baseCbList_.erase(it);
        } else {
            it++;
        }
    }
}

void ExposureInfoCallbackListener::OnExposureInfoChanged(ExposureInfo info)
{
    MEDIA_DEBUG_LOG("OnExposureInfoChanged is called, info: %{public}d", info.exposureDurationValue);
    OnExposureInfoChangedCallbackAsync(info);
}

void IsoInfoCallbackListener::OnIsoInfoChangedCallbackAsync(IsoInfo info) const
{
    MEDIA_DEBUG_LOG("OnIsoInfoChangedCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("failed to allocate work");
        return;
    }
    std::unique_ptr<IsoInfoChangedCallback> callback = std::make_unique<IsoInfoChangedCallback>(info, this);
    work->data = callback.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        IsoInfoChangedCallback* callback = reinterpret_cast<IsoInfoChangedCallback *>(work->data);
        if (callback) {
            callback->listener_->OnIsoInfoChangedCallback(callback->info_);
            delete callback;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callback.release();
    }
}

void IsoInfoCallbackListener::OnIsoInfoChangedCallback(IsoInfo info) const
{
    MEDIA_DEBUG_LOG("OnIsoInfoChangedCallback is called");
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
    napi_value callback = nullptr;
    napi_value retVal;
    for (auto it = baseCbList_.begin(); it != baseCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_get_undefined(env, &result[PARAM0]);
        napi_create_object(env, &result[PARAM1]);
        napi_value value;
        napi_create_int32(env, CameraNapiUtils::FloatToDouble(info.isoValue), &value);
        napi_set_named_property(env, result[PARAM1], "iso", value);
        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_call_function(env_, nullptr, callback, ARGS_TWO, result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            baseCbList_.erase(it);
        } else {
            it++;
        }
    }
}

void IsoInfoCallbackListener::OnIsoInfoChanged(IsoInfo info)
{
    MEDIA_DEBUG_LOG("OnIsoInfoChanged is called, info: %{public}d", info.isoValue);
    OnIsoInfoChangedCallbackAsync(info);
}

void ApertureInfoCallbackListener::OnApertureInfoChangedCallbackAsync(ApertureInfo info) const
{
    MEDIA_DEBUG_LOG("OnApertureInfoChangedCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("failed to allocate work");
        return;
    }
    std::unique_ptr<ApertureInfoChangedCallback> callback = std::make_unique<ApertureInfoChangedCallback>(info, this);
    work->data = callback.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        ApertureInfoChangedCallback* callback = reinterpret_cast<ApertureInfoChangedCallback *>(work->data);
        if (callback) {
            callback->listener_->OnApertureInfoChangedCallback(callback->info_);
            delete callback;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callback.release();
    }
}

void ApertureInfoCallbackListener::OnApertureInfoChangedCallback(ApertureInfo info) const
{
    MEDIA_DEBUG_LOG("OnApertureInfoChangedCallback is called");
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
    napi_value callback = nullptr;
    napi_value retVal;
    for (auto it = baseCbList_.begin(); it != baseCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_get_undefined(env, &result[PARAM0]);
        napi_create_object(env, &result[PARAM1]);
        napi_value value;
        napi_create_double(env, info.apertureValue, &value);
        napi_set_named_property(env, result[PARAM1], "aperture", value);
        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_call_function(env_, nullptr, callback, ARGS_TWO, result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            baseCbList_.erase(it);
        } else {
            it++;
        }
    }
}

void ApertureInfoCallbackListener::OnApertureInfoChanged(ApertureInfo info)
{
    MEDIA_DEBUG_LOG("OnApertureInfoChanged is called, apertureValue: %{public}f", info.apertureValue);
    OnApertureInfoChangedCallbackAsync(info);
}

void LuminationInfoCallbackListener::OnLuminationInfoChangedCallbackAsync(LuminationInfo info) const
{
    MEDIA_DEBUG_LOG("OnLuminationInfoChangedCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("failed to allocate work");
        return;
    }
    std::unique_ptr<LuminationInfoChangedCallback> callback =
        std::make_unique<LuminationInfoChangedCallback>(info, this);
    work->data = callback.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        LuminationInfoChangedCallback* callback = reinterpret_cast<LuminationInfoChangedCallback *>(work->data);
        if (callback) {
            callback->listener_->OnLuminationInfoChangedCallback(callback->info_);
            delete callback;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callback.release();
    }
}

void LuminationInfoCallbackListener::OnLuminationInfoChangedCallback(LuminationInfo info) const
{
    MEDIA_DEBUG_LOG("OnLuminationInfoChangedCallback is called");
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
    napi_value callback = nullptr;
    napi_value retVal;
    for (auto it = baseCbList_.begin(); it != baseCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_get_undefined(env, &result[PARAM0]);
        napi_create_object(env, &result[PARAM1]);
        napi_value isoValue;
        napi_create_double(env, info.luminationValue, &isoValue);
        napi_set_named_property(env, result[PARAM1], "lumination", isoValue);
        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_call_function(env_, nullptr, callback, ARGS_TWO, result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            baseCbList_.erase(it);
        } else {
            it++;
        }
    }
}

void LuminationInfoCallbackListener::OnLuminationInfoChanged(LuminationInfo info)
{
    MEDIA_DEBUG_LOG("OnLuminationInfoChanged is called, luminationValue: %{public}f", info.luminationValue);
    OnLuminationInfoChangedCallbackAsync(info);
}

napi_value ProfessionSessionNapi::On(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<CameraSessionNapi>::On(env, info);
}

napi_value ProfessionSessionNapi::Once(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<CameraSessionNapi>::Once(env, info);
}

napi_value ProfessionSessionNapi::Off(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<CameraSessionNapi>::Off(env, info);
}
} // namespace CameraStandard
} // namespace OHOS