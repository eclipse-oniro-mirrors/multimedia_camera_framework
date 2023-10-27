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

#include "mode/portrait_session_napi.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

thread_local napi_ref PortraitSessionNapi::sConstructor_ = nullptr;

PortraitSessionNapi::PortraitSessionNapi() : env_(nullptr), wrapper_(nullptr)
{
}
PortraitSessionNapi::~PortraitSessionNapi()
{
    MEDIA_DEBUG_LOG("~PortraitSessionNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (portraitSession_) {
        portraitSession_ = nullptr;
    }
}
void PortraitSessionNapi::PortraitSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("PortraitSessionNapiDestructor is called");
    PortraitSessionNapi* cameraObj = reinterpret_cast<PortraitSessionNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}
napi_value PortraitSessionNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    napi_property_descriptor portrait_session_props[] = {
        DECLARE_NAPI_FUNCTION("beginConfig", CameraSessionNapi::BeginConfig),
        DECLARE_NAPI_FUNCTION("commitConfig", CameraSessionNapi::CommitConfig),

        DECLARE_NAPI_FUNCTION("canAddInput", CameraSessionNapi::CanAddInput),
        DECLARE_NAPI_FUNCTION("addInput", CameraSessionNapi::AddInput),
        DECLARE_NAPI_FUNCTION("removeInput", CameraSessionNapi::RemoveInput),

        DECLARE_NAPI_FUNCTION("canAddOutput", CameraSessionNapi::CanAddOutput),
        DECLARE_NAPI_FUNCTION("addOutput", CameraSessionNapi::AddOutput),
        DECLARE_NAPI_FUNCTION("removeOutput", CameraSessionNapi::RemoveOutput),

        DECLARE_NAPI_FUNCTION("start", CameraSessionNapi::Start),
        DECLARE_NAPI_FUNCTION("stop", CameraSessionNapi::Stop),
        DECLARE_NAPI_FUNCTION("release", CameraSessionNapi::Release),

        DECLARE_NAPI_FUNCTION("lockForControl", CameraSessionNapi::LockForControl),
        DECLARE_NAPI_FUNCTION("unlockForControl", CameraSessionNapi::UnlockForControl),

        DECLARE_NAPI_FUNCTION("isVideoStabilizationModeSupported",
                              CameraSessionNapi::IsVideoStabilizationModeSupported),
        DECLARE_NAPI_FUNCTION("getActiveVideoStabilizationMode", CameraSessionNapi::GetActiveVideoStabilizationMode),
        DECLARE_NAPI_FUNCTION("setVideoStabilizationMode", CameraSessionNapi::SetVideoStabilizationMode),

        DECLARE_NAPI_FUNCTION("hasFlash", CameraSessionNapi::HasFlash),
        DECLARE_NAPI_FUNCTION("isFlashModeSupported", CameraSessionNapi::IsFlashModeSupported),
        DECLARE_NAPI_FUNCTION("getFlashMode", CameraSessionNapi::GetFlashMode),
        DECLARE_NAPI_FUNCTION("setFlashMode", CameraSessionNapi::SetFlashMode),

        DECLARE_NAPI_FUNCTION("isExposureModeSupported", CameraSessionNapi::IsExposureModeSupported),
        DECLARE_NAPI_FUNCTION("getExposureMode", CameraSessionNapi::GetExposureMode),
        DECLARE_NAPI_FUNCTION("setExposureMode", CameraSessionNapi::SetExposureMode),
        DECLARE_NAPI_FUNCTION("getExposureBiasRange", CameraSessionNapi::GetExposureBiasRange),
        DECLARE_NAPI_FUNCTION("setExposureBias", CameraSessionNapi::SetExposureBias),
        DECLARE_NAPI_FUNCTION("getExposureValue", CameraSessionNapi::GetExposureValue),

        DECLARE_NAPI_FUNCTION("getMeteringPoint", CameraSessionNapi::GetMeteringPoint),
        DECLARE_NAPI_FUNCTION("setMeteringPoint", CameraSessionNapi::SetMeteringPoint),

        DECLARE_NAPI_FUNCTION("isFocusModeSupported", CameraSessionNapi::IsFocusModeSupported),
        DECLARE_NAPI_FUNCTION("getFocusMode", CameraSessionNapi::GetFocusMode),
        DECLARE_NAPI_FUNCTION("setFocusMode", CameraSessionNapi::SetFocusMode),

        DECLARE_NAPI_FUNCTION("getFocusPoint", CameraSessionNapi::GetFocusPoint),
        DECLARE_NAPI_FUNCTION("setFocusPoint", CameraSessionNapi::SetFocusPoint),
        DECLARE_NAPI_FUNCTION("getFocalLength", CameraSessionNapi::GetFocalLength),

        DECLARE_NAPI_FUNCTION("getZoomRatioRange", CameraSessionNapi::GetZoomRatioRange),
        DECLARE_NAPI_FUNCTION("getZoomRatio", CameraSessionNapi::GetZoomRatio),
        DECLARE_NAPI_FUNCTION("setZoomRatio", CameraSessionNapi::SetZoomRatio),

        DECLARE_NAPI_FUNCTION("getSupportedFilters", CameraSessionNapi::GetSupportedFilters),
        DECLARE_NAPI_FUNCTION("getFilter", CameraSessionNapi::GetFilter),
        DECLARE_NAPI_FUNCTION("setFilter", CameraSessionNapi::SetFilter),

        DECLARE_NAPI_FUNCTION("getSupportedBeautyTypes", CameraSessionNapi::GetSupportedBeautyTypes),
        DECLARE_NAPI_FUNCTION("getSupportedBeautyRange", CameraSessionNapi::GetSupportedBeautyRange),
        DECLARE_NAPI_FUNCTION("getBeauty", CameraSessionNapi::GetBeauty),
        DECLARE_NAPI_FUNCTION("setBeauty", CameraSessionNapi::SetBeauty),

        DECLARE_NAPI_FUNCTION("on", CameraSessionNapi::On),

        DECLARE_NAPI_FUNCTION("getSupportedPortraitEffects", GetSupportedPortraitEffects),
        DECLARE_NAPI_FUNCTION("getPortraitEffect", GetPortraitEffect),
        DECLARE_NAPI_FUNCTION("setPortraitEffect", SetPortraitEffect),

        DECLARE_NAPI_FUNCTION("getSupportedColorEffects", CameraSessionNapi::GetSupportedColorEffects),
        DECLARE_NAPI_FUNCTION("getColorEffect", CameraSessionNapi::GetColorEffect),
        DECLARE_NAPI_FUNCTION("setColorEffect", CameraSessionNapi::SetColorEffect)

    };
    status = napi_define_class(env, PORTRAIT_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               PortraitSessionNapiConstructor, nullptr,
                               sizeof(portrait_session_props) / sizeof(portrait_session_props[PARAM0]),
                               portrait_session_props, &ctorObj);
    if (status == napi_ok) {
        int32_t refCount = 1;
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, PORTRAIT_SESSION_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value PortraitSessionNapi::CreateCameraSession(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        int32_t modeName;
        napi_get_value_int32(env, argv[PARAM0], &modeName);
        MEDIA_INFO_LOG("PortraitSessionNapi::CreateCameraSession mode = %{public}d", modeName);
        if (modeName == 1) { // trans js portrait to fwk portrait
            modeName = CameraMode::PORTRAIT;
        } else {
            modeName = CameraMode::NORMAL;
        }
        sCameraSession_ = ModeManager::GetInstance()->CreateCaptureSession(static_cast<CameraMode>(modeName));
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

napi_value PortraitSessionNapi::PortraitSessionNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PortraitSessionNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<PortraitSessionNapi> obj = std::make_unique<PortraitSessionNapi>();
        obj->env_ = env;
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("sCameraSession_ is null");
            return result;
        }
        obj->portraitSession_ = static_cast<PortraitSession*>(sCameraSession_.GetRefPtr());
        obj->cameraSession_ = obj->portraitSession_;
        if (obj->portraitSession_ == nullptr) {
            MEDIA_ERR_LOG("portraitSession_ is null");
            return result;
        }
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            PortraitSessionNapi::PortraitSessionNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("PortraitSessionNapi Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("PortraitSessionNapi call Failed!");
    return result;
}


napi_value PortraitSessionNapi::GetSupportedPortraitEffects(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetPortraitEffect is called");
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
    PortraitSessionNapi* portraitSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&portraitSessionNapi));
    if (status == napi_ok && portraitSessionNapi != nullptr && portraitSessionNapi->portraitSession_ != nullptr) {
        std::vector<PortraitEffect> PortraitEffects =
            portraitSessionNapi->portraitSession_->GetSupportedPortraitEffects();
        MEDIA_INFO_LOG("PortraitSessionNapi::GetSupportedPortraitEffect len = %{public}zu",
            PortraitEffects.size());
        if (!PortraitEffects.empty()) {
            for (size_t i = 0; i < PortraitEffects.size(); i++) {
                PortraitEffect portaitEffect = PortraitEffects[i];
                napi_value value;
                napi_create_int32(env, portaitEffect, &value);
                napi_set_element(env, result, i, value);
            }
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedPortraitEffect call Failed!");
    }
    return result;
}

napi_value PortraitSessionNapi::GetPortraitEffect(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetPortraitEffect is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PortraitSessionNapi* portraitSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&portraitSessionNapi));
    if (status == napi_ok && portraitSessionNapi != nullptr && portraitSessionNapi->portraitSession_ != nullptr) {
        PortraitEffect portaitEffect = portraitSessionNapi->portraitSession_->GetPortraitEffect();
        napi_create_int32(env, portaitEffect, &result);
    } else {
        MEDIA_ERR_LOG("GetPortraitEffect call Failed!");
    }
    return result;
}

napi_value PortraitSessionNapi::SetPortraitEffect(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetPortraitEffect is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PortraitSessionNapi* portraitSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&portraitSessionNapi));
    if (status == napi_ok && portraitSessionNapi != nullptr && portraitSessionNapi->portraitSession_ != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        PortraitEffect portaitEffect = static_cast<PortraitEffect>(value);
        portraitSessionNapi->portraitSession_->LockForControl();
        portraitSessionNapi->portraitSession_->
                SetPortraitEffect(static_cast<PortraitEffect>(portaitEffect));
        MEDIA_INFO_LOG("PortraitSessionNapi setPortraitEffect set portaitEffect %{public}d!", portaitEffect);
        portraitSessionNapi->portraitSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("setPortraitEffect call Failed!");
    }
    return result;
}
} // namespace CameraStandard
} // namespace OHOS