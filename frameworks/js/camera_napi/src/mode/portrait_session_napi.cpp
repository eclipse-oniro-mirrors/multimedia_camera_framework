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
    std::vector<napi_property_descriptor> portrait_props = {
        DECLARE_NAPI_FUNCTION("getSupportedPortraitEffects", GetSupportedPortraitEffects),
        DECLARE_NAPI_FUNCTION("getPortraitEffect", GetPortraitEffect),
        DECLARE_NAPI_FUNCTION("setPortraitEffect", SetPortraitEffect),

        DECLARE_NAPI_FUNCTION("getSupportedVirtualApertures", GetSupportedVirtualApertures),
        DECLARE_NAPI_FUNCTION("getVirtualAperture", GetVirtualAperture),
        DECLARE_NAPI_FUNCTION("setVirtualAperture", SetVirtualAperture),

        DECLARE_NAPI_FUNCTION("getSupportedPhysicalApertures", GetSupportedPhysicalApertures),
        DECLARE_NAPI_FUNCTION("getPhysicalAperture", GetPhysicalAperture),
        DECLARE_NAPI_FUNCTION("setPhysicalAperture", SetPhysicalAperture)
    };
    std::vector<std::vector<napi_property_descriptor>> descriptors = {camera_process_props,
        flash_props, auto_exposure_props, focus_props, zoom_props, filter_props, beauty_props,
        color_effect_props, macro_props, color_management_props, portrait_props};
    std::vector<napi_property_descriptor> portrait_session_props = CameraNapiUtils::GetPropertyDescriptor(descriptors);
    status = napi_define_class(env, PORTRAIT_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               PortraitSessionNapiConstructor, nullptr,
                               portrait_session_props.size(),
                               portrait_session_props.data(), &ctorObj);
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

napi_value PortraitSessionNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSession_ = CameraManager::GetInstance()->CreateCaptureSession(SceneMode::PORTRAIT);
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("Failed to create Portrait session instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSession_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("success to create Portrait session napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Portrait session napi instance");
        }
    }
    MEDIA_ERR_LOG("Failed to create Portrait session napi instance last");
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

napi_value PortraitSessionNapi::GetSupportedVirtualApertures(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedVirtualApertures is called");
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
        std::vector<float> virtualApertures =
            portraitSessionNapi->portraitSession_->GetSupportedVirtualApertures();
        MEDIA_INFO_LOG("GetSupportedVirtualApertures virtualApertures len = %{public}zu",
            virtualApertures.size());
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

napi_value PortraitSessionNapi::GetVirtualAperture(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetVirtualAperture is called");
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
        float virtualAperture = portraitSessionNapi->portraitSession_->GetVirtualAperture();
        napi_create_double(env, CameraNapiUtils::FloatToDouble(virtualAperture), &result);
    } else {
        MEDIA_ERR_LOG("GetVirtualAperture call Failed!");
    }
    return result;
}

napi_value PortraitSessionNapi::SetVirtualAperture(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetVirtualAperture is called");
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
        double virtualAperture;
        napi_get_value_double(env, argv[PARAM0], &virtualAperture);
        portraitSessionNapi->portraitSession_->LockForControl();
        portraitSessionNapi->portraitSession_->SetVirtualAperture((float)virtualAperture);
        MEDIA_INFO_LOG("SetVirtualAperture set virtualAperture %{public}f!", virtualAperture);
        portraitSessionNapi->portraitSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetVirtualAperture call Failed!");
    }
    return result;
}

napi_value PortraitSessionNapi::ProcessingPhysicalApertures(napi_env env,
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

napi_value PortraitSessionNapi::GetSupportedPhysicalApertures(napi_env env, napi_callback_info info)
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
    PortraitSessionNapi* portraitSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&portraitSessionNapi));
    if (status == napi_ok && portraitSessionNapi != nullptr && portraitSessionNapi->portraitSession_ != nullptr) {
        std::vector<std::vector<float>> physicalApertures =
            portraitSessionNapi->portraitSession_->GetSupportedPhysicalApertures();
        MEDIA_INFO_LOG("GetSupportedPhysicalApertures len = %{public}zu", physicalApertures.size());
        if (!physicalApertures.empty()) {
            result = ProcessingPhysicalApertures(env, physicalApertures);
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedPhysicalApertures call Failed!");
    }
    return result;
}

napi_value PortraitSessionNapi::GetPhysicalAperture(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetPhysicalAperture is called");
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
        float physicalAperture = portraitSessionNapi->portraitSession_->GetPhysicalAperture();
        napi_create_double(env, CameraNapiUtils::FloatToDouble(physicalAperture), &result);
    } else {
        MEDIA_ERR_LOG("GetPhysicalAperture call Failed!");
    }
    return result;
}

napi_value PortraitSessionNapi::SetPhysicalAperture(napi_env env, napi_callback_info info)
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
    PortraitSessionNapi* portraitSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&portraitSessionNapi));
    if (status == napi_ok && portraitSessionNapi != nullptr && portraitSessionNapi->portraitSession_ != nullptr) {
        double physicalAperture;
        napi_get_value_double(env, argv[PARAM0], &physicalAperture);
        portraitSessionNapi->portraitSession_->LockForControl();
        portraitSessionNapi->portraitSession_->SetPhysicalAperture((float)physicalAperture);
        MEDIA_INFO_LOG("SetPhysicalAperture set physicalAperture %{public}f!", ConfusingNumber(physicalAperture));
        portraitSessionNapi->portraitSession_->UnlockForControl();
    } else {
        MEDIA_ERR_LOG("SetPhysicalAperture call Failed!");
    }
    return result;
}
} // namespace CameraStandard
} // namespace OHOS