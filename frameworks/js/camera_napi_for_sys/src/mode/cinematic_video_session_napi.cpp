/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "input/camera_manager_for_sys.h"
#include "mode/cinematic_video_session_napi.h"

namespace OHOS {
namespace CameraStandard {

thread_local napi_ref CinematicVideoSessionNapi::constructor_ = nullptr;

CinematicVideoSessionNapi::CinematicVideoSessionNapi()
    : env_(nullptr), wrapper_(nullptr)
{
    MEDIA_DEBUG_LOG("CinematicVideoSessionNapi::CinematicVideoSessionNapi() is called");
}

CinematicVideoSessionNapi::~CinematicVideoSessionNapi()
{
    MEDIA_DEBUG_LOG("CinematicVideoSessionNapi::~CinematicVideoSessionNapi() is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

void CinematicVideoSessionNapi::Init(napi_env env)
{
    MEDIA_DEBUG_LOG("CinematicVideoSessionNapi::Init is called");
    napi_status status;
    napi_value constructor;
    std::vector<std::vector<napi_property_descriptor>> descriptors = {camera_process_props,
        CameraSessionForSysNapi::camera_process_sys_props, flash_props, CameraSessionForSysNapi::flash_sys_props,
        auto_exposure_props, focus_props, CameraSessionForSysNapi::focus_sys_props, zoom_props,
        CameraSessionForSysNapi::zoom_sys_props, filter_props, beauty_sys_props, color_effect_sys_props, macro_props,
        color_management_props, stabilization_props, preconfig_props,
        CameraSessionForSysNapi::camera_output_capability_sys_props, CameraSessionForSysNapi::camera_ability_sys_props,
        aperture_sys_props, color_reservation_sys_props, effect_suggestion_sys_props, focus_tracking_props};

    std::vector<napi_property_descriptor> cinematic_video_session_props =
        CameraNapiUtils::GetPropertyDescriptor(descriptors);

    status = napi_define_class(env, CINEMATIC_VIDEO_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
        CinematicVideoSessionNapiConstructor, nullptr, cinematic_video_session_props.size(),
        cinematic_video_session_props.data(), &constructor);
    CHECK_RETURN_ELOG(status != napi_ok, "CinematicVideoSessionNapi defined class failed");
    // create a strong ref to prevent the constructor be garbage-collected
    status = NapiRefManager::CreateMemSafetyRef(env, constructor, &constructor_);
    CHECK_RETURN_ELOG(status != napi_ok, "CinematicVideoSessionNapi Init failed");
    MEDIA_DEBUG_LOG("CinematicVideoSessionNapi Init success");
}

napi_value CinematicVideoSessionNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("CinematicVideoSessionNapi::CreateCameraSession is called");
    napi_status status;
    napi_value result;
    napi_value constructor;

    napi_get_undefined(env, &result);
    if (constructor_ == nullptr) {
        CinematicVideoSessionNapi::Init(env);
        CHECK_RETURN_RET_ELOG(constructor_ == nullptr, result, "constructor_ is null");
    }
    status = napi_get_reference_value(env, constructor_, &constructor);
    if (status == napi_ok) {
        sCameraSessionForSys_ =
            CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::CINEMATIC_VIDEO);
        if (sCameraSessionForSys_ == nullptr) {
            MEDIA_ERR_LOG("Failed to create Cinematic Session instance, reason: sCameraSessionForSys_ is null");
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSessionForSys_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("success to create Cinematic Session napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Cinematic Session napi instance, reason: napi_new_instance failed");
        }
    }
    MEDIA_ERR_LOG("Failed to create Cinematic Session napi instance, reason: constructor_ is null");
    return result;
}

napi_value CinematicVideoSessionNapi::CinematicVideoSessionNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CinematicVideoSessionNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CinematicVideoSessionNapi> obj = std::make_unique<CinematicVideoSessionNapi>();
        obj->env_ = env;
        if (sCameraSessionForSys_ == nullptr) {
            MEDIA_ERR_LOG("sCameraSessionForSys_ is null");
            return result;
        }
        obj->cinematicVideoSession_ = static_cast<CinematicVideoSession*>(sCameraSessionForSys_.GetRefPtr());
        obj->cameraSessionForSys_ = obj->cinematicVideoSession_;
        obj->cameraSession_ = obj->cinematicVideoSession_;
        CHECK_RETURN_RET_ELOG(obj->cinematicVideoSession_ == nullptr, result, "CinematicVideoSession_ is null");
        status = napi_wrap(
            env, thisVar, reinterpret_cast<void*>(obj.get()), CinematicVideoSessionNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            (void)obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("CinematicVideoSessionNapiConstructor failed wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("CinematicVideoSessionNapiConstructor call Failed!");
    return result;
}

void CinematicVideoSessionNapi::CinematicVideoSessionNapiDestructor(
    napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CinematicVideoSessionNapiDestructor is called");
    CinematicVideoSessionNapi* cameraObj = reinterpret_cast<CinematicVideoSessionNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}

} // namespace CameraStandard
} // namespace OHOS