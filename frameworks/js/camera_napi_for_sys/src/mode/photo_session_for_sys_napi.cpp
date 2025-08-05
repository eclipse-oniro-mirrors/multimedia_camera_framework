/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "mode/photo_session_for_sys_napi.h"

#include "ability/camera_ability_napi.h"
#include "input/camera_manager_for_sys.h"
#include "napi/native_node_api.h"
#include "session/photo_session.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

thread_local napi_ref PhotoSessionForSysNapi::sConstructor_ = nullptr;

PhotoSessionForSysNapi::PhotoSessionForSysNapi() : env_(nullptr)
{
}
PhotoSessionForSysNapi::~PhotoSessionForSysNapi()
{
    MEDIA_DEBUG_LOG("~PhotoSessionForSysNapi is called");
}
void PhotoSessionForSysNapi::PhotoSessionForSysNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("PhotoSessionForSysNapiDestructor is called");
    PhotoSessionForSysNapi* cameraObj = reinterpret_cast<PhotoSessionForSysNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}
void PhotoSessionForSysNapi::Init(napi_env env)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;

    std::vector<std::vector<napi_property_descriptor>> descriptors = { camera_process_props,
        CameraSessionForSysNapi::camera_process_sys_props, CameraSessionForSysNapi::camera_output_capability_sys_props,
        CameraSessionForSysNapi::camera_ability_sys_props, preconfig_props, flash_props,
        CameraSessionForSysNapi::flash_sys_props, auto_exposure_props, focus_props,
        CameraSessionForSysNapi::focus_sys_props, zoom_props, CameraSessionForSysNapi::zoom_sys_props,
        color_management_props, macro_props, beauty_sys_props, color_effect_sys_props, scene_detection_sys_props,
        effect_suggestion_sys_props, depth_fusion_sys_props, moon_capture_boost_props, filter_props };
    std::vector<napi_property_descriptor> photo_session_props = CameraNapiUtils::GetPropertyDescriptor(descriptors);
    status = napi_define_class(env, PHOTO_SESSION_FOR_SYS_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               PhotoSessionForSysNapiConstructor, nullptr,
                               photo_session_props.size(),
                               photo_session_props.data(), &ctorObj);
    CHECK_RETURN_ELOG(status != napi_ok, "PhotoSessionForSysNapi defined class failed");
    status = NapiRefManager::CreateMemSafetyRef(env, ctorObj, &sConstructor_);
    CHECK_RETURN_ELOG(status != napi_ok, "PhotoSessionForSysNapi Init failed");
    MEDIA_DEBUG_LOG("PhotoSessionForSysNapi Init success");
}

napi_value PhotoSessionForSysNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    if (sConstructor_ == nullptr) {
        PhotoSessionForSysNapi::Init(env);
        CHECK_RETURN_RET_ELOG(sConstructor_ == nullptr, result, "sConstructor_ is null");
    }
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSessionForSys_ =
            CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::CAPTURE);
        if (sCameraSessionForSys_ == nullptr) {
            MEDIA_ERR_LOG("PhotoSessionForSysNapi::CreateCameraSession Failed to create instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSessionForSys_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("PhotoSessionForSysNapi::CreateCameraSession success to create napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("PhotoSessionForSysNapi::CreateCameraSession Failed to create napi instance");
        }
    }
    MEDIA_ERR_LOG("PhotoSessionForSysNapi::CreateCameraSession Failed to create napi instance last");
    napi_get_undefined(env, &result);
    return result;
}

napi_value PhotoSessionForSysNapi::PhotoSessionForSysNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PhotoSessionForSysNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<PhotoSessionForSysNapi> photoSessionSysObj = std::make_unique<PhotoSessionForSysNapi>();
        photoSessionSysObj->env_ = env;
        CHECK_RETURN_RET_ELOG(sCameraSessionForSys_ == nullptr, result, "sCameraSessionForSys_ is null");
        photoSessionSysObj->photoSessionForSys_ = static_cast<PhotoSessionForSys*>(sCameraSessionForSys_.GetRefPtr());
        photoSessionSysObj->cameraSessionForSys_ = photoSessionSysObj->photoSessionForSys_;
        photoSessionSysObj->cameraSession_ = photoSessionSysObj->photoSessionForSys_;
        CHECK_RETURN_RET_ELOG(photoSessionSysObj->photoSessionForSys_ == nullptr, result,
            "photoSessionForSys_ is null");
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(photoSessionSysObj.get()),
            PhotoSessionForSysNapi::PhotoSessionForSysNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            photoSessionSysObj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("PhotoSessionForSysNapi Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("PhotoSessionForSysNapi call Failed!");
    return result;
}

void PhotoSessionForSysNapi::RegisterPressureStatusCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    MEDIA_INFO_LOG("PhotoSessionForSysNapi::RegisterPressureStatusCallbackListener");
    if (pressureCallback_ == nullptr) {
        pressureCallback_ = std::make_shared<PressureCallbackListener>(env);
        photoSessionForSys_->SetPressureCallback(pressureCallback_);
    }
    pressureCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void PhotoSessionForSysNapi::UnregisterPressureStatusCallbackListener(
    const std::string &eventName, napi_env env, napi_value callback, const std::vector<napi_value> &args)
{
    MEDIA_INFO_LOG("PhotoSessionForSysNapi::UnregisterPressureStatusCallbackListener");
    if (pressureCallback_ == nullptr) {
        MEDIA_INFO_LOG("pressureCallback is null");
        return;
    }
    pressureCallback_->RemoveCallbackRef(eventName, callback);
}
} // namespace CameraStandard
} // namespace OHOS
