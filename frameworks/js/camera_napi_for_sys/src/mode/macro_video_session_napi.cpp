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

#include "mode/macro_video_session_napi.h"

#include "input/camera_manager_for_sys.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

thread_local napi_ref MacroVideoSessionNapi::sConstructor_ = nullptr;

MacroVideoSessionNapi::MacroVideoSessionNapi() : env_(nullptr) {}

MacroVideoSessionNapi::~MacroVideoSessionNapi()
{
    MEDIA_DEBUG_LOG("~MacroVideoSessionNapi is called");
}

void MacroVideoSessionNapi::MacroVideoSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("MacroVideoSessionNapiDestructor is called");
    MacroVideoSessionNapi* cameraObj = reinterpret_cast<MacroVideoSessionNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}

void MacroVideoSessionNapi::Init(napi_env env)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;

    std::vector<std::vector<napi_property_descriptor>> descriptors = { camera_process_props,
        CameraSessionForSysNapi::camera_process_sys_props, flash_props, CameraSessionForSysNapi::flash_sys_props,
        auto_exposure_props, focus_props, CameraSessionForSysNapi::focus_sys_props, zoom_props,
        CameraSessionForSysNapi::zoom_sys_props, color_effect_sys_props, scene_detection_sys_props, stabilization_props,
        manual_focus_sys_props, color_management_props };

    std::vector<napi_property_descriptor> macro_video_session_props =
        CameraNapiUtils::GetPropertyDescriptor(descriptors);

    status =
        napi_define_class(env, MACRO_VIDEO_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH, MacroVideoSessionNapiConstructor,
            nullptr, macro_video_session_props.size(), macro_video_session_props.data(), &ctorObj);
    CHECK_RETURN_ELOG(status != napi_ok, "MacroVideoSessionNapi defined class failed");
    status = NapiRefManager::CreateMemSafetyRef(env, ctorObj, &sConstructor_);
    CHECK_RETURN_ELOG(status != napi_ok, "MacroVideoSessionNapi Init failed");
    MEDIA_DEBUG_LOG("MacroVideoSessionNapi Init success");
}

napi_value MacroVideoSessionNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    if (sConstructor_ == nullptr) {
        MacroVideoSessionNapi::Init(env);
        CHECK_RETURN_RET_ELOG(sConstructor_ == nullptr, result, "sConstructor_ is null");
    }
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSessionForSys_ =
            CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::VIDEO_MACRO);
        if (sCameraSessionForSys_ == nullptr) {
            MEDIA_ERR_LOG("MacroVideoSessionNapi::CreateCameraSession Failed to create instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSessionForSys_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("MacroVideoSessionNapi::CreateCameraSession success to create napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("MacroVideoSessionNapi::CreateCameraSession Failed to create napi instance");
        }
    }
    MEDIA_ERR_LOG("MacroVideoSessionNapi::CreateCameraSession Failed to create napi instance last");
    napi_get_undefined(env, &result);
    return result;
}

napi_value MacroVideoSessionNapi::MacroVideoSessionNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("MacroVideoSessionNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<MacroVideoSessionNapi> obj = std::make_unique<MacroVideoSessionNapi>();
        obj->env_ = env;
        CHECK_RETURN_RET_ELOG(sCameraSessionForSys_ == nullptr, result, "sCameraSessionForSys_ is null");
        obj->macroVideoSession_ = static_cast<MacroVideoSession*>(sCameraSessionForSys_.GetRefPtr());
        obj->cameraSessionForSys_ = obj->macroVideoSession_;
        obj->cameraSession_ = obj->macroVideoSession_;
        CHECK_RETURN_RET_ELOG(obj->macroVideoSession_ == nullptr, result, "macroVideoSession_ is null");
        status = napi_wrap(
            env, thisVar, reinterpret_cast<void*>(obj.get()), MacroVideoSessionNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("MacroVideoSessionNapiConstructor Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("MacroVideoSessionNapiConstructor call Failed!");
    return result;
}
} // namespace CameraStandard
} // namespace OHOS
