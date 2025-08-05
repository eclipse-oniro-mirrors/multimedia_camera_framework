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

#include "mode/panorama_session_napi.h"

#include "input/camera_manager_for_sys.h"

namespace OHOS {
namespace CameraStandard {

thread_local napi_ref PanoramaSessionNapi::sConstructor_ = nullptr;

PanoramaSessionNapi::PanoramaSessionNapi() : env_(nullptr), wrapper_(nullptr)
{
}

PanoramaSessionNapi::~PanoramaSessionNapi()
{
    MEDIA_DEBUG_LOG("~PanoramaSessionNapi is called");
    CHECK_EXECUTE(wrapper_ != nullptr, napi_delete_reference(env_, wrapper_));
    if (panoramaSession_) {
        panoramaSession_ = nullptr;
    }
}

void PanoramaSessionNapi::PanoramaSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("PanoramaSessionNapiDestructor is called");
    PanoramaSessionNapi* cameraObj = reinterpret_cast<PanoramaSessionNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}

void PanoramaSessionNapi::Init(napi_env env)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;

    std::vector<std::vector<napi_property_descriptor>> descriptors = { camera_process_props,
        CameraSessionForSysNapi::camera_process_sys_props, focus_props, CameraSessionForSysNapi::focus_sys_props,
        auto_exposure_props, color_effect_sys_props, white_balance_props };

    std::vector<napi_property_descriptor> panorama_session_props =
        CameraNapiUtils::GetPropertyDescriptor(descriptors);

    status =
        napi_define_class(env, PANORAMA_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH, PanoramaSessionNapiConstructor,
            nullptr, panorama_session_props.size(), panorama_session_props.data(), &ctorObj);
    CHECK_RETURN_ELOG(status != napi_ok, "PanoramaSessionNapi defined class failed");
    status = NapiRefManager::CreateMemSafetyRef(env, ctorObj, &sConstructor_);
    CHECK_RETURN_ELOG(status != napi_ok, "PanoramaSessionNapi Init failed");
    MEDIA_DEBUG_LOG("PanoramaSessionNapi Init success");
}

napi_value PanoramaSessionNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    if (sConstructor_ == nullptr) {
        PanoramaSessionNapi::Init(env);
        CHECK_RETURN_RET_ELOG(sConstructor_ == nullptr, result, "sConstructor_ is null");
    }
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSessionForSys_ =
            CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::PANORAMA_PHOTO);
        if (sCameraSessionForSys_ == nullptr) {
            MEDIA_ERR_LOG("PanoramaSessionNapi::CreateCameraSession Failed to create instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSessionForSys_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("PanoramaSessionNapi::CreateCameraSession success to create napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("PanoramaSessionNapi::CreateCameraSession Failed to create napi instance");
        }
    }
    MEDIA_ERR_LOG("PanoramaSessionNapi::CreateCameraSession Failed to create napi instance last");
    napi_get_undefined(env, &result);
    return result;
}

napi_value PanoramaSessionNapi::PanoramaSessionNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PanoramaSessionNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<PanoramaSessionNapi> obj = std::make_unique<PanoramaSessionNapi>();
        obj->env_ = env;
        CHECK_RETURN_RET_ELOG(sCameraSessionForSys_ == nullptr, result, "sCameraSessionForSys_ is null");
        obj->panoramaSession_ = static_cast<PanoramaSession*>(sCameraSessionForSys_.GetRefPtr());
        obj->cameraSessionForSys_ = obj->panoramaSession_;
        obj->cameraSession_ = obj->panoramaSession_;
        CHECK_RETURN_RET_ELOG(obj->panoramaSession_ == nullptr, result, "panoramaSession_ is null");
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            PanoramaSessionNapi::PanoramaSessionNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("PanoramaSessionNapi Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("PanoramaSessionNapi call Failed!");
    return result;
}

} // CameraStandard
} // OHOS
