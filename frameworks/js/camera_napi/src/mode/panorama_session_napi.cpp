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

napi_value PanoramaSessionNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;

    std::vector<std::vector<napi_property_descriptor>> descriptors = { camera_process_props, focus_props,
        auto_exposure_props, color_effect_props, auto_wb_props, manual_wb_props };

    std::vector<napi_property_descriptor> panorama_session_props =
        CameraNapiUtils::GetPropertyDescriptor(descriptors);

    status =
        napi_define_class(env, PANORAMA_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH, PanoramaSessionNapiConstructor,
            nullptr, panorama_session_props.size(), panorama_session_props.data(), &ctorObj);
    if (status == napi_ok) {
        int32_t refCount = 1;
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, PANORAMA_SESSION_NAPI_CLASS_NAME, ctorObj);
            CHECK_ERROR_RETURN_RET(status == napi_ok, exports);
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value PanoramaSessionNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSession_ = CameraManager::GetInstance()->CreateCaptureSession(SceneMode::PANORAMA_PHOTO);
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("Failed to create Photo session instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSession_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("success to create Photo session napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Photo session napi instance");
        }
    }
    MEDIA_ERR_LOG("Failed to create Photo session napi instance last");
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
        CHECK_ERROR_RETURN_RET_LOG(sCameraSession_ == nullptr, result, "sCameraSession_ is null");
        obj->panoramaSession_ = static_cast<PanoramaSession*>(sCameraSession_.GetRefPtr());
        obj->cameraSession_ = obj->panoramaSession_;
        CHECK_ERROR_RETURN_RET_LOG(obj->panoramaSession_ == nullptr, result, "panoramaSession_ is null");
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