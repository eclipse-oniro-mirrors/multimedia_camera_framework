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
 
#include "mode/high_res_photo_session_napi.h"
 
namespace OHOS {
namespace CameraStandard {
using namespace std;
 
thread_local napi_ref HighResPhotoSessionNapi::sConstructor_ = nullptr;
 
HighResPhotoSessionNapi::HighResPhotoSessionNapi() : env_(nullptr), wrapper_(nullptr)
{
}
HighResPhotoSessionNapi::~HighResPhotoSessionNapi()
{
    MEDIA_DEBUG_LOG("~HighResPhotoSessionNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (highResPhotoSession_) {
        highResPhotoSession_ = nullptr;
    }
}
void HighResPhotoSessionNapi::HighResPhotoSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("HighResPhotoSessionNapiDestructor is called");
    HighResPhotoSessionNapi* cameraObj = reinterpret_cast<HighResPhotoSessionNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}
napi_value HighResPhotoSessionNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    std::vector<std::vector<napi_property_descriptor>> descriptors = {camera_process_props,
        auto_exposure_props, focus_props, zoom_props};
    std::vector<napi_property_descriptor> high_res_photo_session_props =
        CameraNapiUtils::GetPropertyDescriptor(descriptors);
    status = napi_define_class(env, HIGH_RES_PHOTO_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               HighResPhotoSessionNapiConstructor, nullptr,
                               high_res_photo_session_props.size(),
                               high_res_photo_session_props.data(), &ctorObj);
    if (status == napi_ok) {
        int32_t refCount = 1;
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, HIGH_RES_PHOTO_SESSION_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}
 
napi_value HighResPhotoSessionNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSession_ = CameraManager::GetInstance()->CreateCaptureSession(SceneMode::HIGH_RES_PHOTO);
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("Failed to create High res photo session instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSession_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("success to create High res photo session napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create High res photo session napi instance");
        }
    } else {
        MEDIA_ERR_LOG("Failed to create napi reference value instance");
    }
    MEDIA_ERR_LOG("Failed to create High res photo session napi instance last");
    napi_get_undefined(env, &result);
    return result;
}
 
napi_value HighResPhotoSessionNapi::HighResPhotoSessionNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("HighResPhotoSessionNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;
 
    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
 
    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<HighResPhotoSessionNapi> obj = std::make_unique<HighResPhotoSessionNapi>();
        obj->env_ = env;
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("sCameraSession_ is null");
            return result;
        }
        obj->highResPhotoSession_ = static_cast<HighResPhotoSession*>(sCameraSession_.GetRefPtr());
        obj->cameraSession_ = obj->highResPhotoSession_;
        if (obj->highResPhotoSession_ == nullptr) {
            MEDIA_ERR_LOG("highResPhotoSession_ is null");
            return result;
        }
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            HighResPhotoSessionNapi::HighResPhotoSessionNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("HighResPhotoSessionNapi Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("HighResPhotoSessionNapi call Failed!");
    return result;
}
} // namespace CameraStandard
} // namespace OHOS