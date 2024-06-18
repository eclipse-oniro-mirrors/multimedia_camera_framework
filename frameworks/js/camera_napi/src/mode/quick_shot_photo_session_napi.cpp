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

#include "mode/quick_shot_photo_session_napi.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

thread_local napi_ref QuickShotPhotoSessionNapi::sConstructor_ = nullptr;

QuickShotPhotoSessionNapi::QuickShotPhotoSessionNapi() : env_(nullptr), wrapper_(nullptr) {}

QuickShotPhotoSessionNapi::~QuickShotPhotoSessionNapi()
{
    MEDIA_DEBUG_LOG("~QuickShotPhotoSessionNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

void QuickShotPhotoSessionNapi::QuickShotPhotoSessionNapiDestructor(
    napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("QuickShotPhotoSessionNapiDestructor is called");
    QuickShotPhotoSessionNapi* cameraObj = reinterpret_cast<QuickShotPhotoSessionNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}

napi_value QuickShotPhotoSessionNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    std::vector<std::vector<napi_property_descriptor>> descriptors = { camera_process_props, auto_exposure_props,
        color_effect_props, color_management_props, effect_suggestion_props, flash_props, focus_props, zoom_props };

    std::vector<napi_property_descriptor> quick_shot_photo_session_props =
        CameraNapiUtils::GetPropertyDescriptor(descriptors);

    status = napi_define_class(env, QUICK_SHOT_PHOTO_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
        QuickShotPhotoSessionNapiConstructor, nullptr, quick_shot_photo_session_props.size(),
        quick_shot_photo_session_props.data(), &ctorObj);
    if (status == napi_ok) {
        int32_t refCount = 1;
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, QUICK_SHOT_PHOTO_SESSION_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value QuickShotPhotoSessionNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSession_ = CameraManager::GetInstance()->CreateCaptureSession(SceneMode::QUICK_SHOT_PHOTO);
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

napi_value QuickShotPhotoSessionNapi::QuickShotPhotoSessionNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("QuickShotPhotoSessionNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<QuickShotPhotoSessionNapi> obj = std::make_unique<QuickShotPhotoSessionNapi>();
        obj->env_ = env;
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("sCameraSession_ is null");
            return result;
        }
        obj->quickShotPhotoSession_ = static_cast<QuickShotPhotoSession*>(sCameraSession_.GetRefPtr());
        obj->cameraSession_ = obj->quickShotPhotoSession_;
        if (obj->quickShotPhotoSession_ == nullptr) {
            MEDIA_ERR_LOG("quickShotPhotoSession_ is null");
            return result;
        }
        status = napi_wrap(
            env, thisVar, reinterpret_cast<void*>(obj.get()), QuickShotPhotoSessionNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("QuickShotPhotoSessionNapiConstructor Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("QuickShotPhotoSessionNapiConstructor call Failed!");
    return result;
}
} // namespace CameraStandard
} // namespace OHOS
