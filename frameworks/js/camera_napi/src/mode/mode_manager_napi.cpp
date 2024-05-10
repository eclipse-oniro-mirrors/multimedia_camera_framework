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

#include "input/camera_napi.h"
#include "input/camera_manager_napi.h"
#include "mode/mode_manager_napi.h"
namespace OHOS {
namespace CameraStandard {
using namespace std;
thread_local napi_ref ModeManagerNapi::sConstructor_ = nullptr;
thread_local uint32_t ModeManagerNapi::modeManagerTaskId = MODE_MANAGER_TASKID;

ModeManagerNapi::ModeManagerNapi() : env_(nullptr), wrapper_(nullptr)
{
    CAMERA_SYNC_TRACE;
}

ModeManagerNapi::~ModeManagerNapi()
{
    MEDIA_DEBUG_LOG("~ModeManagerNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (modeManager_) {
        modeManager_ = nullptr;
    }
}

// Constructor callback
napi_value ModeManagerNapi::ModeManagerNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("ModeManagerNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<ModeManagerNapi> obj = std::make_unique<ModeManagerNapi>();
        obj->env_ = env;
        obj->modeManager_ = CameraManager::GetInstance();
        if (obj->modeManager_ == nullptr) {
            MEDIA_ERR_LOG("Failure wrapping js to native napi, obj->modeManager_ null");
            return result;
        }
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           ModeManagerNapi::ModeManagerNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("ModeManagerNapiConstructor call Failed!");
    return result;
}

void ModeManagerNapi::ModeManagerNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("ModeManagerNapiDestructor is called");
    ModeManagerNapi* camera = reinterpret_cast<ModeManagerNapi*>(nativeObject);
    if (camera != nullptr) {
        delete camera;
    }
}

napi_value ModeManagerNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    napi_property_descriptor mode_mgr_properties[] = {
        DECLARE_NAPI_FUNCTION("getSupportedModes", GetSupportedModes),
        DECLARE_NAPI_FUNCTION("getSupportedOutputCapability", GetSupportedOutputCapability),
        DECLARE_NAPI_FUNCTION("createCaptureSession", CreateCameraSessionInstance),
    };

    status = napi_define_class(env, MODE_MANAGER_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               ModeManagerNapiConstructor, nullptr,
                               sizeof(mode_mgr_properties) / sizeof(mode_mgr_properties[PARAM0]),
                               mode_mgr_properties, &ctorObj);
    if (status == napi_ok) {
        int32_t refCount = 1;
        if (napi_create_reference(env, ctorObj, refCount, &sConstructor_) == napi_ok) {
            status = napi_set_named_property(env, exports, MODE_MANAGER_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value ModeManagerNapi::CreateModeManager(napi_env env)
{
    MEDIA_INFO_LOG("CreateModeManager is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value ctor;

    status = napi_get_reference_value(env, sConstructor_, &ctor);
    if (status == napi_ok) {
        status = napi_new_instance(env, ctor, 0, nullptr, &result);
        if (status == napi_ok) {
            return result;
        } else {
            MEDIA_ERR_LOG("New instance could not be obtained");
        }
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("CreateModeManager call Failed!");
    return result;
}

napi_value ModeManagerNapi::CreateCameraSessionInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreateCameraSessionInstance is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);

    ModeManagerNapi* modeManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&modeManagerNapi));
    if (status != napi_ok || modeManagerNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap failure!");
        return nullptr;
    }

    int32_t jsModeName;
    napi_get_value_int32(env, argv[PARAM0], &jsModeName);
    MEDIA_INFO_LOG("ModeManagerNapi::CreateCameraSessionInstance mode = %{public}d", jsModeName);
    switch (jsModeName) {
        case JsSceneMode::JS_CAPTURE:
            result = PhotoSessionNapi::CreateCameraSession(env);
            break;
        case JsSceneMode::JS_VIDEO:
            result = VideoSessionNapi::CreateCameraSession(env);
            break;
        case JsSceneMode::JS_PORTRAIT:
            result = PortraitSessionNapi::CreateCameraSession(env);
            break;
        case JsSceneMode::JS_NIGHT:
            result = NightSessionNapi::CreateCameraSession(env);
            break;
        case JS_SECURE_CAMERA:
            result = SecureCameraSessionNapi::CreateCameraSession(env);
            break;
        default:
            MEDIA_ERR_LOG("ModeManagerNapi::CreateCameraSessionInstance mode = %{public}d not supported", jsModeName);
            break;
    }
    return result;
}

static napi_value CreateJSArray(napi_env env, napi_status status,
    std::vector<SceneMode> nativeArray)
{
    MEDIA_DEBUG_LOG("CreateJSArray is called");
    napi_value jsArray = nullptr;
    napi_value item = nullptr;

    if (nativeArray.empty()) {
        MEDIA_ERR_LOG("nativeArray is empty");
    }

    status = napi_create_array(env, &jsArray);
    if (status == napi_ok) {
        for (size_t i = 0; i < nativeArray.size(); i++) {
            napi_create_int32(env, nativeArray[i], &item);
            if (napi_set_element(env, jsArray, i, item) != napi_ok) {
                MEDIA_ERR_LOG("Failed to create profile napi wrapper object");
                return nullptr;
            }
        }
    }
    return jsArray;
}

napi_value ModeManagerNapi::GetSupportedModes(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetSupportedModes is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;
    napi_value jsResult = nullptr;
    CameraDeviceNapi* cameraDeviceNapi = nullptr;
    ModeManagerNapi* modeManagerNapi = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    status = napi_unwrap(env, argv[PARAM0], reinterpret_cast<void**>(&cameraDeviceNapi));
    if (status != napi_ok || cameraDeviceNapi == nullptr) {
        MEDIA_ERR_LOG("Could not able to read cameraId argument!");
        return result;
    }
    sptr<CameraDevice> cameraInfo = cameraDeviceNapi->cameraDevice_;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&modeManagerNapi));
    if (status == napi_ok && modeManagerNapi != nullptr) {
        std::vector<SceneMode> modeObjList = modeManagerNapi->modeManager_->GetSupportedModes(cameraInfo);
        MEDIA_INFO_LOG("ModeManagerNapi::GetSupportedModes size=[%{public}zu]", modeObjList.size());
        jsResult = CreateJSArray(env, status, modeObjList);
        if (status == napi_ok) {
            return jsResult;
        } else {
            MEDIA_ERR_LOG("Failed to get modeObjList!, errorCode : %{public}d", status);
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedModes call Failed!");
    }
    return result;
}

napi_value ModeManagerNapi::GetSupportedOutputCapability(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetSupportedOutputCapability is called");
    napi_status status;

    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    CameraDeviceNapi* cameraDeviceNapi = nullptr;
    ModeManagerNapi* modeManagerNapi = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&modeManagerNapi));
    if (status != napi_ok || modeManagerNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap() failure!");
        return result;
    }
    status = napi_unwrap(env, argv[PARAM0], reinterpret_cast<void**>(&cameraDeviceNapi));
    if (status != napi_ok || cameraDeviceNapi == nullptr) {
        MEDIA_ERR_LOG("Could not able to read cameraId argument!");
        return result;
    }
    sptr<CameraDevice> cameraInfo = cameraDeviceNapi->cameraDevice_;
    int32_t sceneMode;
    napi_get_value_int32(env, argv[PARAM1], &sceneMode);
    MEDIA_INFO_LOG("ModeManagerNapi::GetSupportedOutputCapability mode = %{public}d", sceneMode);
    switch (sceneMode) {
        case JS_CAPTURE:
            result = CameraOutputCapabilityNapi::CreateCameraOutputCapability(env, cameraInfo, SceneMode::CAPTURE);
            break;
        case JS_VIDEO:
            result = CameraOutputCapabilityNapi::CreateCameraOutputCapability(env, cameraInfo, SceneMode::VIDEO);
            break;
        case JS_PORTRAIT:
            result = CameraOutputCapabilityNapi::CreateCameraOutputCapability(env, cameraInfo, SceneMode::PORTRAIT);
            break;
        case JS_NIGHT:
            result = CameraOutputCapabilityNapi::CreateCameraOutputCapability(env, cameraInfo, SceneMode::NIGHT);
            break;
        case JS_SECURE_CAMERA:
            result = CameraOutputCapabilityNapi::CreateCameraOutputCapability(env, cameraInfo, SceneMode::SECURE);
            break;
        default:
            MEDIA_ERR_LOG("ModeManagerNapi::CreateCameraSessionInstance mode = %{public}d not supported", sceneMode);
            break;
    }
    return result;
}
} // namespace CameraStandard
} // namespace OHOS
