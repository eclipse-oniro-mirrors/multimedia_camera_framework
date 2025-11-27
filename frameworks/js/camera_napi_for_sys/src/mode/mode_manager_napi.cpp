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

#include "mode/mode_manager_napi.h"

#include "camera_napi_object_types.h"
#include "input/camera_manager_napi.h"
#include "input/camera_napi.h"
#include "napi/native_common.h"
#include "mode/night_session_napi.h"
#include "mode/panorama_session_napi.h"
#include "mode/photo_session_for_sys_napi.h"
#include "mode/portrait_session_napi.h"
#include "mode/secure_session_for_sys_napi.h"
#include "mode/video_session_for_sys_napi.h"
#include "napi_ref_manager.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
thread_local napi_ref ModeManagerNapi::sConstructor_ = nullptr;
thread_local uint32_t ModeManagerNapi::modeManagerTaskId = MODE_MANAGER_TASKID;

namespace {
sptr<CameraDevice> GetCameraDeviceFromNapiCameraInfoObj(napi_env env, napi_value napiCameraInfoObj)
{
    napi_value napiCameraId = nullptr;
    CHECK_RETURN_RET(napi_get_named_property(env, napiCameraInfoObj, "cameraId", &napiCameraId) != napi_ok,
        nullptr);
    std::string cameraId = CameraNapiUtils::GetStringArgument(env, napiCameraId);
    return CameraManager::GetInstance()->GetCameraDeviceFromId(cameraId);
}
}

ModeManagerNapi::ModeManagerNapi() : env_(nullptr)
{
    MEDIA_DEBUG_LOG("ModeManagerNapi::ModeManagerNapi is called");
}

ModeManagerNapi::~ModeManagerNapi()
{
    MEDIA_DEBUG_LOG("~ModeManagerNapi is called");
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
        CHECK_RETURN_RET_ELOG(obj->modeManager_ == nullptr, result,
            "Failure wrapping js to native napi, obj->modeManager_ null");
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

void ModeManagerNapi::Init(napi_env env)
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
    CHECK_RETURN_ELOG(status != napi_ok, "ModeManagerNapi defined class failed");
    status = NapiRefManager::CreateMemSafetyRef(env, ctorObj, &sConstructor_);
    CHECK_RETURN_ELOG(status != napi_ok, "ModeManagerNapi Init failed");
    MEDIA_DEBUG_LOG("ModeManagerNapi Init success");
}

napi_value ModeManagerNapi::CreateModeManager(napi_env env)
{
    MEDIA_INFO_LOG("CreateModeManager is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value ctor;

    if (sConstructor_ == nullptr) {
        ModeManagerNapi::Init(env);
        CHECK_RETURN_RET_ELOG(sConstructor_ == nullptr, result, "sConstructor_ is null");
    }
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
    CHECK_RETURN_RET_ELOG(status != napi_ok || modeManagerNapi == nullptr, nullptr, "napi_unwrap failure!");

    int32_t jsModeName;
    napi_get_value_int32(env, argv[PARAM0], &jsModeName);
    MEDIA_INFO_LOG("ModeManagerNapi::CreateCameraSessionInstance mode = %{public}d", jsModeName);
    switch (jsModeName) {
        case JsSceneMode::JS_CAPTURE:
            result = PhotoSessionForSysNapi::CreateCameraSession(env);
            break;
        case JsSceneMode::JS_VIDEO:
            result = VideoSessionForSysNapi::CreateCameraSession(env);
            break;
        case JsSceneMode::JS_PORTRAIT:
            result = PortraitSessionNapi::CreateCameraSession(env);
            break;
        case JsSceneMode::JS_NIGHT:
            result = NightSessionNapi::CreateCameraSession(env);
            break;
        case JS_SECURE_CAMERA:
            result = SecureSessionForSysNapi::CreateCameraSession(env);
            break;
        case JsSceneMode::JS_PANORAMA_PHOTO:
            result = PanoramaSessionNapi::CreateCameraSession(env);
            break;
        default:
            MEDIA_ERR_LOG("ModeManagerNapi::CreateCameraSessionInstance mode = %{public}d not supported", jsModeName);
            break;
    }
    return result;
}

static napi_value CreateSceneModeJSArray(napi_env env, napi_status status,
    std::vector<SceneMode> nativeArray)
{
    MEDIA_DEBUG_LOG("CreateSceneModeJSArray is called");
    napi_value jsArray = nullptr;
    napi_value item = nullptr;

    CHECK_PRINT_ELOG(nativeArray.empty(), "nativeArray is empty");

    status = napi_create_array(env, &jsArray);
    if (status == napi_ok) {
        for (size_t i = 0; i < nativeArray.size(); i++) {
            napi_create_int32(env, nativeArray[i], &item);
            CHECK_RETURN_RET_ELOG(napi_set_element(env, jsArray, i, item) != napi_ok, nullptr,
                "CreateSceneModeJSArray Failed to create profile napi wrapper object");
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
    ModeManagerNapi* modeManagerNapi = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    sptr<CameraDevice> cameraInfo = GetCameraDeviceFromNapiCameraInfoObj(env, argv[PARAM0]);
    CHECK_RETURN_RET_ELOG(cameraInfo == nullptr, result, "Could not able to read cameraId argument!");

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&modeManagerNapi));
    if (status == napi_ok && modeManagerNapi != nullptr) {
        std::vector<SceneMode> modeObjList = modeManagerNapi->modeManager_->GetSupportedModes(cameraInfo);
        MEDIA_INFO_LOG("ModeManagerNapi::GetSupportedModes size=[%{public}zu]", modeObjList.size());
        jsResult = CreateSceneModeJSArray(env, status, modeObjList);
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
    ModeManagerNapi* modeManagerNapi = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&modeManagerNapi));
    CHECK_RETURN_RET_ELOG(status != napi_ok || modeManagerNapi == nullptr, result, "napi_unwrap() failure!");

    sptr<CameraDevice> cameraInfo = GetCameraDeviceFromNapiCameraInfoObj(env, argv[PARAM0]);
    CHECK_RETURN_RET_ELOG(cameraInfo == nullptr, result, "Could not able to read cameraId argument!");

    int32_t sceneMode;
    napi_get_value_int32(env, argv[PARAM1], &sceneMode);
    MEDIA_INFO_LOG("ModeManagerNapi::GetSupportedOutputCapability mode = %{public}d", sceneMode);

    sptr<CameraOutputCapability> outputCapability = nullptr;
    auto cameraManager = CameraManager::GetInstance();
    switch (sceneMode) {
        case JS_CAPTURE:
            outputCapability = cameraManager->GetSupportedOutputCapability(cameraInfo, SceneMode::CAPTURE);
            break;
        case JS_VIDEO:
            outputCapability = cameraManager->GetSupportedOutputCapability(cameraInfo, SceneMode::VIDEO);
            break;
        case JS_PORTRAIT:
            outputCapability = cameraManager->GetSupportedOutputCapability(cameraInfo, SceneMode::PORTRAIT);
            break;
        case JS_NIGHT:
            outputCapability = cameraManager->GetSupportedOutputCapability(cameraInfo, SceneMode::NIGHT);
            break;
        case JS_SECURE_CAMERA:
            outputCapability = cameraManager->GetSupportedOutputCapability(cameraInfo, SceneMode::SECURE);
            break;
        default:
            MEDIA_ERR_LOG("ModeManagerNapi::CreateCameraSessionInstance mode = %{public}d not supported", sceneMode);
            break;
    }
    if (outputCapability != nullptr) {
        result = CameraNapiObjCameraOutputCapability(*outputCapability).GenerateNapiValue(env);
    }
    return result;
}

extern "C" napi_value createModeManagerInstance(napi_env env)
{
    MEDIA_DEBUG_LOG("createModeManagerInstance is called");
    napi_value result = nullptr;
    result = ModeManagerNapi::CreateModeManager(env);
    CHECK_RETURN_RET_ELOG(result == nullptr, result, "createModeManagerInstance failed");
    return result;
}
} // namespace CameraStandard
} // namespace OHOS
