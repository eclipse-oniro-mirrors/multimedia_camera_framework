/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "input/camera_manager_napi.h"

#include <uv.h>

#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_napi_const.h"
#include "camera_napi_event_emitter.h"
#include "camera_napi_param_parser.h"
#include "camera_napi_security_utils.h"
#include "camera_napi_template_utils.h"
#include "camera_napi_utils.h"
#include "input/camera_napi.h"
#include "input/camera_pre_launch_config_napi.h"
#include "js_native_api_types.h"
#include "mode/macro_photo_session_napi.h"
#include "mode/macro_video_session_napi.h"
#include "mode/high_res_photo_session_napi.h"
#include "mode/night_session_napi.h"
#include "mode/photo_session_for_sys_napi.h"
#include "mode/photo_session_napi.h"
#include "mode/portrait_session_napi.h"
#include "mode/profession_session_napi.h"
#include "mode/slow_motion_session_napi.h"
#include "mode/video_session_for_sys_napi.h"
#include "mode/video_session_napi.h"
#include "mode/secure_camera_session_napi.h"
namespace OHOS {
namespace CameraStandard {
using namespace std;
using namespace CameraNapiSecurity;
thread_local napi_ref CameraManagerNapi::sConstructor_ = nullptr;
thread_local uint32_t CameraManagerNapi::cameraManagerTaskId = CAMERA_MANAGER_TASKID;

const std::unordered_map<SceneMode, JsSceneMode> g_nativeToNapiSupportedModeForSystem_ = {
    {SceneMode::CAPTURE,  JsSceneMode::JS_CAPTURE},
    {SceneMode::VIDEO,  JsSceneMode::JS_VIDEO},
    {SceneMode::PORTRAIT,  JsSceneMode::JS_PORTRAIT},
    {SceneMode::NIGHT,  JsSceneMode::JS_NIGHT},
    {SceneMode::CAPTURE_MACRO, JsSceneMode::JS_CAPTURE_MARCO},
    {SceneMode::VIDEO_MACRO, JsSceneMode::JS_VIDEO_MARCO},
    {SceneMode::SLOW_MOTION,  JsSceneMode::JS_SLOW_MOTION},
    {SceneMode::PROFESSIONAL_PHOTO,  JsSceneMode::JS_PROFESSIONAL_PHOTO},
    {SceneMode::PROFESSIONAL_VIDEO,  JsSceneMode::JS_PROFESSIONAL_VIDEO},
    {SceneMode::HIGH_RES_PHOTO, JsSceneMode::JS_HIGH_RES_PHOTO},
    {SceneMode::SECURE, JsSceneMode::JS_SECURE_CAMERA},
};

const std::unordered_map<SceneMode, JsSceneMode> g_nativeToNapiSupportedMode_ = {
    {SceneMode::CAPTURE,  JsSceneMode::JS_CAPTURE},
    {SceneMode::VIDEO,  JsSceneMode::JS_VIDEO},
    {SceneMode::SECURE,  JsSceneMode::JS_SECURE_CAMERA},
};

CameraManagerCallbackNapi::CameraManagerCallbackNapi(napi_env env): ListenerBase(env)
{}

CameraManagerCallbackNapi::~CameraManagerCallbackNapi()
{
}

void CameraManagerCallbackNapi::OnCameraStatusCallbackAsync(const CameraStatusInfo &cameraStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnCameraStatusCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("failed to allocate work");
        return;
    }
    std::unique_ptr<CameraStatusCallbackInfo> callbackInfo =
        std::make_unique<CameraStatusCallbackInfo>(cameraStatusInfo, shared_from_this());
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        CameraStatusCallbackInfo* callbackInfo = reinterpret_cast<CameraStatusCallbackInfo *>(work->data);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            if (listener) {
                listener->OnCameraStatusCallback(callbackInfo->info_);
            }
            delete callbackInfo;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void CameraManagerCallbackNapi::OnCameraStatusCallback(const CameraStatusInfo& cameraStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnCameraStatusCallback is called");
    napi_value result[ARGS_TWO];
    napi_value retVal;
    napi_value propValue;
    napi_value undefinedResult;

    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);
    napi_get_undefined(env_, &undefinedResult);
    CAMERA_NAPI_CHECK_NULL_PTR_RETURN_VOID(cameraStatusInfo.cameraDevice, "callback cameraDevice is null");
    napi_create_object(env_, &result[PARAM1]);

    if (cameraStatusInfo.cameraDevice != nullptr) {
        napi_value cameraDeviceNapi = CameraDeviceNapi::CreateCameraObj(env_, cameraStatusInfo.cameraDevice);
        napi_set_named_property(env_, result[PARAM1], "camera", cameraDeviceNapi);
    } else {
        MEDIA_ERR_LOG("Camera info is null");
        napi_set_named_property(env_, result[PARAM1], "camera", undefinedResult);
    }

    int32_t jsCameraStatus = -1;
    jsCameraStatus = cameraStatusInfo.cameraStatus;
    napi_create_int64(env_, jsCameraStatus, &propValue);
    napi_set_named_property(env_, result[PARAM1], "status", propValue);
    MEDIA_INFO_LOG("CameraId: %{public}s, CameraStatus: %{public}d", cameraStatusInfo.cameraDevice->GetID().c_str(),
        cameraStatusInfo.cameraStatus);

    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(callbackNapiPara);
}

void CameraManagerCallbackNapi::OnCameraStatusChanged(const CameraStatusInfo &cameraStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnCameraStatusChanged is called, CameraStatus: %{public}d", cameraStatusInfo.cameraStatus);
    OnCameraStatusCallbackAsync(cameraStatusInfo);
}

void CameraManagerCallbackNapi::OnFlashlightStatusChanged(const std::string &cameraID,
    const FlashStatus flashStatus) const
{
    (void)cameraID;
    (void)flashStatus;
}

CameraMuteListenerNapi::CameraMuteListenerNapi(napi_env env): ListenerBase(env)
{
    MEDIA_DEBUG_LOG("CameraMuteListenerNapi is called.");
}

CameraMuteListenerNapi::~CameraMuteListenerNapi()
{
    MEDIA_DEBUG_LOG("~CameraMuteListenerNapi is called.");
}

void CameraMuteListenerNapi::OnCameraMuteCallbackAsync(bool muteMode) const
{
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("Failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("Failed to allocate work");
        return;
    }
    std::unique_ptr<CameraMuteCallbackInfo> callbackInfo =
        std::make_unique<CameraMuteCallbackInfo>(muteMode, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        CameraMuteCallbackInfo* callbackInfo = reinterpret_cast<CameraMuteCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnCameraMuteCallback(callbackInfo->muteMode_);
            delete callbackInfo;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("Failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void CameraMuteListenerNapi::OnCameraMuteCallback(bool muteMode) const
{
    MEDIA_DEBUG_LOG("OnCameraMuteCallback is called, muteMode: %{public}d", muteMode);
    napi_value result[ARGS_TWO];
    napi_value retVal;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);
    napi_get_boolean(env_, muteMode, &result[PARAM1]);

    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(callbackNapiPara);
}

void CameraMuteListenerNapi::OnCameraMute(bool muteMode) const
{
    MEDIA_DEBUG_LOG("OnCameraMute is called, muteMode: %{public}d", muteMode);
    OnCameraMuteCallbackAsync(muteMode);
}

TorchListenerNapi::TorchListenerNapi(napi_env env): ListenerBase(env)
{
    MEDIA_DEBUG_LOG("TorchListenerNapi is called.");
}

TorchListenerNapi::~TorchListenerNapi()
{
    MEDIA_DEBUG_LOG("~TorchListenerNapi is called.");
}

void TorchListenerNapi::OnTorchStatusChangeCallbackAsync(const TorchStatusInfo &torchStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnTorchStatusChangeCallbackAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("Failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("Failed to allocate work");
        return;
    }
    std::unique_ptr<TorchStatusChangeCallbackInfo> callbackInfo =
        std::make_unique<TorchStatusChangeCallbackInfo>(torchStatusInfo, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        TorchStatusChangeCallbackInfo* callbackInfo = reinterpret_cast<TorchStatusChangeCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnTorchStatusChangeCallback(callbackInfo->info_);
            delete callbackInfo;
        }
        delete work;
    }, uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("Failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void TorchListenerNapi::OnTorchStatusChangeCallback(const TorchStatusInfo& torchStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnTorchStatusChangeCallback is called");
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env_, &scope);
    if (scope == nullptr) {
        return;
    }
    napi_value result[ARGS_TWO];
    napi_value retVal;
    napi_value propValue;

    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);

    napi_create_object(env_, &result[PARAM1]);

    napi_get_boolean(env_, torchStatusInfo.isTorchAvailable, &propValue);
    napi_set_named_property(env_, result[PARAM1], "isTorchAvailable", propValue);
    napi_get_boolean(env_, torchStatusInfo.isTorchActive, &propValue);
    napi_set_named_property(env_, result[PARAM1], "isTorchActive", propValue);
    napi_create_double(env_, torchStatusInfo.torchLevel, &propValue);
    napi_set_named_property(env_, result[PARAM1], "torchLevel", propValue);

    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(callbackNapiPara);
    napi_close_handle_scope(env_, scope);
}

void TorchListenerNapi::OnTorchStatusChange(const TorchStatusInfo &torchStatusInfo) const
{
    MEDIA_DEBUG_LOG("OnTorchStatusChange is called");
    OnTorchStatusChangeCallbackAsync(torchStatusInfo);
}

const std::unordered_map<JsSceneMode, SceneMode> g_jsToFwMode_ = {
    {JsSceneMode::JS_CAPTURE, SceneMode::CAPTURE},
    {JsSceneMode::JS_VIDEO, SceneMode::VIDEO},
    {JsSceneMode::JS_PORTRAIT, SceneMode::PORTRAIT},
    {JsSceneMode::JS_NIGHT, SceneMode::NIGHT},
    {JsSceneMode::JS_SLOW_MOTION, SceneMode::SLOW_MOTION},
    {JsSceneMode::JS_CAPTURE_MARCO, SceneMode::CAPTURE_MACRO},
    {JsSceneMode::JS_VIDEO_MARCO, SceneMode::VIDEO_MACRO},
    {JsSceneMode::JS_PROFESSIONAL_PHOTO, SceneMode::PROFESSIONAL_PHOTO},
    {JsSceneMode::JS_PROFESSIONAL_VIDEO, SceneMode::PROFESSIONAL_VIDEO},
    {JsSceneMode::JS_HIGH_RES_PHOTO, SceneMode::HIGH_RES_PHOTO},
    {JsSceneMode::JS_SECURE_CAMERA, SceneMode::SECURE},
};

CameraManagerNapi::CameraManagerNapi() : env_(nullptr), wrapper_(nullptr)
{
    CAMERA_SYNC_TRACE;
}

CameraManagerNapi::~CameraManagerNapi()
{
    MEDIA_DEBUG_LOG("~CameraManagerNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

// Constructor callback
napi_value CameraManagerNapi::CameraManagerNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraManagerNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CameraManagerNapi> obj = std::make_unique<CameraManagerNapi>();
        obj->env_ = env;
        obj->cameraManager_ = CameraManager::GetInstance();
        if (obj->cameraManager_ == nullptr) {
            MEDIA_ERR_LOG("Failure wrapping js to native napi, obj->cameraManager_ null");
            return result;
        }
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           CameraManagerNapi::CameraManagerNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("CameraManagerNapiConstructor call Failed!");
    return result;
}

void CameraManagerNapi::CameraManagerNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CameraManagerNapiDestructor is called");
    CameraManagerNapi* camera = reinterpret_cast<CameraManagerNapi*>(nativeObject);
    if (camera != nullptr) {
        delete camera;
    }
}

napi_value CameraManagerNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor camera_mgr_properties[] = {
        // CameraManager
        DECLARE_NAPI_FUNCTION("getSupportedCameras", GetSupportedCameras),
        DECLARE_NAPI_FUNCTION("getSupportedSceneModes", GetSupportedModes),
        DECLARE_NAPI_FUNCTION("getSupportedOutputCapability", GetSupportedOutputCapability),
        DECLARE_NAPI_FUNCTION("isCameraMuted", IsCameraMuted),
        DECLARE_NAPI_FUNCTION("isCameraMuteSupported", IsCameraMuteSupported),
        DECLARE_NAPI_FUNCTION("muteCamera", MuteCamera),
        DECLARE_NAPI_FUNCTION("prelaunch", PrelaunchCamera),
        DECLARE_NAPI_FUNCTION("preSwitchCamera", PreSwitchCamera),
        DECLARE_NAPI_FUNCTION("isPrelaunchSupported", IsPrelaunchSupported),
        DECLARE_NAPI_FUNCTION("setPrelaunchConfig", SetPrelaunchConfig),
        DECLARE_NAPI_FUNCTION("createCameraInput", CreateCameraInputInstance),
        DECLARE_NAPI_FUNCTION("createCaptureSession", CreateCameraSessionInstance),
        DECLARE_NAPI_FUNCTION("createSession", CreateSessionInstance),
        DECLARE_NAPI_FUNCTION("createPreviewOutput", CreatePreviewOutputInstance),
        DECLARE_NAPI_FUNCTION("createDeferredPreviewOutput", CreateDeferredPreviewOutputInstance),
        DECLARE_NAPI_FUNCTION("createPhotoOutput", CreatePhotoOutputInstance),
        DECLARE_NAPI_FUNCTION("createVideoOutput", CreateVideoOutputInstance),
        DECLARE_NAPI_FUNCTION("createMetadataOutput", CreateMetadataOutputInstance),
        DECLARE_NAPI_FUNCTION("isTorchSupported", IsTorchSupported),
        DECLARE_NAPI_FUNCTION("isTorchModeSupported", IsTorchModeSupported),
        DECLARE_NAPI_FUNCTION("getTorchMode", GetTorchMode),
        DECLARE_NAPI_FUNCTION("setTorchMode", SetTorchMode),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("once", Once),
        DECLARE_NAPI_FUNCTION("off", Off)
    };

    status = napi_define_class(env, CAMERA_MANAGER_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               CameraManagerNapiConstructor, nullptr,
                               sizeof(camera_mgr_properties) / sizeof(camera_mgr_properties[PARAM0]),
                               camera_mgr_properties, &ctorObj);
    if (status == napi_ok) {
        if (napi_create_reference(env, ctorObj, refCount, &sConstructor_) == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_MANAGER_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value CameraManagerNapi::CreateCameraManager(napi_env env)
{
    MEDIA_INFO_LOG("CreateCameraManager is called");
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
    MEDIA_ERR_LOG("CreateCameraManager call Failed!");
    return result;
}

static napi_value CreateCameraJSArray(napi_env env, napi_status status,
    std::vector<sptr<CameraDevice>> cameraObjList)
{
    MEDIA_DEBUG_LOG("CreateCameraJSArray is called");
    napi_value cameraArray = nullptr;
    napi_value camera = nullptr;

    if (cameraObjList.empty()) {
        MEDIA_ERR_LOG("cameraObjList is empty");
    }

    status = napi_create_array(env, &cameraArray);
    if (status == napi_ok) {
        for (size_t i = 0; i < cameraObjList.size(); i++) {
            camera = CameraDeviceNapi::CreateCameraObj(env, cameraObjList[i]);
            if (camera == nullptr || napi_set_element(env, cameraArray, i, camera) != napi_ok) {
                MEDIA_ERR_LOG("Failed to create camera napi wrapper object");
                return nullptr;
            }
        }
    }
    return cameraArray;
}

void CameraManagerCommonCompleteCallback(napi_env env, napi_status status, void* data)
{
    MEDIA_INFO_LOG("CameraManagerCommonCompleteCallback is called");
    auto context = static_cast<CameraManagerContext*>(data);

    CAMERA_NAPI_CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    MEDIA_INFO_LOG("modeForAsync = %{public}d", context->modeForAsync);
    napi_get_undefined(env, &jsContext->error);
    if (context->modeForAsync == CREATE_DEFERRED_PREVIEW_OUTPUT_ASYNC_CALLBACK) {
        MEDIA_INFO_LOG("createDeferredPreviewOutput");
        jsContext->data = PreviewOutputNapi::CreateDeferredPreviewOutput(env, context->profile);
    }

    if (jsContext->data == nullptr) {
        context->status = false;
        context->errString = context->funcName + " failed";
        MEDIA_ERR_LOG("Failed to create napi, funcName = %{public}s", context->funcName.c_str());
        CameraNapiUtils::CreateNapiErrorObject(env, context->errorCode, context->errString.c_str(), jsContext);
    } else {
        jsContext->status = true;
        MEDIA_INFO_LOG("Success to create napi, funcName = %{public}s", context->funcName.c_str());
    }

    // Finish async trace
    if (!context->funcName.empty() && context->taskId > 0) {
        CAMERA_FINISH_ASYNC_TRACE(context->funcName, context->taskId);
        jsContext->funcName = context->funcName;
    }
    if (context->work != nullptr) {
        CameraNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                             context->work, *jsContext);
    }
    delete context;
}

napi_value CameraManagerNapi::CreateCameraSessionInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreateCameraSessionInstance is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);

    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status != napi_ok || cameraManagerNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap failure!");
        return nullptr;
    }
    result = CameraSessionNapi::CreateCameraSession(env);
    return result;
}

napi_value CameraManagerNapi::CreateSessionInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreateSessionInstance is called");
    CameraManagerNapi* cameraManagerNapi = nullptr;
    int32_t jsModeName = -1;
    CameraNapiParamParser jsParamParser(env, info, cameraManagerNapi, jsModeName);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "Create session invalid argument!")) {
        MEDIA_ERR_LOG("CameraManagerNapi::CreateSessionInstance invalid argument: %{public}d", jsModeName);
    }
    MEDIA_INFO_LOG("CameraManagerNapi::CreateSessionInstance mode = %{public}d", jsModeName);

    std::unordered_map<int32_t, std::function<napi_value(napi_env)>> sessionFactories = {
        {JsSceneMode::JS_CAPTURE, [] (napi_env env) { return CheckSystemApp(env, false) ?
            PhotoSessionForSysNapi::CreateCameraSession(env) : PhotoSessionNapi::CreateCameraSession(env); }},
        {JsSceneMode::JS_VIDEO, [] (napi_env env) { return CheckSystemApp(env, false) ?
            VideoSessionForSysNapi::CreateCameraSession(env) : VideoSessionNapi::CreateCameraSession(env); }},
        {JsSceneMode::JS_PORTRAIT, [] (napi_env env) { return PortraitSessionNapi::CreateCameraSession(env); }},
        {JsSceneMode::JS_NIGHT, [] (napi_env env) { return NightSessionNapi::CreateCameraSession(env); }},
        {JsSceneMode::JS_SLOW_MOTION, [] (napi_env env) { return SlowMotionSessionNapi::CreateCameraSession(env); }},
        {JsSceneMode::JS_PROFESSIONAL_PHOTO, [] (napi_env env) {
            return ProfessionSessionNapi::CreateCameraSession(env, SceneMode::PROFESSIONAL_PHOTO); }},
        {JsSceneMode::JS_PROFESSIONAL_VIDEO, [] (napi_env env) {
            return ProfessionSessionNapi::CreateCameraSession(env, SceneMode::PROFESSIONAL_VIDEO); }},
        {JsSceneMode::JS_CAPTURE_MARCO, [] (napi_env env) { return CheckSystemApp(env, true) ?
            MacroPhotoSessionNapi::CreateCameraSession(env) : nullptr; }},
        {JsSceneMode::JS_VIDEO_MARCO, [] (napi_env env) { return CheckSystemApp(env, true) ?
            MacroVideoSessionNapi::CreateCameraSession(env) : nullptr; }},
        {JsSceneMode::JS_HIGH_RES_PHOTO, [] (napi_env env) { return CheckSystemApp(env, true) ?
            HighResPhotoSessionNapi::CreateCameraSession(env) : nullptr; }},
        {JsSceneMode::JS_SECURE_CAMERA, [] (napi_env env) {
            return SecureCameraSessionNapi::CreateCameraSession(env); }},
    };

    napi_value result = nullptr;
    if (sessionFactories.find(jsModeName) != sessionFactories.end()) {
        result = sessionFactories[jsModeName](env);
    } else {
        result = CameraNapiUtils::GetUndefinedValue(env);
        MEDIA_ERR_LOG("CameraManagerNapi::CreateSessionInstance mode = %{public}d not supported", jsModeName);
    }
    return result;
}

bool ParseSize(napi_env env, napi_value root, Size* size)
{
    MEDIA_DEBUG_LOG("ParseSize is called");
    napi_value tempValue = nullptr;

    if (napi_get_named_property(env, root, "width", &tempValue) == napi_ok) {
        napi_get_value_uint32(env, tempValue, &size->width);
    }

    if (napi_get_named_property(env, root, "height", &tempValue) == napi_ok) {
        napi_get_value_uint32(env, tempValue, &(size->height));
    }

    return true;
}

bool ParseProfile(napi_env env, napi_value root, Profile* profile)
{
    MEDIA_DEBUG_LOG("ParseProfile is called");
    napi_value res = nullptr;

    if (napi_get_named_property(env, root, "size", &res) == napi_ok) {
        ParseSize(env, res, &(profile->size_));
    }

    int32_t intValue = {0};
    if (napi_get_named_property(env, root, "format", &res) == napi_ok) {
        napi_get_value_int32(env, res, &intValue);
        profile->format_ = static_cast<CameraFormat>(intValue);
    }

    return true;
}

bool ParsePrelaunchConfig(napi_env env, napi_value root, PrelaunchConfig* prelaunchConfig)
{
    napi_value res = nullptr;
    napi_status status;
    CameraDeviceNapi* cameraDeviceNapi = nullptr;
    int32_t intValue;
    if (napi_get_named_property(env, root, "cameraDevice", &res) == napi_ok) {
        status = napi_unwrap(env, res, reinterpret_cast<void**>(&cameraDeviceNapi));
        prelaunchConfig->cameraDevice_ = cameraDeviceNapi->cameraDevice_;
        if (status != napi_ok || prelaunchConfig->cameraDevice_ == nullptr) {
            MEDIA_ERR_LOG("napi_unwrap() failure!");
        }
    } else {
        if (!CameraNapiUtils::CheckError(env, INVALID_ARGUMENT)) {
            return false;
        }
    }
    if (napi_get_named_property(env, root, "restoreParamType", &res) == napi_ok) {
        napi_get_value_int32(env, res, &intValue);
        prelaunchConfig->restoreParamType = static_cast<RestoreParamType>(intValue);
        MEDIA_INFO_LOG("SetPrelaunchConfig restoreParamType = %{public}d", intValue);
    }

    if (napi_get_named_property(env, root, "activeTime", &res) == napi_ok) {
        napi_get_value_int32(env, res, &intValue);
        prelaunchConfig->activeTime = intValue;
        MEDIA_INFO_LOG("SetPrelaunchConfig activeTime = %{public}d", intValue);
    }
    return true;
}


bool ParseSettingParam(napi_env env, napi_value root, EffectParam* effectParam)
{
    napi_value res = nullptr;
    if (napi_get_named_property(env, root, "settingParam",  &res) == napi_ok) {
        napi_value tempValue = nullptr;
        int32_t effectValue;
        if (napi_get_named_property(env, res, "skinSmoothLevel", &tempValue) == napi_ok) {
            napi_get_value_int32(env, tempValue, &effectValue);
            effectParam->skinSmoothLevel = effectValue;
        }
        if (napi_get_named_property(env, res, "faceSlender", &tempValue) == napi_ok) {
            napi_get_value_int32(env, tempValue, &effectValue);
            effectParam->faceSlender = effectValue;
        }

        if (napi_get_named_property(env, res, "skinTone", &tempValue) == napi_ok) {
            napi_get_value_int32(env, tempValue, &effectValue);
            effectParam->skinTone = effectValue;
        }
        MEDIA_INFO_LOG("SetPrelaunchConfig effectParam = %{public}d", effectParam->skinSmoothLevel);
    }
    return true;
}

bool ParseVideoProfile(napi_env env, napi_value root, VideoProfile* profile)
{
    MEDIA_DEBUG_LOG("ParseVideoProfile is called");
    napi_value res = nullptr;

    if (napi_get_named_property(env, root, "size", &res) == napi_ok) {
        ParseSize(env, res, &(profile->size_));
    }
    int32_t intValue = {0};
    if (napi_get_named_property(env, root, "format", &res) == napi_ok) {
        napi_get_value_int32(env, res, &intValue);
        profile->format_ = static_cast<CameraFormat>(intValue);
    }

    if (napi_get_named_property(env, root, "frameRateRange", &res) == napi_ok) {
        const static int32_t LENGTH = 2;
        std::vector<int32_t> rateRanges(LENGTH);

        int32_t intValue = {0};
        const static uint32_t MIN_INDEX = 0;
        const static uint32_t MAX_INDEX = 1;

        napi_value value;
        if (napi_get_named_property(env, res, "min", &value) == napi_ok) {
            napi_get_value_int32(env, value, &intValue);
            rateRanges[MIN_INDEX] = intValue;
        }
        if (napi_get_named_property(env, res, "max", &value) == napi_ok) {
            napi_get_value_int32(env, value, &intValue);
            rateRanges[MAX_INDEX] = intValue;
        }
        profile->framerates_ = rateRanges;
    }

    return true;
}

napi_value CameraManagerNapi::CreatePreviewOutputInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreatePreviewOutputInstance is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_TWO, argv, CREATE_PREVIEW_OUTPUT_INSTANCE)) {
        MEDIA_INFO_LOG("CheckInvalidArgument napi_throw_type_error ");
        return result;
    }
    MEDIA_INFO_LOG("CheckInvalidArgument pass");
    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status != napi_ok || cameraManagerNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap failure!");
        return nullptr;
    }
    Profile profile;
    ParseProfile(env, argv[PARAM0], &profile);
    MEDIA_INFO_LOG("ParseProfile "
                   "size.width = %{public}d, size.height = %{public}d, format = %{public}d",
                   profile.size_.width, profile.size_.height, profile.format_);

    char buffer[PATH_MAX];
    size_t length = 0;
    if (napi_get_value_string_utf8(env, argv[PARAM1], buffer, PATH_MAX, &length) == napi_ok) {
        MEDIA_INFO_LOG("surfaceId buffer --1  : %{public}s", buffer);
        std::string surfaceId = std::string(buffer);
        result = PreviewOutputNapi::CreatePreviewOutput(env, profile, surfaceId);
        MEDIA_INFO_LOG("surfaceId after convert : %{public}s", surfaceId.c_str());
    } else {
        MEDIA_ERR_LOG("Could not able to read surfaceId argument!");
    }
    return result;
}

napi_value CameraManagerNapi::CreateDeferredPreviewOutputInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreateDeferredPreviewOutputInstance is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi CreateDeferredPreviewOutputInstance is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_ONE, argv, CREATE_DEFERRED_PREVIEW_OUTPUT)) {
        return result;
    }
    MEDIA_INFO_LOG("CheckInvalidArgument pass");
    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status != napi_ok || cameraManagerNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap failure!");
        return nullptr;
    }
    Profile profile;
    ParseProfile(env, argv[PARAM0], &profile);
    MEDIA_INFO_LOG("ParseProfile "
                   "size.width = %{public}d, size.height = %{public}d, format = %{public}d",
                   profile.size_.width, profile.size_.height, profile.format_);
    result = PreviewOutputNapi::CreateDeferredPreviewOutput(env, profile);
    return result;
}

napi_value CameraManagerNapi::CreatePhotoOutputInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreatePhotoOutputInstance is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, argc, argv, CREATE_PHOTO_OUTPUT_INSTANCE)) {
        return result;
    }

    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status != napi_ok || cameraManagerNapi == nullptr) {
        MEDIA_ERR_LOG("CreatePhotoOutputInstance napi_unwrap failure!");
        return nullptr;
    }

    Profile profile;
    ParseProfile(env, argv[PARAM0], &profile);
    MEDIA_INFO_LOG("CreatePhotoOutputInstance ParseProfile "
                   "size.width = %{public}d, size.height = %{public}d, format = %{public}d",
                   profile.size_.width, profile.size_.height, profile.format_);

    // API10
    char buffer[PATH_MAX];
    size_t length = 0;
    if (argc == ARGS_ONE) {
        MEDIA_INFO_LOG("surface will be create locally");
        result = PhotoOutputNapi::CreatePhotoOutput(env, profile, "");
    } else if (argc == ARGS_TWO &&
               napi_get_value_string_utf8(env, argv[PARAM1], buffer, PATH_MAX, &length) == napi_ok) {
        MEDIA_INFO_LOG("surfaceId buffer --1  : %{public}s", buffer);
        std::string surfaceId = std::string(buffer);
        result = PhotoOutputNapi::CreatePhotoOutput(env, profile, surfaceId);
        MEDIA_INFO_LOG("CreatePhotoOutputInstance surfaceId after convert : %{public}s", surfaceId.c_str());
    } else {
        MEDIA_ERR_LOG("CreatePhotoOutputInstance Could not able to read surfaceId argument!");
    }
    return result;
}

napi_value CameraManagerNapi::CreateVideoOutputInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreateVideoOutputInstance is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_TWO, argv, CREATE_VIDEO_OUTPUT_INSTANCE)) {
        return result;
    }

    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status != napi_ok || cameraManagerNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap failure!");
        return nullptr;
    }
    VideoProfile vidProfile;
    ParseVideoProfile(env, argv[0], &(vidProfile));
                MEDIA_INFO_LOG("ParseVideoProfile "
                    "size.width = %{public}d, size.height = %{public}d, format = %{public}d, "
                    "frameRateRange : min = %{public}d, max = %{public}d",
                    vidProfile.size_.width,
                    vidProfile.size_.height,
                    vidProfile.format_,
                    vidProfile.framerates_[0],
                    vidProfile.framerates_[1]);
    char buffer[PATH_MAX];
    size_t length = 0;
    if (napi_get_value_string_utf8(env, argv[PARAM1], buffer, PATH_MAX, &length) == napi_ok) {
        MEDIA_INFO_LOG("surfaceId buffer --1  : %{public}s", buffer);
        std::string surfaceId = std::string(buffer);
        result = VideoOutputNapi::CreateVideoOutput(env, vidProfile, surfaceId);
        MEDIA_INFO_LOG("surfaceId after convert : %{public}s", surfaceId.c_str());
    } else {
        MEDIA_ERR_LOG("Could not able to read surfaceId argument!");
    }
    return result;
}

napi_value ParseMetadataObjectTypes(napi_env env, napi_value arrayParam,
                                    std::vector<MetadataObjectType> &metadataObjectTypes)
{
    MEDIA_DEBUG_LOG("ParseMetadataObjectTypes is called");
    napi_value result;
    uint32_t length = 0;
    napi_value value;
    int32_t metadataType;
    napi_get_array_length(env, arrayParam, &length);
    napi_valuetype type = napi_undefined;
    for (uint32_t i = 0; i < length; i++) {
        napi_get_element(env, arrayParam, i, &value);
        napi_typeof(env, value, &type);
        if (type != napi_number) {
            return nullptr;
        }
        napi_get_value_int32(env, value, &metadataType);
        metadataObjectTypes.push_back(static_cast<MetadataObjectType>(metadataType));
    }
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value CameraManagerNapi::CreateMetadataOutputInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreateMetadataOutputInstance is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_ONE, argv, CREATE_METADATA_OUTPUT_INSTANCE)) {
        return result;
    }

    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status != napi_ok || cameraManagerNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap failure!");
        return nullptr;
    }
    std::vector<MetadataObjectType> metadataObjectTypes;
    ParseMetadataObjectTypes(env, argv[PARAM0], metadataObjectTypes);
    result = MetadataOutputNapi::CreateMetadataOutput(env);
    return result;
}

napi_value CameraManagerNapi::GetSupportedCameras(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetSupportedCameras is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status == napi_ok && cameraManagerNapi != nullptr) {
        std::vector<sptr<CameraDevice>> cameraObjList = cameraManagerNapi->cameraManager_->GetSupportedCameras();
        result = CreateCameraJSArray(env, status, cameraObjList);
        MEDIA_DEBUG_LOG("CameraManagerNapi::GetSupportedCameras size=[%{public}zu]", cameraObjList.size());
    } else {
        MEDIA_ERR_LOG("GetSupportedCameras call Failed!");
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
    std::unordered_map<SceneMode, JsSceneMode> nativeToNapiMap = g_nativeToNapiSupportedMode_;
    if (CameraNapiSecurity::CheckSystemApp(env, false)) {
        nativeToNapiMap = g_nativeToNapiSupportedModeForSystem_;
    }
    if (status == napi_ok) {
        for (size_t i = 0; i < nativeArray.size(); i++) {
            auto itr = nativeToNapiMap.find(nativeArray[i]);
            if (itr != nativeToNapiMap.end()) {
                napi_create_int32(env, itr->second, &item);
            }
            if (napi_set_element(env, jsArray, i, item) != napi_ok) {
                MEDIA_ERR_LOG("Failed to create profile napi wrapper object");
                return nullptr;
            }
        }
    }
    return jsArray;
}

napi_value CameraManagerNapi::GetSupportedModes(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetSupportedModes is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;
    napi_value jsResult = nullptr;
    CameraDeviceNapi* cameraDeviceNapi = nullptr;
    CameraManagerNapi* cameraManagerNapi = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    status = napi_unwrap(env, argv[PARAM0], reinterpret_cast<void**>(&cameraDeviceNapi));
    if (status != napi_ok || cameraDeviceNapi == nullptr) {
        MEDIA_ERR_LOG("Could not able to read cameraId argument!");
        return result;
    }
    sptr<CameraDevice> cameraInfo = cameraDeviceNapi->cameraDevice_;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status == napi_ok && cameraManagerNapi != nullptr) {
        std::vector<SceneMode> modeObjList = cameraManagerNapi->cameraManager_->GetSupportedModes(cameraInfo);
        for (auto it = modeObjList.begin(); it != modeObjList.end(); it++) {
            if (*it == SCAN) {
                modeObjList.erase(it);
                break;
            }
        }
        if (modeObjList.empty()) {
            modeObjList.emplace_back(CAPTURE);
            modeObjList.emplace_back(VIDEO);
        }
        MEDIA_INFO_LOG("CameraManagerNapi::GetSupportedModes size=[%{public}zu]", modeObjList.size());
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

napi_value CameraManagerNapi::GetSupportedOutputCapability(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetSupportedOutputCapability is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    CameraDeviceNapi* cameraDeviceNapi = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    napi_get_undefined(env, &result);
    status = napi_unwrap(env, argv[PARAM0], reinterpret_cast<void**>(&cameraDeviceNapi));
    if (status != napi_ok || cameraDeviceNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap failure!");
        return result;
    }
    sptr<CameraDevice> cameraInfo = cameraDeviceNapi->cameraDevice_;
    if (argc == ARGS_ONE) {
        result = CameraOutputCapabilityNapi::CreateCameraOutputCapability(env, cameraInfo);
    } else if (argc == ARGS_TWO) {
        int32_t jsSceneMode;
        napi_get_value_int32(env, argv[PARAM1], &jsSceneMode);
        MEDIA_INFO_LOG("CameraManagerNapi::GetSupportedOutputCapability mode = %{public}d", jsSceneMode);
        auto itr = g_jsToFwMode_.find(static_cast<JsSceneMode>(jsSceneMode));
        if (itr != g_jsToFwMode_.end()) {
            result = CameraOutputCapabilityNapi::CreateCameraOutputCapability(env, cameraInfo, itr->second);
        } else {
            MEDIA_ERR_LOG("CreateCameraSessionInstance mode = %{public}d not supported", jsSceneMode);
        }
    }
    return result;
}

napi_value CameraManagerNapi::IsCameraMuted(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("IsCameraMuted is called");
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameters maximum");
    bool isMuted = CameraManager::GetInstance()->IsCameraMuted();
    MEDIA_DEBUG_LOG("IsCameraMuted : %{public}d", isMuted);
    napi_get_boolean(env, isMuted, &result);
    return result;
}

napi_value CameraManagerNapi::IsCameraMuteSupported(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsCameraMuteSupported is called!");
        return nullptr;
    }
    MEDIA_INFO_LOG("IsCameraMuteSupported is called");
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameters maximum");

    bool isMuteSupported = CameraManager::GetInstance()->IsCameraMuteSupported();
    MEDIA_DEBUG_LOG("isMuteSupported: %{public}d", isMuteSupported);
    napi_get_boolean(env, isMuteSupported, &result);
    return result;
}

napi_value CameraManagerNapi::MuteCamera(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi MuteCamera is called!");
        return nullptr;
    }
    MEDIA_INFO_LOG("MuteCamera is called");
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_TWO, "requires 1 parameters maximum");
    bool isSupported;
    napi_get_value_bool(env, argv[PARAM0], &isSupported);
    CameraManager::GetInstance()->MuteCamera(isSupported);
    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraManagerNapi::CreateCameraInputInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreateCameraInputInstance is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_TWO, argv, CREATE_CAMERA_INPUT_INSTANCE)) {
        return result;
    }

    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status != napi_ok || cameraManagerNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap( ) failure!");
        return result;
    }
    sptr<CameraDevice> cameraInfo = nullptr;
    if (argc == ARGS_ONE) {
        CameraDeviceNapi* cameraDeviceNapi = nullptr;
        status = napi_unwrap(env, argv[PARAM0], reinterpret_cast<void**>(&cameraDeviceNapi));
        if (status != napi_ok || cameraDeviceNapi == nullptr) {
            MEDIA_ERR_LOG("napi_unwrap( ) failure!");
            return result;
        }
        cameraInfo = cameraDeviceNapi->cameraDevice_;
    } else if (argc == ARGS_TWO) {
        int32_t numValue;

        napi_get_value_int32(env, argv[PARAM0], &numValue);
        CameraPosition cameraPosition = static_cast<CameraPosition>(numValue);

        napi_get_value_int32(env, argv[PARAM1], &numValue);
        CameraType cameraType = static_cast<CameraType>(numValue);

        ProcessCameraInfo(cameraManagerNapi->cameraManager_, cameraPosition, cameraType, cameraInfo);
    }
    if (cameraInfo != nullptr) {
        sptr<CameraInput> cameraInput = nullptr;
        int retCode = CameraManager::GetInstance()->CreateCameraInput(cameraInfo, &cameraInput);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        result = CameraInputNapi::CreateCameraInput(env, cameraInput);
    } else {
        MEDIA_ERR_LOG("cameraInfo is null");
    }
    return result;
}

void CameraManagerNapi::ProcessCameraInfo(sptr<CameraManager>& cameraManager, const CameraPosition cameraPosition,
    const CameraType cameraType, sptr<CameraDevice>& cameraInfo)
{
    std::vector<sptr<CameraDevice>> cameraObjList = cameraManager->GetSupportedCameras();
    MEDIA_DEBUG_LOG("cameraInfo is null, the cameraObjList size is %{public}zu", cameraObjList.size());
    for (size_t i = 0; i < cameraObjList.size(); i++) {
        sptr<CameraDevice> cameraDevice = cameraObjList[i];
        if (cameraDevice == nullptr) {
            continue;
        }
        if (cameraDevice->GetPosition() == cameraPosition &&
            cameraDevice->GetCameraType() == cameraType) {
            cameraInfo = cameraDevice;
            break;
        }
    }
}

void CameraManagerNapi::RegisterCameraStatusCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (cameraManagerCallback_ == nullptr) {
        shared_ptr<CameraManagerCallbackNapi> cameraManagerCallback =
            std::static_pointer_cast<CameraManagerCallbackNapi>(cameraManager_->GetApplicationCallback());
        if (cameraManagerCallback == nullptr) {
            cameraManagerCallback = make_shared<CameraManagerCallbackNapi>(env);
            cameraManager_->SetCallback(cameraManagerCallback);
        }
        cameraManagerCallback_ = cameraManagerCallback;
    }
    cameraManagerCallback_->SaveCallbackReference(callback, isOnce);
}

void CameraManagerNapi::UnregisterCameraStatusCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (cameraManagerCallback_ == nullptr) {
        MEDIA_ERR_LOG("cameraManagerCallback is null");
    } else {
        cameraManagerCallback_->RemoveCallbackRef(env, callback);
    }
}

void CameraManagerNapi::RegisterCameraMuteCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi On cameraMute is called!");
        return;
    }
    if (cameraMuteListener_ == nullptr) {
        shared_ptr<CameraMuteListenerNapi> cameraMuteListener =
            std::static_pointer_cast<CameraMuteListenerNapi>(cameraManager_->GetCameraMuteListener());
        if (cameraMuteListener == nullptr) {
            cameraMuteListener = make_shared<CameraMuteListenerNapi>(env);
            cameraManager_->RegisterCameraMuteListener(cameraMuteListener);
        }
        cameraMuteListener_ = cameraMuteListener;
    }
    cameraMuteListener_->SaveCallbackReference(callback, isOnce);
}

void CameraManagerNapi::UnregisterCameraMuteCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi On cameraMute is called!");
        return;
    }
    if (cameraMuteListener_ == nullptr) {
        MEDIA_ERR_LOG("cameraMuteListener is null");
    } else {
        cameraMuteListener_->RemoveCallbackRef(env, callback);
    }
}

void CameraManagerNapi::RegisterTorchStatusCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (torchListener_ == nullptr) {
        shared_ptr<TorchListenerNapi> torchListener =
            std::static_pointer_cast<TorchListenerNapi>(cameraManager_->GetTorchListener());
        if (torchListener == nullptr) {
            torchListener = make_shared<TorchListenerNapi>(env);
            cameraManager_->RegisterTorchListener(torchListener);
        }
        torchListener_ = torchListener;
    }
    torchListener_->SaveCallbackReference(callback, isOnce);
}

void CameraManagerNapi::UnregisterTorchStatusCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (torchListener_ == nullptr) {
        MEDIA_ERR_LOG("torchListener_ is null");
    } else {
        torchListener_->RemoveCallbackRef(env, callback);
    }
}

const CameraManagerNapi::EmitterFunctions& CameraManagerNapi::GetEmitterFunctions()
{
    static const EmitterFunctions funMap = {
        { "cameraStatus", {
            &CameraManagerNapi::RegisterCameraStatusCallbackListener,
            &CameraManagerNapi::UnregisterCameraStatusCallbackListener } },
        { "cameraMute", {
            &CameraManagerNapi::RegisterCameraMuteCallbackListener,
            &CameraManagerNapi::UnregisterCameraMuteCallbackListener } },
        { "torchStatusChange", {
            &CameraManagerNapi::RegisterTorchStatusCallbackListener,
            &CameraManagerNapi::UnregisterTorchStatusCallbackListener } } };
    return funMap;
}

napi_value CameraManagerNapi::IsPrelaunchSupported(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("IsPrelaunchSupported is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsPrelaunchSupported is called!");
        return nullptr;
    }
    napi_status status;

    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    CameraDeviceNapi* cameraDeviceNapi = nullptr;
    CameraManagerNapi* cameraManagerNapi = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status != napi_ok || cameraManagerNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap( ) failure!");
        return result;
    }
    status = napi_unwrap(env, argv[PARAM0], reinterpret_cast<void**>(&cameraDeviceNapi));
    if (status == napi_ok && cameraDeviceNapi != nullptr) {
        sptr<CameraDevice> cameraInfo = cameraDeviceNapi->cameraDevice_;
        bool isPrelaunchSupported = CameraManager::GetInstance()->IsPrelaunchSupported(cameraInfo);
        MEDIA_DEBUG_LOG("isPrelaunchSupported: %{public}d", isPrelaunchSupported);
        napi_get_boolean(env, isPrelaunchSupported, &result);
    } else {
        MEDIA_ERR_LOG("Could not able to read cameraDevice argument!");
        if (!CameraNapiUtils::CheckError(env, INVALID_ARGUMENT)) {
            MEDIA_DEBUG_LOG("Could not able to read cameraDevice argument throw error");
        }
    }
    return result;
}

napi_value CameraManagerNapi::PrelaunchCamera(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("PrelaunchCamera is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi PrelaunchCamera is called!");
        return nullptr;
    }
    napi_value result = nullptr;
    int32_t retCode = CameraManager::GetInstance()->PrelaunchCamera();
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        return result;
    }
    MEDIA_INFO_LOG("PrelaunchCamera");
    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraManagerNapi::PreSwitchCamera(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("PreSwitchCamera is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi PreSwitchCamera is called!");
        return nullptr;
    }
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc < ARGS_TWO, "requires 1 parameters maximum");
    char buffer[PATH_MAX];
    size_t length;
    napi_get_value_string_utf8(env, argv[ARGS_ZERO], buffer, PATH_MAX, &length);
    int32_t retCode = CameraManager::GetInstance()->PreSwitchCamera(std::string(buffer));
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        return result;
    }
    MEDIA_INFO_LOG("PreSwitchCamera");
    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraManagerNapi::SetPrelaunchConfig(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("SetPrelaunchConfig is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi SetPrelaunchConfig is called!");
        return nullptr;
    }

    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc < ARGS_TWO, "requires 1 parameters maximum");
    PrelaunchConfig prelaunchConfig;
    EffectParam effectParam;
    napi_value result = nullptr;

    bool isConfigSuccess = ParsePrelaunchConfig(env, argv[PARAM0], &prelaunchConfig);
    if (!isConfigSuccess) {
        MEDIA_ERR_LOG("SetPrelaunchConfig failed");
        return result;
    }
    ParseSettingParam(env, argv[PARAM0], &effectParam);
    std::string cameraId = prelaunchConfig.GetCameraDevice()->GetID();
    MEDIA_INFO_LOG("SetPrelaunchConfig cameraId = %{public}s", cameraId.c_str());

    int32_t retCode = CameraManager::GetInstance()->SetPrelaunchConfig(cameraId,
        static_cast<RestoreParamTypeOhos>(prelaunchConfig.restoreParamType), prelaunchConfig.activeTime, effectParam);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        return result;
    }
    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraManagerNapi::IsTorchSupported(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("IsTorchSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status == napi_ok && cameraManagerNapi != nullptr) {
        bool isTorchSupported = CameraManager::GetInstance()->IsTorchSupported();
        MEDIA_DEBUG_LOG("IsTorchSupported : %{public}d", isTorchSupported);
        napi_get_boolean(env, isTorchSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsTorchSupported call Failed!");
    }
    return result;
}

napi_value CameraManagerNapi::IsTorchModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("IsTorchModeSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status == napi_ok && cameraManagerNapi != nullptr) {
        int32_t mode;
        napi_get_value_int32(env, argv[PARAM0], &mode);
        MEDIA_INFO_LOG("CameraManagerNapi::IsTorchModeSupported mode = %{public}d", mode);
        TorchMode torchMode = (TorchMode)mode;
        bool isTorchModeSupported = CameraManager::GetInstance()->IsTorchModeSupported(torchMode);
        MEDIA_DEBUG_LOG("IsTorchModeSupported : %{public}d", isTorchModeSupported);
        napi_get_boolean(env, isTorchModeSupported, &result);
    } else {
        MEDIA_ERR_LOG("GetTorchMode call Failed!");
    }
    return result;
}

napi_value CameraManagerNapi::GetTorchMode(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetTorchMode is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status == napi_ok && cameraManagerNapi != nullptr) {
        TorchMode torchMode = CameraManager::GetInstance()->GetTorchMode();
        MEDIA_DEBUG_LOG("GetTorchMode : %{public}d", torchMode);
        napi_create_int32(env, torchMode, &result);
    } else {
        MEDIA_ERR_LOG("GetTorchMode call Failed!");
    }
    return result;
}

napi_value CameraManagerNapi::SetTorchMode(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("SetTorchMode is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status == napi_ok && cameraManagerNapi != nullptr) {
        int32_t mode;
        napi_get_value_int32(env, argv[PARAM0], &mode);
        MEDIA_INFO_LOG("CameraManagerNapi::SetTorchMode mode = %{public}d", mode);
        TorchMode torchMode = (TorchMode)mode;
        int32_t retCode = CameraManager::GetInstance()->SetTorchMode(torchMode);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            MEDIA_DEBUG_LOG("SetTorchMode fail throw error");
        }
    } else {
        MEDIA_ERR_LOG("GetTorchMode call Failed!");
    }
    return result;
}

napi_value CameraManagerNapi::On(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<CameraManagerNapi>::On(env, info);
}

napi_value CameraManagerNapi::Once(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<CameraManagerNapi>::Once(env, info);
}

napi_value CameraManagerNapi::Off(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<CameraManagerNapi>::Off(env, info);
}
} // namespace CameraStandard
} // namespace OHOS
