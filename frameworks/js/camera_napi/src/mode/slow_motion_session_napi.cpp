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

#include "camera_napi_security_utils.h"
#include "camera_napi_param_parser.h"
#include "uv.h"
#include "mode/slow_motion_session_napi.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

thread_local napi_ref SlowMotionSessionNapi::sConstructor_ = nullptr;

void SlowMotionStateListener::OnSlowMotionStateCbAsync(const SlowMotionState state) const
{
    MEDIA_DEBUG_LOG("OnSlowMotionStateCbAsync is called");
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
    std::unique_ptr<SlowMotionStateListenerInfo> callbackInfo =
        std::make_unique<SlowMotionStateListenerInfo>(state, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        SlowMotionStateListenerInfo* callbackInfo = reinterpret_cast<SlowMotionStateListenerInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnSlowMotionStateCb(callbackInfo->state_);
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

void SlowMotionStateListener::OnSlowMotionStateCb(const SlowMotionState state) const
{
    MEDIA_DEBUG_LOG("OnSlowMotionStateCb is called, state: %{public}d", state);
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
    napi_value retVal;
    napi_get_undefined(env_, &result[PARAM0]);
    napi_create_int32(env_, state, &result[PARAM1]);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(callbackNapiPara);
}

void SlowMotionStateListener::OnSlowMotionState(SlowMotionState state)
{
    OnSlowMotionStateCbAsync(state);
}

SlowMotionSessionNapi::SlowMotionSessionNapi() : env_(nullptr), wrapper_(nullptr)
{
}

SlowMotionSessionNapi::~SlowMotionSessionNapi()
{
    MEDIA_DEBUG_LOG("~SlowMotionSessionNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (slowMotionSession_) {
        slowMotionSession_ = nullptr;
    }
}

void SlowMotionSessionNapi::SlowMotionSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("SlowMotionSessionNapiDestructor is called");
    SlowMotionSessionNapi* cameraObj = reinterpret_cast<SlowMotionSessionNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}

napi_value SlowMotionSessionNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    std::vector<napi_property_descriptor> slow_motion_props = {
        DECLARE_NAPI_FUNCTION("isMotionDetectionSupported", IsSlowMotionDetectionSupported),
        DECLARE_NAPI_FUNCTION("startMotionMonitoring", SetSlowMotionDetectionArea),
        DECLARE_NAPI_FUNCTION("enableMotionDetection", EnableMotionDetection),
        DECLARE_NAPI_FUNCTION("isSlowMotionDetectionSupported", IsSlowMotionDetectionSupported),
        DECLARE_NAPI_FUNCTION("setSlowMotionDetectionArea", SetSlowMotionDetectionArea)
    };
    std::vector<std::vector<napi_property_descriptor>> descriptors = {camera_process_props, flash_props,
        auto_exposure_props, focus_props, zoom_props, filter_props, slow_motion_props};
    std::vector<napi_property_descriptor> slow_motion_session_props =
        CameraNapiUtils::GetPropertyDescriptor(descriptors);
    status = napi_define_class(env, SLOW_MOTION_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               SlowMotionSessionNapiConstructor, nullptr,
                               slow_motion_session_props.size(),
                               slow_motion_session_props.data(), &ctorObj);
    if (status == napi_ok) {
        int32_t refCount = 1;
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, SLOW_MOTION_SESSION_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        } else {
            MEDIA_ERR_LOG("napi_create_reference Failed!");
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value SlowMotionSessionNapi::CreateCameraSession(napi_env env)
{
    MEDIA_DEBUG_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSession_ = CameraManager::GetInstance()->CreateCaptureSession(SceneMode::SLOW_MOTION);
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("Failed to create SlowMotion session instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSession_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_DEBUG_LOG("success to create slow motion session napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create slow motion session napi instance");
        }
    }
    MEDIA_ERR_LOG("Failed to create slow motion session napi instance last");
    napi_get_undefined(env, &result);
    return result;
}

napi_value SlowMotionSessionNapi::SlowMotionSessionNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SlowMotionSessionNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<SlowMotionSessionNapi> obj = std::make_unique<SlowMotionSessionNapi>();
        obj->env_ = env;
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("sCameraSession is null");
            return result;
        }
        obj->slowMotionSession_ = static_cast<SlowMotionSession*>(sCameraSession_.GetRefPtr());
        obj->cameraSession_ = obj->slowMotionSession_;
        if (obj->slowMotionSession_ == nullptr) {
            MEDIA_ERR_LOG("slowMotionSession is null");
            return result;
        }
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            SlowMotionSessionNapi::SlowMotionSessionNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("SlowMotionSessionNapi Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("SlowMotionSessionNapi call Failed!");
    return result;
}

napi_value SlowMotionSessionNapi::IsSlowMotionDetectionSupported(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("IsSlowMotionDetectionSupported is called");
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsSlowMotionDetectionSupported is called!");
        return result;
    }
    SlowMotionSessionNapi* slowMotionSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, slowMotionSessionNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("IsSlowMotionDetectionSupported parse parameter occur error");
        return result;
    }
    if (slowMotionSessionNapi != nullptr && slowMotionSessionNapi->slowMotionSession_ != nullptr) {
        bool isSupported = slowMotionSessionNapi->slowMotionSession_->IsSlowMotionDetectionSupported();
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsSlowMotionDetectionSupported call Failed!");
    }
    return result;
}

napi_value SlowMotionSessionNapi::GetDoubleProperty(napi_env env, napi_value param, const std::string& propertyName,
    double& propertyValue)
{
    napi_status status;
    napi_value property;
    status = napi_get_named_property(env, param, propertyName.c_str(), &property);
    if (status != napi_ok) {
        return nullptr;
    }
    status = napi_get_value_double(env, property, &propertyValue);
    if (status != napi_ok) {
        return nullptr;
    }
    return property;
}

napi_value SlowMotionSessionNapi::SetSlowMotionDetectionArea(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("SetSlowMotionDetectionArea is called");
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi SetSlowMotionDetectionArea is called!");
        return result;
    }
    SlowMotionSessionNapi* slowMotionSessionNapi = nullptr;
    napi_status status;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    double topLeftX;
    double topLeftY;
    double width;
    double height;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    if ((GetDoubleProperty(env, argv[PARAM0], "topLeftX", topLeftX) == nullptr) ||
        (GetDoubleProperty(env, argv[PARAM0], "topLeftY", topLeftY) == nullptr) ||
        (GetDoubleProperty(env, argv[PARAM0], "width", width) == nullptr) ||
        (GetDoubleProperty(env, argv[PARAM0], "height", height) == nullptr)) {
        return result;
    }

    Rect rect = (Rect) {topLeftX, topLeftY, width, height};
    napi_get_undefined(env, &result);
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&slowMotionSessionNapi));
    if (status == napi_ok && slowMotionSessionNapi != nullptr && slowMotionSessionNapi->slowMotionSession_ != nullptr) {
        slowMotionSessionNapi->slowMotionSession_->SetSlowMotionDetectionArea(rect);
    } else {
        MEDIA_ERR_LOG("SetSlowMotionDetectionArea call Failed!");
    }
    return result;
}

void SlowMotionSessionNapi::RegisterSlowMotionStateCb(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    MEDIA_INFO_LOG("RegisterSlowMotionStateCb is called");
    if (slowMotionStateListener_ == nullptr) {
        shared_ptr<SlowMotionStateListener> slowMotionStateListenerTemp =
            static_pointer_cast<SlowMotionStateListener>(slowMotionSession_->GetApplicationCallback());
        if (slowMotionStateListenerTemp == nullptr) {
            slowMotionStateListenerTemp = make_shared<SlowMotionStateListener>(env);
            slowMotionSession_->SetCallback(slowMotionStateListenerTemp);
        }
        slowMotionStateListener_ = slowMotionStateListenerTemp;
    }
    slowMotionStateListener_->SaveCallbackReference(callback, isOnce);
    MEDIA_INFO_LOG("RegisterSlowMotionStateCb success");
}

void SlowMotionSessionNapi::UnregisterSlowMotionStateCb(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    MEDIA_INFO_LOG("UnregisterSlowMotionStateCb is called");
    if (slowMotionStateListener_ == nullptr) {
        MEDIA_ERR_LOG("slowMotionStateListener_ is null");
    } else {
        slowMotionStateListener_->RemoveCallbackRef(env, callback);
    }
}

napi_value SlowMotionSessionNapi::EnableMotionDetection(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("EnableMotionDetection is called");
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi EnableMotionDetection is called!");
        return result;
    }
    bool isEnable;
    SlowMotionSessionNapi* slowMotionSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, slowMotionSessionNapi, isEnable);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("EnableMotionDetection parse parameter occur error");
        return result;
    }

    if (slowMotionSessionNapi->slowMotionSession_ != nullptr) {
        MEDIA_INFO_LOG("EnableMotionDetection:%{public}d", isEnable);
        slowMotionSessionNapi->slowMotionSession_->LockForControl();
        int32_t retCode = slowMotionSessionNapi->slowMotionSession_->EnableMotionDetection(isEnable);
        slowMotionSessionNapi->slowMotionSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            MEDIA_ERR_LOG("EnableMotionDetection fail %{public}d", retCode);
            return result;
        }
    } else {
        MEDIA_ERR_LOG("EnableMotionDetection get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return result;
    }
    return result;
}
} // namespace CameraStandard
} // namespace OHOS