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

#include <uv.h>

#include "camera_napi_param_parser.h"
#include "input/camera_manager_for_sys.h"
#include "mode/slow_motion_session_napi.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

thread_local napi_ref SlowMotionSessionNapi::sConstructor_ = nullptr;

void SlowMotionStateListener::OnSlowMotionStateCbAsync(const SlowMotionState state) const
{
    MEDIA_DEBUG_LOG("OnSlowMotionStateCbAsync is called");
    std::unique_ptr<SlowMotionStateListenerInfo> callbackInfo =
        std::make_unique<SlowMotionStateListenerInfo>(state, shared_from_this());
    SlowMotionStateListenerInfo *event = callbackInfo.get();
    auto task = [event]() {
        SlowMotionStateListenerInfo* callbackInfo = reinterpret_cast<SlowMotionStateListenerInfo *>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            CHECK_EXECUTE(listener != nullptr, listener->OnSlowMotionStateCb(callbackInfo->state_));
            delete callbackInfo;
        }
    };
    std::unordered_map<std::string, std::string> params = {
        {"state", std::to_string(state)},
    };
    std::string taskName =
        CameraNapiUtils::GetTaskName("SlowMotionStateListener::OnSlowMotionStateCbAsync", params);
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate, taskName.c_str())) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        callbackInfo.release();
    }
}

void SlowMotionStateListener::OnSlowMotionStateCb(const SlowMotionState state) const
{
    MEDIA_DEBUG_LOG("OnSlowMotionStateCb is called, state: %{public}d", state);

    ExecuteCallbackScopeSafe("slowMotionStatus", [&]() {
        napi_value callbackObj;
        napi_value errCode;

        napi_create_int32(env_, state, &callbackObj);
        errCode = CameraNapiUtils::GetUndefinedValue(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
}

void SlowMotionStateListener::OnSlowMotionState(SlowMotionState state)
{
    OnSlowMotionStateCbAsync(state);
}

SlowMotionSessionNapi::SlowMotionSessionNapi() : env_(nullptr)
{
}

SlowMotionSessionNapi::~SlowMotionSessionNapi()
{
    MEDIA_DEBUG_LOG("~SlowMotionSessionNapi is called");
}

void SlowMotionSessionNapi::SlowMotionSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("SlowMotionSessionNapiDestructor is called");
    SlowMotionSessionNapi* cameraObj = reinterpret_cast<SlowMotionSessionNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}

void SlowMotionSessionNapi::Init(napi_env env)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    std::vector<napi_property_descriptor> slow_motion_props = {
        DECLARE_NAPI_FUNCTION("isSlowMotionDetectionSupported", IsSlowMotionDetectionSupported),
        DECLARE_NAPI_FUNCTION("setSlowMotionDetectionArea", SetSlowMotionDetectionArea)
    };
    std::vector<std::vector<napi_property_descriptor>> descriptors = { camera_process_props,
        CameraSessionForSysNapi::camera_process_sys_props, flash_props, CameraSessionForSysNapi::flash_sys_props,
        auto_exposure_props, focus_props, CameraSessionForSysNapi::focus_sys_props, zoom_props,
        CameraSessionForSysNapi::zoom_sys_props, slow_motion_props, filter_props };
    std::vector<napi_property_descriptor> slow_motion_session_props =
        CameraNapiUtils::GetPropertyDescriptor(descriptors);
    status = napi_define_class(env, SLOW_MOTION_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               SlowMotionSessionNapiConstructor, nullptr,
                               slow_motion_session_props.size(),
                               slow_motion_session_props.data(), &ctorObj);
    CHECK_RETURN_ELOG(status != napi_ok, "SlowMotionSessionNapi defined class failed");
    status = NapiRefManager::CreateMemSafetyRef(env, ctorObj, &sConstructor_);
    CHECK_RETURN_ELOG(status != napi_ok, "SlowMotionSessionNapi Init failed");
    MEDIA_DEBUG_LOG("SlowMotionSessionNapi Init success");
}

napi_value SlowMotionSessionNapi::CreateCameraSession(napi_env env)
{
    COMM_INFO_LOG("CreateCameraSession is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    if (sConstructor_ == nullptr) {
        SlowMotionSessionNapi::Init(env);
        CHECK_RETURN_RET_ELOG(sConstructor_ == nullptr, result, "sConstructor_ is null");
    }
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraSessionForSys_ =
            CameraManagerForSys::GetInstance()->CreateCaptureSessionForSys(SceneMode::SLOW_MOTION);
        if (sCameraSessionForSys_ == nullptr) {
            MEDIA_ERR_LOG("Failed to create SlowMotion session instance");
            napi_get_undefined(env, &result);
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCameraSessionForSys_ = nullptr;
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
        CHECK_RETURN_RET_ELOG(sCameraSessionForSys_ == nullptr, result, "sCameraSessionForSys_ is null");
        obj->slowMotionSession_ = static_cast<SlowMotionSession*>(sCameraSessionForSys_.GetRefPtr());
        obj->cameraSessionForSys_ = obj->slowMotionSession_;
        obj->cameraSession_ = obj->slowMotionSession_;
        CHECK_RETURN_RET_ELOG(obj->slowMotionSession_ == nullptr, result, "slowMotionSession is null");
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
    SlowMotionSessionNapi* slowMotionSessionNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, slowMotionSessionNapi);
    CHECK_RETURN_RET_ELOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"),
        result, "IsSlowMotionDetectionSupported parse parameter occur error");
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
    CHECK_RETURN_RET(status != napi_ok, nullptr);
    status = napi_get_value_double(env, property, &propertyValue);
    CHECK_RETURN_RET(status != napi_ok, nullptr);
    return property;
}

napi_value SlowMotionSessionNapi::SetSlowMotionDetectionArea(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("SetSlowMotionDetectionArea is called");
    napi_value result = CameraNapiUtils::GetUndefinedValue(env);
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
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
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
    slowMotionStateListener_->SaveCallbackReference(eventName, callback, isOnce);
    MEDIA_INFO_LOG("RegisterSlowMotionStateCb success");
}

void SlowMotionSessionNapi::UnregisterSlowMotionStateCb(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    MEDIA_INFO_LOG("UnregisterSlowMotionStateCb is called");
    if (slowMotionStateListener_ == nullptr) {
        MEDIA_ERR_LOG("slowMotionStateListener_ is null");
    } else {
        slowMotionStateListener_->RemoveCallbackRef(eventName, callback);
    }
}
} // namespace CameraStandard
} // namespace OHOS