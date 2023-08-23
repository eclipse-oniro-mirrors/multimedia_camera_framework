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

#include "session/camera_session_napi.h"
#include <uv.h>

namespace OHOS {
namespace CameraStandard {
using namespace std;
using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;

namespace {
    constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "CameraNapi"};
}

thread_local napi_ref CameraSessionNapi::sConstructor_ = nullptr;
thread_local sptr<CaptureSession> CameraSessionNapi::sCameraSession_ = nullptr;
thread_local uint32_t CameraSessionNapi::cameraSessionTaskId = CAMERA_SESSION_TASKID;

void ExposureCallbackListener::OnExposureStateCallbackAsync(ExposureState state) const
{
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("ExposureCallbackListener:OnExposureStateCallbackAsync() failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("ExposureCallbackListener:OnExposureStateCallbackAsync() failed to allocate work");
        return;
    }
    std::unique_ptr<ExposureCallbackInfo> callbackInfo = std::make_unique<ExposureCallbackInfo>(state, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        ExposureCallbackInfo* callbackInfo = reinterpret_cast<ExposureCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnExposureStateCallback(callbackInfo->state_);
            delete callbackInfo;
        }
        delete work;
    });
    if (ret) {
        MEDIA_ERR_LOG("ExposureCallbackListener:OnExposureStateCallbackAsync() failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void ExposureCallbackListener::OnExposureStateCallback(ExposureState state) const
{
    napi_value result[ARGS_ONE];
    napi_value callback = nullptr;
    napi_value retVal;

    napi_create_int32(env_, state, &result[PARAM0]);

    napi_get_reference_value(env_, callbackRef_, &callback);
    napi_call_function(env_, nullptr, callback, ARGS_ONE, result, &retVal);
}

void ExposureCallbackListener::OnExposureState(const ExposureState state)
{
    MEDIA_INFO_LOG("ExposureCallbackListener:OnExposureState() is called!, state: %{public}d", state);
    OnExposureStateCallbackAsync(state);
}

void FocusCallbackListener::OnFocusStateCallbackAsync(FocusState state) const
{
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("FocusCallbackListener:OnFocusStateCallbackAsync() failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("FocusCallbackListener:OnFocusStateCallbackAsync() failed to allocate work");
        return;
    }
    std::unique_ptr<FocusCallbackInfo> callbackInfo = std::make_unique<FocusCallbackInfo>(state, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        FocusCallbackInfo* callbackInfo = reinterpret_cast<FocusCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnFocusStateCallback(callbackInfo->state_);
            delete callbackInfo;
        }
        delete work;
    });
    if (ret) {
        MEDIA_ERR_LOG("FocusCallbackListener:OnFocusStateCallbackAsync() failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void FocusCallbackListener::OnFocusStateCallback(FocusState state) const
{
    napi_value result[ARGS_ONE];
    napi_value callback = nullptr;
    napi_value retVal;

    napi_create_int32(env_, state, &result[PARAM0]);

    napi_get_reference_value(env_, callbackRef_, &callback);
    napi_call_function(env_, nullptr, callback, ARGS_ONE, result, &retVal);
}

void FocusCallbackListener::OnFocusState(FocusState state)
{
    MEDIA_INFO_LOG("FocusCallbackListener:OnFocusState() is called!, state: %{public}d", state);
    OnFocusStateCallbackAsync(state);
}

void SessionCallbackListener::OnErrorCallbackAsync(int32_t errorCode) const
{
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("SessionCallbackListener:OnErrorCallbackAsync() failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("SessionCallbackListener:OnErrorCallbackAsync() failed to allocate work");
        return;
    }
    std::unique_ptr<SessionCallbackInfo> callbackInfo = std::make_unique<SessionCallbackInfo>(errorCode, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        SessionCallbackInfo* callbackInfo = reinterpret_cast<SessionCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnErrorCallback(callbackInfo->errorCode_);
            delete callbackInfo;
        }
        delete work;
    });
    if (ret) {
        MEDIA_ERR_LOG("SessionCallbackListener:OnErrorCallbackAsync() failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void SessionCallbackListener::OnErrorCallback(int32_t errorCode) const
{
    int32_t jsErrorCodeUnknown = -1;
    napi_value result[ARGS_ONE];
    napi_value callback = nullptr;
    napi_value retVal;
    napi_value propValue;
    napi_create_object(env_, &result[PARAM0]);

    napi_create_int32(env_, jsErrorCodeUnknown, &propValue);

    napi_set_named_property(env_, result[PARAM0], "code", propValue);
    napi_get_reference_value(env_, callbackRef_, &callback);
    napi_call_function(env_, nullptr, callback, ARGS_ONE, result, &retVal);
}

void SessionCallbackListener::OnError(int32_t errorCode)
{
    MEDIA_INFO_LOG("SessionCallbackListener:OnError() is called!, errorCode: %{public}d", errorCode);
    OnErrorCallbackAsync(errorCode);
}

CameraSessionNapi::CameraSessionNapi() : env_(nullptr), wrapper_(nullptr)
{
}

CameraSessionNapi::~CameraSessionNapi()
{
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (cameraSession_) {
        cameraSession_ = nullptr;
    }
}

void CameraSessionNapi::CameraSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CameraSessionNapiDestructor enter");
}

napi_value CameraSessionNapi::Init(napi_env env, napi_value exports)
{
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor camera_session_props[] = {
        DECLARE_NAPI_FUNCTION("beginConfig", BeginConfig),
        DECLARE_NAPI_FUNCTION("commitConfig", CommitConfig),

        DECLARE_NAPI_FUNCTION("canAddInput", CanAddInput),
        DECLARE_NAPI_FUNCTION("addInput", AddInput),
        DECLARE_NAPI_FUNCTION("removeInput", RemoveInput),

        DECLARE_NAPI_FUNCTION("canAddOutput", CanAddOutput),
        DECLARE_NAPI_FUNCTION("addOutput", AddOutput),
        DECLARE_NAPI_FUNCTION("removeOutput", RemoveOutput),

        DECLARE_NAPI_FUNCTION("start", Start),
        DECLARE_NAPI_FUNCTION("stop", Stop),
        DECLARE_NAPI_FUNCTION("release", Release),

        DECLARE_NAPI_FUNCTION("lockForControl", LockForControl),
        DECLARE_NAPI_FUNCTION("unlockForControl", UnlockForControl),

        DECLARE_NAPI_FUNCTION("isVideoStabilizationModeSupported", IsVideoStabilizationModeSupported),
        DECLARE_NAPI_FUNCTION("getActiveVideoStabilizationMode", GetActiveVideoStabilizationMode),
        DECLARE_NAPI_FUNCTION("setVideoStabilizationMode", SetVideoStabilizationMode),

        DECLARE_NAPI_FUNCTION("hasFlash", HasFlash),
        DECLARE_NAPI_FUNCTION("isFlashModeSupported", IsFlashModeSupported),
        DECLARE_NAPI_FUNCTION("getFlashMode", GetFlashMode),
        DECLARE_NAPI_FUNCTION("setFlashMode", SetFlashMode),

        DECLARE_NAPI_FUNCTION("isExposureModeSupported", IsExposureModeSupported),
        DECLARE_NAPI_FUNCTION("getExposureMode", GetExposureMode),
        DECLARE_NAPI_FUNCTION("setExposureMode", SetExposureMode),
        DECLARE_NAPI_FUNCTION("getExposureBiasRange", GetExposureBiasRange),
        DECLARE_NAPI_FUNCTION("setExposureBias", SetExposureBias),
        DECLARE_NAPI_FUNCTION("getExposureValue", GetExposureValue),

        DECLARE_NAPI_FUNCTION("getMeteringPoint", GetMeteringPoint),
        DECLARE_NAPI_FUNCTION("setMeteringPoint", SetMeteringPoint),

        DECLARE_NAPI_FUNCTION("isFocusModeSupported", IsFocusModeSupported),
        DECLARE_NAPI_FUNCTION("getFocusMode", GetFocusMode),
        DECLARE_NAPI_FUNCTION("setFocusMode", SetFocusMode),

        DECLARE_NAPI_FUNCTION("getFocusPoint", GetFocusPoint),
        DECLARE_NAPI_FUNCTION("setFocusPoint", SetFocusPoint),
        DECLARE_NAPI_FUNCTION("getFocalLength", GetFocalLength),

        DECLARE_NAPI_FUNCTION("getZoomRatioRange", GetZoomRatioRange),
        DECLARE_NAPI_FUNCTION("getZoomRatio", GetZoomRatio),
        DECLARE_NAPI_FUNCTION("setZoomRatio", SetZoomRatio),

        DECLARE_NAPI_FUNCTION("on", On)
    };

    status = napi_define_class(env, CAMERA_SESSION_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               CameraSessionNapiConstructor, nullptr,
                               sizeof(camera_session_props) / sizeof(camera_session_props[PARAM0]),
                               camera_session_props, &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_SESSION_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }

    return nullptr;
}

// Constructor callback
napi_value CameraSessionNapi::CameraSessionNapiConstructor(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CameraSessionNapi> obj = std::make_unique<CameraSessionNapi>();
        if (obj != nullptr) {
            obj->env_ = env;
            if (sCameraSession_ == nullptr) {
                MEDIA_ERR_LOG("sCameraSession_ is null");
                return result;
            }
            obj->cameraSession_ = sCameraSession_;
            status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                               CameraSessionNapi::CameraSessionNapiDestructor, nullptr, nullptr);
            if (status == napi_ok) {
                obj.release();
                return thisVar;
            } else {
                MEDIA_ERR_LOG("CameraSessionNapi Failure wrapping js to native napi");
            }
        }
    }

    return result;
}

int32_t QueryAndGetInputProperty(napi_env env, napi_value arg, const string &propertyName, napi_value &property)
{
    bool present = false;
    int32_t retval = 0;
    if ((napi_has_named_property(env, arg, propertyName.c_str(), &present) != napi_ok)
        || (!present) || (napi_get_named_property(env, arg, propertyName.c_str(), &property) != napi_ok)) {
            HiLog::Error(LABEL, "Failed to obtain property: %{public}s", propertyName.c_str());
            retval = -1;
    }

    return retval;
}

int32_t GetPointProperties(napi_env env, napi_value pointObj, Point &point)
{
    napi_value propertyX = nullptr;
    napi_value propertyY = nullptr;
    double pointX = -1.0;
    double pointY = -1.0;

    if ((QueryAndGetInputProperty(env, pointObj, "x", propertyX) == 0) &&
        (QueryAndGetInputProperty(env, pointObj, "y", propertyY) == 0)) {
        if ((napi_get_value_double(env, propertyX, &pointX) != napi_ok) ||
            (napi_get_value_double(env, propertyY, &pointY) != napi_ok)) {
            MEDIA_ERR_LOG("GetPointProperties: get propery for x & y failed");
            return -1;
        } else {
            point.x = pointX;
            point.y = pointY;
        }
    } else {
        return -1;
    }

    // Return 0 after focus point properties are successfully obtained
    return 0;
}

napi_value GetPointNapiValue(napi_env env, Point &point)
{
    napi_value result;
    napi_value propValue;
    napi_create_object(env, &result);
    napi_create_double(env, point.x, &propValue);
    napi_set_named_property(env, result, "x", propValue);
    napi_create_double(env, point.y, &propValue);
    napi_set_named_property(env, result, "y", propValue);
    return result;
}

napi_value CameraSessionNapi::CreateCameraSession(napi_env env)
{
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        int retCode = CameraManager::GetInstance()->CreateCaptureSession(&sCameraSession_);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        if (sCameraSession_ == nullptr) {
            MEDIA_ERR_LOG("Failed to create Camera session instance");
            napi_get_undefined(env, &result);
            return result;
        } else {
            MEDIA_INFO_LOG("Camera session instance create success");
        }
        MEDIA_INFO_LOG("before new Camera session napi instance");
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        MEDIA_INFO_LOG("after new Camera session napi instance");
        sCameraSession_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            MEDIA_INFO_LOG("success to create Camera session napi instance");
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Camera session napi instance");
        }
    }
    MEDIA_ERR_LOG("Failed to create Camera session napi instance last");
    napi_get_undefined(env, &result);
    return result;
}

void PopulateRetVal(napi_env env, SessionAsyncCallbackModes mode,
    CameraSessionAsyncContext* context, std::unique_ptr<JSAsyncContextOutput> &jsContext)
{
    jsContext->status = true;
    napi_get_undefined(env, &jsContext->error);
    switch (mode) {
        case COMMIT_CONFIG_ASYNC_CALLBACK:
            if (context->objectInfo->cameraSession_ != nullptr) {
                context->errorCode = context->objectInfo->cameraSession_->CommitConfig();
                MEDIA_INFO_LOG("commit config return : %{public}d", context->errorCode);
            }
            break;
        case SESSION_START_ASYNC_CALLBACK:
            if (context->objectInfo->cameraSession_ != nullptr) {
                context->errorCode = context->objectInfo->cameraSession_->Start();
                MEDIA_INFO_LOG("Start return : %{public}d", context->errorCode);
            }
            break;
        case SESSION_STOP_ASYNC_CALLBACK:
            if (context->objectInfo->cameraSession_ != nullptr) {
                context->errorCode = context->objectInfo->cameraSession_->Stop();
                MEDIA_INFO_LOG("Stop return : %{public}d", context->errorCode);
            }
            break;
        case SESSION_RELEASE_ASYNC_CALLBACK:
            if (context->objectInfo->cameraSession_ != nullptr) {
                context->errorCode = context->objectInfo->cameraSession_->Release();
                MEDIA_INFO_LOG("Release return : %{public}d", context->errorCode);
            }
            break;
        default:
            MEDIA_DEBUG_LOG("mode is not support");
            break;
    }
    if (context->errorCode != 0) {
        context->status = false;
        CameraNapiUtils::CreateNapiErrorObject(env, context->errorCode, context->errorMsg.c_str(), jsContext);
    }
    napi_get_undefined(env, &jsContext->data);
}

static void CommonCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto context = static_cast<CameraSessionAsyncContext*>(data);
    if (context == nullptr) {
        MEDIA_ERR_LOG("Async context is null");
        return;
    }

    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();

    if (!context->status) {
        CameraNapiUtils::CreateNapiErrorObject(env, context->errorCode, context->errorMsg.c_str(), jsContext);
    } else {
        PopulateRetVal(env, context->modeForAsync, context, jsContext);
    }

    if (!context->funcName.empty() && context->taskId > 0) {
        // Finish async trace
        CAMERA_FINISH_ASYNC_TRACE(context->funcName, context->taskId);
        jsContext->funcName = context->funcName;
    }

    if (context->work != nullptr) {
        CameraNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                             context->work, *jsContext);
    }
    delete context;
}

napi_value CameraSessionNapi::BeginConfig(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("BeginConfig called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t ret = cameraSessionNapi->cameraSession_->BeginConfig();
        if (!CameraNapiUtils::CheckError(env, ret)) {
            return nullptr;
        }
    }
    return result;
}

napi_value CameraSessionNapi::CommitConfig(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CommitConfig called");
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= 1, "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    std::unique_ptr<CameraSessionAsyncContext> asyncContext = std::make_unique<CameraSessionAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "CommitConfig");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<CameraSessionAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "CameraSessionNapi::CommitConfig";
                context->taskId = CameraNapiUtils::IncreamentAndGet(cameraSessionTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->bRetBool = false;
                    context->status = true;
                    context->modeForAsync = COMMIT_CONFIG_ASYNC_CALLBACK;
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for CommitConfig");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

napi_value CameraSessionNapi::LockForControl(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("BeginConfig called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        cameraSessionNapi->cameraSession_->LockForControl();
    }

    return result;
}

napi_value CameraSessionNapi::UnlockForControl(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("UnlockForControl called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        cameraSessionNapi->cameraSession_->UnlockForControl();
    }

    return result;
}

napi_value GetJSArgsForCameraInput(napi_env env, size_t argc, const napi_value argv[],
    sptr<CaptureInput> &cameraInput)
{
    napi_value result = nullptr;
    CameraInputNapi* cameraInputNapiObj = nullptr;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_object) {
            napi_unwrap(env, argv[i], reinterpret_cast<void**>(&cameraInputNapiObj));
            if (cameraInputNapiObj != nullptr) {
                MEDIA_ERR_LOG("cameraInputNapiObj->GetCameraInput()");
                cameraInput = cameraInputNapiObj->GetCameraInput();
            } else {
                NAPI_ASSERT(env, false, "type mismatch");
            }
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value CameraSessionNapi::AddInput(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("AddInput called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_ONE, argv, ADD_INPUT)) {
        return result;
    }

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    sptr<CaptureInput> cameraInput = nullptr;
    GetJSArgsForCameraInput(env, argc, argv, cameraInput);
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t ret = cameraSessionNapi->cameraSession_->AddInput(cameraInput);
        if (!CameraNapiUtils::CheckError(env, ret)) {
            return nullptr;
        }
    }
    return result;
}

napi_value CameraSessionNapi::CanAddInput(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CanAddInput called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        sptr<CaptureInput> cameraInput = nullptr;
        GetJSArgsForCameraInput(env, argc, argv, cameraInput);
        bool isSupported = cameraSessionNapi->cameraSession_->CanAddInput(cameraInput);
        napi_get_boolean(env, isSupported, &result);
    }

    return result;
}

napi_value CameraSessionNapi::RemoveInput(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_ONE, argv, REMOVE_INPUT)) {
        return result;
    }

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        sptr<CaptureInput> cameraInput = nullptr;
        GetJSArgsForCameraInput(env, argc, argv, cameraInput);
        int32_t ret = cameraSessionNapi->cameraSession_->RemoveInput(cameraInput);
        if (!CameraNapiUtils::CheckError(env, ret)) {
            return nullptr;
        }
        return result;
    }

    return result;
}

napi_value GetJSArgsForCameraOutput(napi_env env, size_t argc, const napi_value argv[],
    sptr<CaptureOutput> &cameraOutput)
{
    napi_value result = nullptr;
    PreviewOutputNapi* previewOutputNapiObj = nullptr;
    PhotoOutputNapi* photoOutputNapiObj = nullptr;
    VideoOutputNapi* videoOutputNapiObj = nullptr;
    MetadataOutputNapi* metadataOutputNapiObj = nullptr;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_object) {
            if (PreviewOutputNapi::IsPreviewOutput(env, argv[i])) {
                MEDIA_INFO_LOG("preview output adding..");
                napi_unwrap(env, argv[i], reinterpret_cast<void**>(&previewOutputNapiObj));
                cameraOutput = previewOutputNapiObj->GetPreviewOutput();
            } else if (PhotoOutputNapi::IsPhotoOutput(env, argv[i])) {
                MEDIA_INFO_LOG("photo output adding..");
                napi_unwrap(env, argv[i], reinterpret_cast<void**>(&photoOutputNapiObj));
                cameraOutput = photoOutputNapiObj->GetPhotoOutput();
            } else if (VideoOutputNapi::IsVideoOutput(env, argv[i])) {
                MEDIA_INFO_LOG("video output adding..");
                napi_unwrap(env, argv[i], reinterpret_cast<void**>(&videoOutputNapiObj));
                cameraOutput = videoOutputNapiObj->GetVideoOutput();
            } else if (MetadataOutputNapi::IsMetadataOutput(env, argv[i])) {
                MEDIA_INFO_LOG("metadata output adding..");
                napi_unwrap(env, argv[i], reinterpret_cast<void**>(&metadataOutputNapiObj));
                cameraOutput = metadataOutputNapiObj->GetMetadataOutput();
            } else {
                MEDIA_INFO_LOG("invalid output ..");
                NAPI_ASSERT(env, false, "type mismatch");
            }
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value CameraSessionNapi::AddOutput(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("AddOutput called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_ONE, argv, ADD_OUTPUT)) {
        return result;
    }

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        sptr<CaptureOutput> cameraOutput = nullptr;
        result = GetJSArgsForCameraOutput(env, argc, argv, cameraOutput);
        int32_t ret = cameraSessionNapi->cameraSession_->AddOutput(cameraOutput);
        if (!CameraNapiUtils::CheckError(env, ret)) {
            return nullptr;
        }
    }
    return result;
}

napi_value CameraSessionNapi::CanAddOutput(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CanAddOutput called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        sptr<CaptureOutput> cameraOutput = nullptr;
        result = GetJSArgsForCameraOutput(env, argc, argv, cameraOutput);
        bool isSupported = cameraSessionNapi->cameraSession_->CanAddOutput(cameraOutput);
        napi_get_boolean(env, isSupported, &result);
    }

    return result;
}

napi_value CameraSessionNapi::RemoveOutput(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("RemoveOutput called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_ONE, argv, REMOVE_OUTPUT)) {
        return result;
    }

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        sptr<CaptureOutput> cameraOutput = nullptr;
        result = GetJSArgsForCameraOutput(env, argc, argv, cameraOutput);
        int32_t ret = cameraSessionNapi->cameraSession_->RemoveOutput(cameraOutput);
        if (!CameraNapiUtils::CheckError(env, ret)) {
            return nullptr;
        }
    }

    return result;
}

napi_value CameraSessionNapi::Start(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("start called");
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= 1, "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    std::unique_ptr<CameraSessionAsyncContext> asyncContext = std::make_unique<CameraSessionAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Start");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<CameraSessionAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "CameraSessionNapi::Start";
                context->taskId = CameraNapiUtils::IncreamentAndGet(cameraSessionTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->bRetBool = false;
                    context->status = true;
                    context->modeForAsync = SESSION_START_ASYNC_CALLBACK;
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for CameraSessionNapi::Start");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

napi_value CameraSessionNapi::Stop(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Stop called");
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= 1, "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    std::unique_ptr<CameraSessionAsyncContext> asyncContext = std::make_unique<CameraSessionAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Stop");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<CameraSessionAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "CameraSessionNapi::Stop";
                context->taskId = CameraNapiUtils::IncreamentAndGet(cameraSessionTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->bRetBool = false;
                    context->status = true;
                    context->modeForAsync = SESSION_STOP_ASYNC_CALLBACK;
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for CameraSessionNapi::Stop");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

napi_value CameraSessionNapi::Release(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Release called");
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= 1, "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    std::unique_ptr<CameraSessionAsyncContext> asyncContext = std::make_unique<CameraSessionAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Release");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<CameraSessionAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "CameraSessionNapi::Release";
                context->taskId = CameraNapiUtils::IncreamentAndGet(cameraSessionTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->bRetBool = false;
                    context->status = true;
                    context->modeForAsync = SESSION_RELEASE_ASYNC_CALLBACK;
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for CameraSessionNapi::Release");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

napi_value CameraSessionNapi::IsVideoStabilizationModeSupported(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        VideoStabilizationMode videoStabilizationMode = (VideoStabilizationMode)value;
        bool isSupported;
        int32_t retCode = cameraSessionNapi->cameraSession_->
                          IsVideoStabilizationModeSupported(videoStabilizationMode, isSupported);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_get_boolean(env, isSupported, &result);
    }

    return result;
}

napi_value CameraSessionNapi::GetActiveVideoStabilizationMode(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        VideoStabilizationMode videoStabilizationMode;
        int32_t retCode = cameraSessionNapi->cameraSession_->
                          GetActiveVideoStabilizationMode(videoStabilizationMode);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_int32(env, videoStabilizationMode, &result);
    }

    return result;
}

napi_value CameraSessionNapi::SetVideoStabilizationMode(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        VideoStabilizationMode videoStabilizationMode = (VideoStabilizationMode)value;
        int retCode = cameraSessionNapi->cameraSession_->SetVideoStabilizationMode(videoStabilizationMode);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
    }
    return result;
}

napi_value CameraSessionNapi::HasFlash(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        std::vector<FlashMode> flashModes;
        int retCode = cameraSessionNapi->cameraSession_->GetSupportedFlashModes(flashModes);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        bool isSupported = !(flashModes.empty());
        napi_get_boolean(env, isSupported, &result);
    }
    return result;
}

napi_value CameraSessionNapi::IsFlashModeSupported(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        FlashMode flashMode = (FlashMode)value;
        bool isSupported;
        int32_t retCode = cameraSessionNapi->cameraSession_->IsFlashModeSupported(flashMode, isSupported);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_get_boolean(env, isSupported, &result);
    }

    return result;
}

napi_value CameraSessionNapi::SetFlashMode(napi_env env, napi_callback_info info)
{
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        FlashMode flashMode = (FlashMode)value;
        cameraSessionNapi->cameraSession_->LockForControl();
        int retCode = cameraSessionNapi->cameraSession_->SetFlashMode(flashMode);
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
    }
    return result;
}

napi_value CameraSessionNapi::GetFlashMode(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        FlashMode flashMode;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetFlashMode(flashMode);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_int32(env, flashMode, &result);
    }

    return result;
}

napi_value CameraSessionNapi::IsExposureModeSupported(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        ExposureMode exposureMode = (ExposureMode)value;
        bool isSupported;
        int32_t retCode = cameraSessionNapi->cameraSession_->
                    IsExposureModeSupported(static_cast<ExposureMode>(exposureMode), isSupported);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_get_boolean(env, isSupported, &result);
    }
    return result;
}

napi_value CameraSessionNapi::GetExposureMode(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        ExposureMode exposureMode;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetExposureMode(exposureMode);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_int32(env, exposureMode, &result);
    }

    return result;
}

napi_value CameraSessionNapi::SetExposureMode(napi_env env, napi_callback_info info)
{
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        ExposureMode exposureMode = (ExposureMode)value;
        cameraSessionNapi->cameraSession_->LockForControl();
        int retCode = cameraSessionNapi->cameraSession_->SetExposureMode(exposureMode);
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
    }

    return result;
}

napi_value CameraSessionNapi::SetMeteringPoint(napi_env env, napi_callback_info info)
{
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        Point exposurePoint;
        if (GetPointProperties(env, argv[PARAM0], exposurePoint) == 0) {
            cameraSessionNapi->cameraSession_->LockForControl();
            int32_t retCode = cameraSessionNapi->cameraSession_->SetMeteringPoint(exposurePoint);
            cameraSessionNapi->cameraSession_->UnlockForControl();
            if (!CameraNapiUtils::CheckError(env, retCode)) {
                return nullptr;
            }
        } else {
            MEDIA_ERR_LOG("get point failed");
        }
    }

    return result;
}

napi_value CameraSessionNapi::GetMeteringPoint(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        Point exposurePoint;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetMeteringPoint(exposurePoint);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        return GetPointNapiValue(env, exposurePoint);
    }

    return result;
}

napi_value CameraSessionNapi::GetExposureBiasRange(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        std::vector<int32_t> vecExposureBiasList;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetExposureBiasRange(vecExposureBiasList);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        if (vecExposureBiasList.empty() || napi_create_array(env, &result) != napi_ok) {
            return result;
        }
        int32_t j = 0;
        size_t len = vecExposureBiasList.size();
        for (size_t i = 0; i < len; i++) {
            int32_t  exposureBias = vecExposureBiasList[i];
            MEDIA_DEBUG_LOG("EXPOSURE_BIAS_RANGE : exposureBias = %{public}d", vecExposureBiasList[i]);
            napi_value value;
            if (napi_create_int32(env, exposureBias, &value) == napi_ok) {
                napi_set_element(env, result, j, value);
                j++;
            }
        }
        MEDIA_DEBUG_LOG("EXPOSURE_BIAS_RANGE ExposureBiasList size : %{public}zu", vecExposureBiasList.size());
    }

    return result;
}

napi_value CameraSessionNapi::GetExposureValue(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi!= nullptr) {
        int32_t exposureValue;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetExposureValue(exposureValue);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_int32(env, exposureValue, &result);
    }
    return result;
}

napi_value CameraSessionNapi::SetExposureBias(napi_env env, napi_callback_info info)
{
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t exposureValue;
        napi_get_value_int32(env, argv[0], &exposureValue);
        cameraSessionNapi->cameraSession_->LockForControl();
        int32_t retCode = cameraSessionNapi->cameraSession_->SetExposureBias(exposureValue);
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
    }

    return result;
}

napi_value CameraSessionNapi::IsFocusModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("IsFocusModeSupported called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        FocusMode focusMode = (FocusMode)value;
        bool isSupported;
        int32_t retCode = cameraSessionNapi->cameraSession_->IsFocusModeSupported(focusMode,
                                                                                  isSupported);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_get_boolean(env, isSupported, &result);
    }

    return result;
}

napi_value CameraSessionNapi::GetFocalLength(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        float focalLength;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetFocalLength(focalLength);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_double(env, focalLength, &result);
    }

    return result;
}

napi_value CameraSessionNapi::SetFocusPoint(napi_env env, napi_callback_info info)
{
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        Point focusPoint;
        if (GetPointProperties(env, argv[PARAM0], focusPoint) == 0) {
            cameraSessionNapi->cameraSession_->LockForControl();
            int32_t retCode = cameraSessionNapi->cameraSession_->SetFocusPoint(focusPoint);
            cameraSessionNapi->cameraSession_->UnlockForControl();
            if (!CameraNapiUtils::CheckError(env, retCode)) {
                return nullptr;
            }
        } else {
            MEDIA_ERR_LOG("get point failed");
        }
    }

    return result;
}

napi_value CameraSessionNapi::GetFocusPoint(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        Point focusPoint;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetFocusPoint(focusPoint);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        return GetPointNapiValue(env, focusPoint);
    }

    return result;
}

napi_value CameraSessionNapi::GetFocusMode(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        FocusMode focusMode;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetFocusMode(focusMode);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_int32(env, focusMode, &result);
    }

    return result;
}

napi_value CameraSessionNapi::SetFocusMode(napi_env env, napi_callback_info info)
{
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        int32_t value;
        napi_get_value_int32(env, argv[PARAM0], &value);
        FocusMode focusMode = (FocusMode)value;
        cameraSessionNapi->cameraSession_->LockForControl();
        int retCode = cameraSessionNapi->cameraSession_->
                SetFocusMode(static_cast<FocusMode>(focusMode));
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
    }
    return result;
}

napi_value CameraSessionNapi::GetZoomRatioRange(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        std::vector<float> vecZoomRatioList;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetZoomRatioRange(vecZoomRatioList);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        MEDIA_INFO_LOG("CameraSessionNapi::GetZoomRatioRange len = %{public}zu",
            vecZoomRatioList.size());

        if (!vecZoomRatioList.empty() && napi_create_array(env, &result) == napi_ok) {
            for (size_t i = 0; i < vecZoomRatioList.size(); i++) {
                float zoomRatio = vecZoomRatioList[i];
                napi_value value;
                napi_create_double(env, zoomRatio, &value);
                napi_set_element(env, result, i, value);
            }
        } else {
            MEDIA_ERR_LOG("vecSupportedZoomRatioList is empty or failed to create array!");
        }
    }

    return result;
}

napi_value CameraSessionNapi::GetZoomRatio(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        float zoomRatio;
        int32_t retCode = cameraSessionNapi->cameraSession_->GetZoomRatio(zoomRatio);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        napi_create_double(env, zoomRatio, &result);
    }

    return result;
}

napi_value CameraSessionNapi::SetZoomRatio(napi_env env, napi_callback_info info)
{
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;

    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraSessionNapi* cameraSessionNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraSessionNapi));
    if (status == napi_ok && cameraSessionNapi != nullptr) {
        double zoomRatio;
        napi_get_value_double(env, argv[PARAM0], &zoomRatio);
        cameraSessionNapi->cameraSession_->LockForControl();
        int32_t retCode = cameraSessionNapi->cameraSession_->SetZoomRatio((float)zoomRatio);
        cameraSessionNapi->cameraSession_->UnlockForControl();
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
    }

    return result;
}

napi_value CameraSessionNapi::On(napi_env env, napi_callback_info info)
{
    CAMERA_SYNC_TRACE;
    napi_value undefinedResult = nullptr;
    size_t argCount = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr};
    napi_value thisVar = nullptr;
    size_t res = 0;
    char buffer[SIZE];
    const int32_t refCount = 1;
    CameraSessionNapi* obj = nullptr;
    napi_status status;

    napi_get_undefined(env, &undefinedResult);

    CAMERA_NAPI_GET_JS_ARGS(env, info, argCount, argv, thisVar);
    NAPI_ASSERT(env, argCount == ARGS_TWO, "requires 2 parameters");

    if (thisVar == nullptr || argv[PARAM0] == nullptr || argv[PARAM1] == nullptr) {
        MEDIA_ERR_LOG("Failed to retrieve details about the callback");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr) {
        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string
            || napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function) {
            return undefinedResult;
        }

        napi_get_value_string_utf8(env, argv[PARAM0], buffer, SIZE, &res);
        std::string eventType = std::string(buffer);

        napi_ref callbackRef;
        napi_create_reference(env, argv[PARAM1], refCount, &callbackRef);

        if (!eventType.empty() && eventType.compare("exposureStateChange") == 0) {
            // Set callback for exposureStateChange
            std::shared_ptr<ExposureCallbackListener> exposureCallback =
                make_shared<ExposureCallbackListener>(env, callbackRef);
            obj->cameraSession_->SetExposureCallback(exposureCallback);
        } else if (!eventType.empty() && eventType.compare("focusStateChange") == 0) {
            // Set callback for focusStateChange
            std::shared_ptr<FocusCallbackListener> focusCallback =
                make_shared<FocusCallbackListener>(env, callbackRef);
            obj->cameraSession_->SetFocusCallback(focusCallback);
        } else if (!eventType.empty() && eventType.compare("error") == 0) {
            std::shared_ptr<SessionCallbackListener> errorCallback =
                std::make_shared<SessionCallbackListener>(SessionCallbackListener(env, callbackRef));
            obj->cameraSession_->SetCallback(errorCallback);
        } else  {
            MEDIA_ERR_LOG("Failed to Register Callback: event type is empty!");
            if (callbackRef != nullptr) {
                napi_delete_reference(env, callbackRef);
            }
        }
    }

    return undefinedResult;
}
} // namespace CameraStandard
} // namespace OHOS
