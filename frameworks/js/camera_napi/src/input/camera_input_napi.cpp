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

#include "input/camera_input_napi.h"
#include <uv.h>
#include "input/camera_info_napi.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;

namespace {
    constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "CameraNapi"};
}

thread_local napi_ref CameraInputNapi::sConstructor_ = nullptr;
thread_local sptr<CameraInput> CameraInputNapi::sCameraInput_ = nullptr;
thread_local uint32_t CameraInputNapi::cameraInputTaskId = CAMERA_INPUT_TASKID;

void ErrorCallbackListener::OnErrorCallbackAsync(const int32_t errorType, const int32_t errorMsg) const
{
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("ErrorCallbackListener:OnErrorCallbackAsync() failed to get event loop");
        return;
    }
    uv_work_t* work = new(std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("ErrorCallbackListener:OnErrorCallbackAsync() failed to allocate work");
        return;
    }
    std::unique_ptr<ErrorCallbackInfo> callbackInfo = std::make_unique<ErrorCallbackInfo>(errorType, errorMsg, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        ErrorCallbackInfo* callbackInfo = reinterpret_cast<ErrorCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnErrorCallback(callbackInfo->errorType_, callbackInfo->errorMsg_);
            delete callbackInfo;
        }
        delete work;
    });
    if (ret) {
        MEDIA_ERR_LOG("ErrorCallbackListener:OnErrorCallbackAsync() failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void ErrorCallbackListener::OnErrorCallback(const int32_t errorType, const int32_t errorMsg) const
{
    napi_value result;
    napi_value callback = nullptr;
    napi_value retVal;
    napi_value propValue;
    napi_create_int32(env_, errorType, &propValue);
    napi_create_object(env_, &result);
    napi_set_named_property(env_, result, "code", propValue);
    napi_get_reference_value(env_, callbackRef_, &callback);
    napi_call_function(env_, nullptr, callback, ARGS_ONE, &result, &retVal);
}

void ErrorCallbackListener::OnError(const int32_t errorType, const int32_t errorMsg) const
{
    MEDIA_INFO_LOG("ErrorCallbackListener:OnError() is called!, errorType: %{public}d", errorType);
    OnErrorCallbackAsync(errorType, errorMsg);
}

CameraInputNapi::CameraInputNapi() : env_(nullptr), wrapper_(nullptr)
{
}

CameraInputNapi::~CameraInputNapi()
{
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (cameraInput_) {
        cameraInput_ = nullptr;
    }
}

void CameraInputNapi::CameraInputNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CameraInputNapiDestructor enter");
}

napi_value CameraInputNapi::Init(napi_env env, napi_value exports)
{
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    // todo: Open and Close in native have not implemented
    napi_property_descriptor camera_input_props[] = {
        DECLARE_NAPI_FUNCTION("open", Open),
        DECLARE_NAPI_FUNCTION("close", Close),
        DECLARE_NAPI_FUNCTION("release", Release),
        DECLARE_NAPI_FUNCTION("on", On)
    };

    status = napi_define_class(env, CAMERA_INPUT_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               CameraInputNapiConstructor, nullptr,
                               sizeof(camera_input_props) / sizeof(camera_input_props[PARAM0]),
                               camera_input_props, &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_INPUT_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }

    return nullptr;
}

// Constructor callback
napi_value CameraInputNapi::CameraInputNapiConstructor(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CameraInputNapi> obj = std::make_unique<CameraInputNapi>();
        obj->env_ = env;
        obj->cameraInput_ = sCameraInput_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           CameraInputNapi::CameraInputNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }

    return result;
}

napi_value CameraInputNapi::CreateCameraInput(napi_env env, sptr<CameraInput> cameraInput)
{
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    if (cameraInput == nullptr) {
        return result;
    }
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sCameraInput_ = cameraInput;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create Camera input instance");
        }
    }

    napi_get_undefined(env, &result);
    return result;
}

sptr<CameraInput> CameraInputNapi::GetCameraInput()
{
    return cameraInput_;
}

void CommonCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto context = static_cast<CameraInputAsyncContext*>(data);

    if (context == nullptr) {
        MEDIA_ERR_LOG("Async context is null");
        return;
    }

    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();

    MEDIA_INFO_LOG("%{public}s, modeForAsync = %{public}d, status = %{public}d",
        context->funcName.c_str(), context->modeForAsync, context->status);
    switch (context->modeForAsync) {
        case OPEN_ASYNC_CALLBACK:
            if (context->objectInfo && context->objectInfo->GetCameraInput()) {
                context->errorCode = context->objectInfo->GetCameraInput()->Open();
                context->status = context->errorCode == 0;
                jsContext->status = context->status;
            }
            break;
        case CLOSE_ASYNC_CALLBACK:
            if (context->objectInfo && context->objectInfo->GetCameraInput()) {
                context->errorCode = context->objectInfo->GetCameraInput()->Close();
                context->status = context->errorCode == 0;
                jsContext->status = context->status;
            }
            break;
        case RELEASE_ASYNC_CALLBACK:
            if (context->objectInfo && context->objectInfo->GetCameraInput()) {
                context->objectInfo->GetCameraInput()->Release();
                jsContext->status = context->status;
            }
            break;
        default:
            break;
    }

    if (!context->status) {
        CameraNapiUtils::CreateNapiErrorObject(env, context->errorCode, context->errorMsg.c_str(), jsContext);
    } else {
        napi_get_undefined(env, &jsContext->data);
    }

    if (!context->funcName.empty() && context->taskId > 0) {
        // Finish async trace
        CAMERA_FINISH_ASYNC_TRACE(context->funcName, context->taskId);
        jsContext->funcName = context->funcName.c_str();
    }

    if (context->work != nullptr) {
        CameraNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    delete context;
}

napi_value CameraInputNapi::Open(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter maximum");
    napi_get_boolean(env, true, &result);
    CAMERA_NAPI_CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");
    std::unique_ptr<CameraInputAsyncContext> asyncContext = std::make_unique<CameraInputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Open");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<CameraInputAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "CameraInputNapi::Open";
                context->taskId = CameraNapiUtils::IncreamentAndGet(cameraInputTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->status = true;
                    context->modeForAsync = OPEN_ASYNC_CALLBACK;
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for CameraInputNapi::Open");
            if (asyncContext->callbackRef != nullptr) {
                napi_delete_reference(env, asyncContext->callbackRef);
            }
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

napi_value CameraInputNapi::Close(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter maximum");
    napi_get_boolean(env, true, &result);
    CAMERA_NAPI_CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");
    std::unique_ptr<CameraInputAsyncContext> asyncContext = std::make_unique<CameraInputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Close");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<CameraInputAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "CameraInputNapi::Close";
                context->taskId = CameraNapiUtils::IncreamentAndGet(cameraInputTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->status = true;
                    context->modeForAsync = CLOSE_ASYNC_CALLBACK;
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for CameraInputNapi::Close");
            if (asyncContext->callbackRef != nullptr) {
                napi_delete_reference(env, asyncContext->callbackRef);
            }
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

napi_value CameraInputNapi::Release(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter maximum");
    napi_get_boolean(env, true, &result);
    CAMERA_NAPI_CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");
    std::unique_ptr<CameraInputAsyncContext> asyncContext = std::make_unique<CameraInputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Release");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<CameraInputAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "CameraInputNapi::Release";
                context->taskId = CameraNapiUtils::IncreamentAndGet(cameraInputTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->status = true;
                    context->modeForAsync = RELEASE_ASYNC_CALLBACK;
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for CameraInputNapi::Release");
            if (asyncContext->callbackRef != nullptr) {
                napi_delete_reference(env, asyncContext->callbackRef);
            }
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

void CameraInputNapi::RegisterCallback(napi_env env, const string &eventType, napi_ref callbackRef)
{
    if (eventType.empty()) {
        MEDIA_ERR_LOG("Failed to Register Callback callback name is empty!");
        return;
    }

    if (eventType.compare("error") == 0) {
        // Set callback for error
        shared_ptr<ErrorCallbackListener> errorCallback = make_shared<ErrorCallbackListener>(env, callbackRef);
        cameraInput_->SetErrorCallback(errorCallback);
    } else {
        MEDIA_ERR_LOG("Incorrect callback event type provided for camera input!");
    }
}

napi_value CameraInputNapi::On(napi_env env, napi_callback_info info)
{
    CAMERA_SYNC_TRACE;
    napi_value undefinedResult = nullptr;
    size_t argCount = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {nullptr};
    napi_value thisVar = nullptr;
    size_t res = 0;
    char buffer[SIZE];
    const int32_t refCount = 1;
    CameraInputNapi* obj = nullptr;
    CameraDeviceNapi* cameraDeviceNapi = nullptr;
    napi_status status;

    napi_get_undefined(env, &undefinedResult);

    CAMERA_NAPI_GET_JS_ARGS(env, info, argCount, argv, thisVar);

    NAPI_ASSERT(env, argCount == ARGS_THREE, "requires 3 parameters");

    if (thisVar == nullptr || argv[PARAM0] == nullptr || argv[PARAM1] == nullptr || argv[PARAM2] == nullptr) {
        MEDIA_ERR_LOG("Failed to retrieve details about the callback");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr) {
        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string
            || napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_object
            || napi_typeof(env, argv[PARAM2], &valueType) != napi_ok || valueType != napi_function) {
            return undefinedResult;
        }

        napi_get_value_string_utf8(env, argv[PARAM0], buffer, SIZE, &res);
        std::string eventType = std::string(buffer);

        status = napi_unwrap(env, argv[PARAM1], reinterpret_cast<void **>(&cameraDeviceNapi));
        if (status != napi_ok || cameraDeviceNapi == nullptr) {
            MEDIA_ERR_LOG("Could not able to read cameraDevice argument!");
            return undefinedResult;
        }

        napi_ref callbackRef;
        napi_create_reference(env, argv[PARAM2], refCount, &callbackRef);

        obj->RegisterCallback(env, eventType, callbackRef);
    }

    return undefinedResult;
}
} // namespace CameraStandard
} // namespace OHOS
