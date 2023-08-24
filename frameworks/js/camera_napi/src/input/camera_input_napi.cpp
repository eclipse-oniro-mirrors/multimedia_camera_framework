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
    MEDIA_DEBUG_LOG("OnErrorCallbackAsync is called");
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
    std::unique_ptr<ErrorCallbackInfo> callbackInfo = std::make_unique<ErrorCallbackInfo>(errorType, errorMsg, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        ErrorCallbackInfo* callbackInfo = reinterpret_cast<ErrorCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnErrorCallback(callbackInfo->errorType_, callbackInfo->errorMsg_);
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

void ErrorCallbackListener::OnErrorCallback(const int32_t errorType, const int32_t errorMsg) const
{
    MEDIA_DEBUG_LOG("OnErrorCallback is called");
    napi_value result;
    napi_value callback = nullptr;
    napi_value retVal;
    napi_value propValue;
    for (auto it = cameraInputErrorCbList_.begin(); it != cameraInputErrorCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_create_int32(env, errorType, &propValue);
        napi_create_object(env, &result);
        napi_set_named_property(env, result, "code", propValue);
        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_call_function(env, nullptr, callback, ARGS_ONE, &result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference((*it)->env_, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            cameraInputErrorCbList_.erase(it);
        } else {
            it++;
        }
    }
}

void ErrorCallbackListener::OnError(const int32_t errorType, const int32_t errorMsg) const
{
    MEDIA_DEBUG_LOG("OnError is called!, errorType: %{public}d", errorType);
    OnErrorCallbackAsync(errorType, errorMsg);
}

void ErrorCallbackListener::SaveCallbackReference(const std::string &eventType, napi_value callback, bool isOnce)
{
    std::lock_guard<std::mutex> lock(mutex_);
    napi_ref callbackRef = nullptr;
    const int32_t refCount = 1;

    bool isSameCallback = true;
    for (auto it = cameraInputErrorCbList_.begin(); it != cameraInputErrorCbList_.end(); ++it) {
        isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        CHECK_AND_RETURN_LOG(!isSameCallback, "SaveCallbackReference: has same callback, nothing to do");
    }
    napi_status status = napi_create_reference(env_, callback, refCount, &callbackRef);
    CHECK_AND_RETURN_LOG(status == napi_ok && callbackRef != nullptr,
        "ErrorCallbackListener: creating reference for callback fail");
    std::shared_ptr<AutoRef> cb = std::make_shared<AutoRef>(env_, callbackRef, isOnce);
    cameraInputErrorCbList_.push_back(cb);
    MEDIA_INFO_LOG("Save callback reference success, cameraInput callback list size [%{public}zu]",
        cameraInputErrorCbList_.size());
}

void ErrorCallbackListener::RemoveCallbackRef(napi_env env, napi_value callback)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (callback == nullptr) {
        MEDIA_INFO_LOG("RemoveCallbackReference: js callback is nullptr, remove all callback reference");
        RemoveAllCallbacks();
        return;
    }
    for (auto it = cameraInputErrorCbList_.begin(); it != cameraInputErrorCbList_.end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        if (isSameCallback) {
            MEDIA_INFO_LOG("RemoveCallbackReference: find js callback, delete it");
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            (*it)->cb_ = nullptr;
            CHECK_AND_RETURN_LOG(status == napi_ok, "RemoveCallbackReference: delete reference for callback fail");
            cameraInputErrorCbList_.erase(it);
            return;
        }
    }
    MEDIA_INFO_LOG("RemoveCallbackReference: js callback no find");
}

void ErrorCallbackListener::RemoveAllCallbacks()
{
    for (auto it = cameraInputErrorCbList_.begin(); it != cameraInputErrorCbList_.end(); ++it) {
        napi_delete_reference(env_, (*it)->cb_);
        (*it)->cb_ = nullptr;
    }
    cameraInputErrorCbList_.clear();
    MEDIA_INFO_LOG("RemoveAllCallbacks: remove all js callbacks success");
}

CameraInputNapi::CameraInputNapi() : env_(nullptr), wrapper_(nullptr)
{
}

CameraInputNapi::~CameraInputNapi()
{
    MEDIA_INFO_LOG("~CameraInputNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (cameraInput_) {
        MEDIA_INFO_LOG("~CameraInputNapi cameraInput_ is not null");
        cameraInput_ = nullptr;
    }
}

void CameraInputNapi::CameraInputNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_INFO_LOG("CameraInputNapiDestructor is called");
    CameraInputNapi* cameraObj = reinterpret_cast<CameraInputNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}

napi_value CameraInputNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    // todo: Open and Close in native have not implemented
    napi_property_descriptor camera_input_props[] = {
        DECLARE_NAPI_FUNCTION("open", Open),
        DECLARE_NAPI_FUNCTION("close", Close),
        DECLARE_NAPI_FUNCTION("release", Release),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("once", Once),
        DECLARE_NAPI_FUNCTION("off", Off)
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
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

// Constructor callback
napi_value CameraInputNapi::CameraInputNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CameraInputNapiConstructor is called");
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
    MEDIA_ERR_LOG("CameraInputNapiConstructor call Failed!");
    return result;
}

napi_value CameraInputNapi::CreateCameraInput(napi_env env, sptr<CameraInput> cameraInput)
{
    MEDIA_INFO_LOG("CreateCameraInput is called");
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
    MEDIA_ERR_LOG("CreateCameraInput call Failed!");
    return result;
}

sptr<CameraInput> CameraInputNapi::GetCameraInput()
{
    return cameraInput_;
}

void CommonCompleteCallback(napi_env env, napi_status status, void* data)
{
    MEDIA_DEBUG_LOG("CommonCompleteCallback is called");
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
    MEDIA_INFO_LOG("Open is called");
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
            napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
            asyncContext.release();
        }
    } else {
        MEDIA_ERR_LOG("Open call Failed!");
    }
    return result;
}

napi_value CameraInputNapi::Close(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Close is called");
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
            napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
            asyncContext.release();
        }
    } else {
        MEDIA_ERR_LOG("Close call Failed!");
    }
    return result;
}

napi_value CameraInputNapi::Release(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Release is called");
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
            napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
            asyncContext.release();
        }
    } else {
        MEDIA_ERR_LOG("Release call Failed!");
    }
    return result;
}

napi_value CameraInputNapi::RegisterCallback(napi_env env, napi_value jsThis,
    const string &eventType, napi_value* argv, bool isOnce)
{
    MEDIA_DEBUG_LOG("RegisterCallback is called");
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);
    napi_status status;
    CameraInputNapi* cameraInputNapi = nullptr;
    CameraDeviceNapi* cameraDeviceNapi = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&cameraInputNapi));
    NAPI_ASSERT(env, status == napi_ok && cameraInputNapi != nullptr, "Failed to retrieve cameraInput napi instance.");
    NAPI_ASSERT(env, cameraInputNapi->cameraInput_ != nullptr, "cameraInput instance is null.");
    status = napi_unwrap(env, argv[PARAM1], reinterpret_cast<void**>(&cameraDeviceNapi));
    NAPI_ASSERT(env, status == napi_ok && cameraDeviceNapi != nullptr, "Could not able to read cameraDevice argument!");

    if (eventType.compare("error") == 0) {
        // Set callback for error
        if (cameraInputNapi->errorCallback_ == nullptr) {
            shared_ptr<ErrorCallbackListener> errorCallback = make_shared<ErrorCallbackListener>(env);
            cameraInputNapi->errorCallback_ = errorCallback;
            cameraInputNapi->cameraInput_->SetErrorCallback(errorCallback);
        }
        cameraInputNapi->errorCallback_->SaveCallbackReference(eventType, argv[PARAM2], isOnce);
    } else {
        MEDIA_ERR_LOG("Incorrect callback event type provided for camera input!");
    }
    return undefinedResult;
}

napi_value CameraInputNapi::UnregisterCallback(napi_env env, napi_value jsThis,
    const std::string &eventType, napi_value* argv)
{
    MEDIA_DEBUG_LOG("UnregisterCallback is called");
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);
    CameraDeviceNapi* cameraDeviceNapi = nullptr;
    napi_status status = napi_unwrap(env, argv[PARAM1], reinterpret_cast<void**>(&cameraDeviceNapi));
    NAPI_ASSERT(env, status == napi_ok && cameraDeviceNapi != nullptr, "Could not able to read cameraDevice argument!");
    CameraInputNapi *cameraInputNapi = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&cameraInputNapi));
    NAPI_ASSERT(env, status == napi_ok && cameraInputNapi != nullptr, "Failed to retrieve cameraInput napi instance.");
    NAPI_ASSERT(env, cameraInputNapi->cameraInput_ != nullptr, "cameraInput instance is null.");

    if (eventType.compare("error") == 0) {
        // unset callback for error
        if (cameraInputNapi->errorCallback_ == nullptr) {
            MEDIA_ERR_LOG("errorCallback is null");
        } else {
            cameraInputNapi->errorCallback_->RemoveCallbackRef(env, argv[PARAM2]);
        }
    } else {
        MEDIA_ERR_LOG("Incorrect callback event type provided for camera input!");
    }
    return undefinedResult;
}

napi_value CameraInputNapi::On(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("On is called");
    CAMERA_SYNC_TRACE;
    napi_value undefinedResult = nullptr;
    size_t argCount = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {nullptr, nullptr, nullptr};
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);

    CAMERA_NAPI_GET_JS_ARGS(env, info, argCount, argv, thisVar);

    NAPI_ASSERT(env, argCount == ARGS_THREE, "requires 3 parameters");

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string
        || napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_object
        || napi_typeof(env, argv[PARAM2], &valueType) != napi_ok || valueType != napi_function) {
        return undefinedResult;
    }

    std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[PARAM0]);
    MEDIA_INFO_LOG("On eventType: %{public}s", eventType.c_str());
    return RegisterCallback(env, thisVar, eventType, argv, false);
}

napi_value CameraInputNapi::Once(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Once is called");
    CAMERA_SYNC_TRACE;
    napi_value undefinedResult = nullptr;
    size_t argCount = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {nullptr, nullptr, nullptr};
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);

    CAMERA_NAPI_GET_JS_ARGS(env, info, argCount, argv, thisVar);

    NAPI_ASSERT(env, argCount == ARGS_THREE, "requires 3 parameters");

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string
        || napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_object
        || napi_typeof(env, argv[PARAM2], &valueType) != napi_ok || valueType != napi_function) {
        return undefinedResult;
    }

    std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[PARAM0]);
    MEDIA_INFO_LOG("Once eventType: %{public}s", eventType.c_str());
    return RegisterCallback(env, thisVar, eventType, argv, true);
}

napi_value CameraInputNapi::Off(napi_env env, napi_callback_info info)
{
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);
    const size_t minArgCount = 2;
    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {nullptr, nullptr, nullptr};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (argc < minArgCount) {
        return undefinedResult;
    }

    napi_valuetype valueType = napi_undefined;
    if ((napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string
        || napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_object
        || (argc > minArgCount &&
            (napi_typeof(env, argv[PARAM2], &valueType) != napi_ok || valueType != napi_function)))) {
        return undefinedResult;
    }

    std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[PARAM0]);
    MEDIA_INFO_LOG("Off eventType: %{public}s", eventType.c_str());
    return UnregisterCallback(env, thisVar, eventType, argv);
}
} // namespace CameraStandard
} // namespace OHOS
