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

#include "output/preview_output_napi.h"

#include <cstdint>
#include <memory>
#include <string>
#include <unistd.h>
#include <uv.h>

#include "camera_error_code.h"
#include "camera_napi_const.h"
#include "camera_napi_object_types.h"
#include "camera_napi_param_parser.h"
#include "camera_napi_security_utils.h"
#include "camera_napi_template_utils.h"
#include "camera_napi_utils.h"
#include "camera_napi_worker_queue_keeper.h"
#include "camera_output_capability.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "listener_base.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "preview_output.h"
#include "refbase.h"
#include "surface_utils.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
namespace {
sptr<Surface> GetSurfaceFromSurfaceId(napi_env env, std::string& surfaceId)
{
    MEDIA_DEBUG_LOG("GetSurfaceFromSurfaceId enter");
    char *ptr;
    uint64_t iSurfaceId = std::strtoull(surfaceId.c_str(), &ptr, 10);
    MEDIA_INFO_LOG("GetSurfaceFromSurfaceId surfaceId %{public}" PRIu64, iSurfaceId);

    return SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
}

void AsyncCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto context = static_cast<PreviewOutputAsyncContext*>(data);
    CHECK_ERROR_RETURN_LOG(context == nullptr, "PreviewOutputNapi AsyncCompleteCallback context is null");
    MEDIA_INFO_LOG("PreviewOutputNapi AsyncCompleteCallback %{public}s, status = %{public}d", context->funcName.c_str(),
        context->status);
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = context->status;
    if (!context->status) {
        CameraNapiUtils::CreateNapiErrorObject(env, context->errorCode, context->errorMsg.c_str(), jsContext);
    } else {
        napi_get_undefined(env, &jsContext->data);
    }
    if (!context->funcName.empty() && context->taskId > 0) {
        // Finish async trace
        CAMERA_FINISH_ASYNC_TRACE(context->funcName, context->taskId);
        jsContext->funcName = context->funcName;
    }
    if (context->work != nullptr) {
        CameraNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    context->FreeHeldNapiValue(env);
    delete context;
}
} // namespace

thread_local napi_ref PreviewOutputNapi::sConstructor_ = nullptr;
thread_local sptr<PreviewOutput> PreviewOutputNapi::sPreviewOutput_ = nullptr;
thread_local uint32_t PreviewOutputNapi::previewOutputTaskId = CAMERA_PREVIEW_OUTPUT_TASKID;

PreviewOutputCallback::PreviewOutputCallback(napi_env env) : ListenerBase(env) {}

void PreviewOutputCallback::UpdateJSCallbackAsync(PreviewOutputEventType eventType, const int32_t value) const
{
    MEDIA_DEBUG_LOG("UpdateJSCallbackAsync is called");
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
    std::unique_ptr<PreviewOutputCallbackInfo> callbackInfo =
        std::make_unique<PreviewOutputCallbackInfo>(eventType, value, shared_from_this());
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        PreviewOutputCallbackInfo* callbackInfo = reinterpret_cast<PreviewOutputCallbackInfo *>(work->data);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            if (listener) {
                listener->UpdateJSCallback(callbackInfo->eventType_, callbackInfo->value_);
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

void PreviewOutputCallback::OnFrameStarted() const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnFrameStarted is called");
    UpdateJSCallbackAsync(PreviewOutputEventType::PREVIEW_FRAME_START, -1);
}

void PreviewOutputCallback::OnFrameEnded(const int32_t frameCount) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnFrameEnded is called, frameCount: %{public}d", frameCount);
    UpdateJSCallbackAsync(PreviewOutputEventType::PREVIEW_FRAME_END, frameCount);
}

void PreviewOutputCallback::OnError(const int32_t errorCode) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnError is called, errorCode: %{public}d", errorCode);
    UpdateJSCallbackAsync(PreviewOutputEventType::PREVIEW_FRAME_ERROR, errorCode);
}

void PreviewOutputCallback::OnSketchStatusDataChangedAsync(SketchStatusData statusData) const
{
    MEDIA_DEBUG_LOG("OnSketchStatusChangedAsync is called");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("failed to get event loop");
        return;
    }
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("failed to allocate work");
        return;
    }
    std::unique_ptr<SketchStatusCallbackInfo> callbackInfo =
        std::make_unique<SketchStatusCallbackInfo>(statusData, shared_from_this(), env_);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {},
        [](uv_work_t* work, int status) {
            SketchStatusCallbackInfo* callbackInfo = reinterpret_cast<SketchStatusCallbackInfo*>(work->data);
            if (callbackInfo) {
                auto listener = callbackInfo->listener_.lock();
                if (listener) {
                    napi_handle_scope scope = nullptr;
                    napi_open_handle_scope(callbackInfo->env_, &scope);
                    listener->OnSketchStatusDataChangedCall(callbackInfo->sketchStatusData_);
                    napi_close_handle_scope(callbackInfo->env_, scope);
                }
                delete callbackInfo;
            }
            delete work;
        },
        uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void PreviewOutputCallback::OnSketchStatusDataChangedCall(SketchStatusData sketchStatusData) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnSketchStatusChangedCall is called");
    napi_value args[ARGS_TWO];
    napi_value retVal;
    napi_get_undefined(env_, &args[PARAM0]);
    napi_value napiSketchStatus;
    napi_value napiSketchStatusKey;
    napi_value napiSketchRatio;
    napi_value napiSketchRatioKey;
    napi_value callbackObj;
    napi_create_object(env_, &callbackObj);
    napi_create_string_utf8(env_, "status", NAPI_AUTO_LENGTH, &napiSketchStatusKey);
    napi_create_int32(env_, static_cast<int32_t>(sketchStatusData.status), &napiSketchStatus);
    napi_set_property(env_, callbackObj, napiSketchStatusKey, napiSketchStatus);
    napi_create_string_utf8(env_, "sketchRatio", NAPI_AUTO_LENGTH, &napiSketchRatioKey);
    napi_create_double(env_, sketchStatusData.sketchRatio, &napiSketchRatio);
    napi_set_property(env_, callbackObj, napiSketchRatioKey, napiSketchRatio);
    args[PARAM1] = callbackObj;

    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = args, .result = &retVal };
    ExecuteCallback(CONST_SKETCH_STATUS_CHANGED, callbackNapiPara);
}

void PreviewOutputCallback::OnSketchStatusDataChanged(const SketchStatusData& statusData) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnSketchStatusDataChanged is called");
    OnSketchStatusDataChangedAsync(statusData);
}

void PreviewOutputCallback::UpdateJSCallback(PreviewOutputEventType eventType, const int32_t value) const
{
    MEDIA_DEBUG_LOG("UpdateJSCallback is called");
    napi_value result[ARGS_ONE];
    napi_value retVal;
    napi_value propValue;
    napi_get_undefined(env_, &result[PARAM0]);
    std::string eventName = PreviewOutputEventTypeHelper.GetKeyString(eventType);
    if (eventName.empty()) {
        MEDIA_WARNING_LOG(
            "PreviewOutputCallback::UpdateJSCallback, event type is invalid %d", static_cast<int32_t>(eventType));
        return;
    }

    if (eventType == PreviewOutputEventType::PREVIEW_FRAME_ERROR) {
        napi_create_object(env_, &result[PARAM0]);
        napi_create_int32(env_, value, &propValue);
        napi_set_named_property(env_, result[PARAM0], "code", propValue);
    }
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_ONE, .argv = result, .result = &retVal };
    ExecuteCallback(eventName, callbackNapiPara);
}

PreviewOutputNapi::PreviewOutputNapi() : env_(nullptr) {}

PreviewOutputNapi::~PreviewOutputNapi()
{
    MEDIA_DEBUG_LOG("~PreviewOutputNapi is called");
}

void PreviewOutputNapi::PreviewOutputNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("PreviewOutputNapiDestructor is called");
    PreviewOutputNapi* cameraObj = reinterpret_cast<PreviewOutputNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}

napi_value PreviewOutputNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor preview_output_props[] = {
        DECLARE_NAPI_FUNCTION("addDeferredSurface", AddDeferredSurface),
        DECLARE_NAPI_FUNCTION("start", Start),
        DECLARE_NAPI_FUNCTION("stop", Stop),
        DECLARE_NAPI_FUNCTION("release", Release),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("once", Once),
        DECLARE_NAPI_FUNCTION("off", Off),
        DECLARE_NAPI_FUNCTION("isSketchSupported", IsSketchSupported),
        DECLARE_NAPI_FUNCTION("getSketchRatio", GetSketchRatio),
        DECLARE_NAPI_FUNCTION("enableSketch", EnableSketch),
        DECLARE_NAPI_FUNCTION("attachSketchSurface", AttachSketchSurface),
        DECLARE_NAPI_FUNCTION("setFrameRate", SetFrameRate),
        DECLARE_NAPI_FUNCTION("getActiveFrameRate", GetActiveFrameRate),
        DECLARE_NAPI_FUNCTION("getSupportedFrameRates", GetSupportedFrameRates),
        DECLARE_NAPI_FUNCTION("getActiveProfile", GetActiveProfile),
        DECLARE_NAPI_FUNCTION("getPreviewRotation", GetPreviewRotation),
        DECLARE_NAPI_FUNCTION("setPreviewRotation", SetPreviewRotation)
    };

    status = napi_define_class(env, CAMERA_PREVIEW_OUTPUT_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               PreviewOutputNapiConstructor, nullptr,
                               sizeof(preview_output_props) / sizeof(preview_output_props[PARAM0]),
                               preview_output_props, &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_PREVIEW_OUTPUT_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

// Constructor callback
napi_value PreviewOutputNapi::PreviewOutputNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PreviewOutputNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<PreviewOutputNapi> obj = std::make_unique<PreviewOutputNapi>();
        if (obj != nullptr) {
            obj->env_ = env;
            obj->previewOutput_ = sPreviewOutput_;

            status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                PreviewOutputNapi::PreviewOutputNapiDestructor, nullptr, nullptr);
            if (status == napi_ok) {
                obj.release();
                return thisVar;
            } else {
                MEDIA_ERR_LOG("Failure wrapping js to native napi");
            }
        }
    }
    MEDIA_ERR_LOG("PreviewOutputNapiConstructor call Failed!");
    return result;
}

napi_value PreviewOutputNapi::CreateDeferredPreviewOutput(napi_env env, Profile& profile)
{
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sPreviewOutput_ = CameraManager::GetInstance()->CreateDeferredPreviewOutput(profile);
        if (sPreviewOutput_ == nullptr) {
            MEDIA_ERR_LOG("failed to create previewOutput");
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sPreviewOutput_ = nullptr;

        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create preview output instance");
        }
    }

    napi_get_undefined(env, &result);
    return result;
}

napi_value PreviewOutputNapi::CreatePreviewOutput(napi_env env, Profile& profile, std::string surfaceId)
{
    MEDIA_INFO_LOG("CreatePreviewOutput is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        uint64_t iSurfaceId;
        std::istringstream iss(surfaceId);
        iss >> iSurfaceId;
        sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
        if (!surface) {
            surface = Media::ImageReceiver::getSurfaceById(surfaceId);
        }
        if (surface == nullptr) {
            MEDIA_ERR_LOG("failed to get surface");
            return result;
        }

        surface->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
        int retCode = CameraManager::GetInstance()->CreatePreviewOutput(profile, surface, &sPreviewOutput_);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        if (sPreviewOutput_ == nullptr) {
            MEDIA_ERR_LOG("failed to create previewOutput");
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sPreviewOutput_ = nullptr;

        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create preview output instance");
        }
    }
    MEDIA_ERR_LOG("CreatePreviewOutput call Failed!");
    napi_get_undefined(env, &result);
    return result;
}

napi_value PreviewOutputNapi::CreatePreviewOutput(napi_env env, std::string surfaceId)
{
    MEDIA_INFO_LOG("CreatePreviewOutput with only surfaceId is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        uint64_t iSurfaceId;
        std::istringstream iss(surfaceId);
        iss >> iSurfaceId;
        sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
        if (!surface) {
            surface = Media::ImageReceiver::getSurfaceById(surfaceId);
        }
        if (surface == nullptr) {
            MEDIA_ERR_LOG("failed to get surface");
            return result;
        }
        int retCode = CameraManager::GetInstance()->CreatePreviewOutputWithoutProfile(surface, &sPreviewOutput_);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        if (sPreviewOutput_ == nullptr) {
            MEDIA_ERR_LOG("failed to create previewOutput");
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sPreviewOutput_ = nullptr;

        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create preview output instance");
        }
    }
    MEDIA_ERR_LOG("CreatePreviewOutput call Failed!");
    napi_get_undefined(env, &result);
    return result;
}

sptr<PreviewOutput> PreviewOutputNapi::GetPreviewOutput()
{
    return previewOutput_;
}

bool PreviewOutputNapi::IsPreviewOutput(napi_env env, napi_value obj)
{
    MEDIA_DEBUG_LOG("IsPreviewOutput is called");
    bool result = false;
    napi_status status;
    napi_value constructor = nullptr;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        status = napi_instanceof(env, obj, constructor, &result);
        if (status != napi_ok) {
            result = false;
        }
    }
    return result;
}

napi_value PreviewOutputNapi::GetActiveProfile(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PreviewOutputNapi::GetActiveProfile is called");
    PreviewOutputNapi* previewOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, previewOutputNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("PreviewOutputNapi::GetActiveProfile parse parameter occur error");
        return nullptr;
    }
    auto profile = previewOutputNapi->previewOutput_->GetPreviewProfile();
    if (profile == nullptr) {
        return CameraNapiUtils::GetUndefinedValue(env);
    }
    return CameraNapiObjProfile(*profile).GenerateNapiValue(env);
}

napi_value PreviewOutputNapi::Release(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("PreviewOutputNapi::Release is called");
    std::unique_ptr<PreviewOutputAsyncContext> asyncContext = std::make_unique<PreviewOutputAsyncContext>(
        "PreviewOutputNapi::Release", CameraNapiUtils::IncrementAndGet(previewOutputTaskId));
    auto asyncFunction =
        std::make_shared<CameraNapiAsyncFunction>(env, "Release", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("PreviewOutputNapi::Release invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("PreviewOutputNapi::Release running on worker");
            auto context = static_cast<PreviewOutputAsyncContext*>(data);
            CHECK_ERROR_RETURN_LOG(context->objectInfo == nullptr, "PreviewOutputNapi::Release async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
                context->errorCode = context->objectInfo->previewOutput_->Release();
                context->status = context->errorCode == CameraErrorCode::SUCCESS;
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for PreviewOutputNapi::Release");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("PreviewOutputNapi::Release");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value PreviewOutputNapi::AddDeferredSurface(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("AddDeferredSurface is called");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi AddDeferredSurface is called!");
        return nullptr;
    }

    PreviewOutputNapi* previewOutputNapi;
    std::string surfaceId;
    CameraNapiParamParser jsParamParser(env, info, previewOutputNapi, surfaceId);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("CameraInputNapi::AddDeferredSurface invalid argument");
        return nullptr;
    }

    uint64_t iSurfaceId;
    std::istringstream iss(surfaceId);
    iss >> iSurfaceId;
    sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
    if (!surface) {
        surface = Media::ImageReceiver::getSurfaceById(surfaceId);
    }
    if (surface == nullptr) {
        MEDIA_ERR_LOG("CameraInputNapi::AddDeferredSurface failed to get surface");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "invalid argument surface get fail");
        return nullptr;
    }
    auto previewProfile = previewOutputNapi->previewOutput_->GetPreviewProfile();
    if (previewProfile != nullptr) {
        surface->SetUserData(CameraManager::surfaceFormat, std::to_string(previewProfile->GetCameraFormat()));
    }
    previewOutputNapi->previewOutput_->AddDeferredSurface(surface);
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value PreviewOutputNapi::Start(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Start is called");
    std::unique_ptr<PreviewOutputAsyncContext> asyncContext = std::make_unique<PreviewOutputAsyncContext>(
        "PreviewOutputNapi::Start", CameraNapiUtils::IncrementAndGet(previewOutputTaskId));
    auto asyncFunction =
        std::make_shared<CameraNapiAsyncFunction>(env, "Start", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("PreviewOutputNapi::Start invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("PreviewOutputNapi::Start running on worker");
            auto context = static_cast<PreviewOutputAsyncContext*>(data);
            CHECK_ERROR_RETURN_LOG(context->objectInfo == nullptr, "PreviewOutputNapi::Start async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
                context->errorCode = context->objectInfo->previewOutput_->Start();
                context->status = context->errorCode == CameraErrorCode::SUCCESS;
                MEDIA_INFO_LOG("PreviewOutputNapi::Start errorCode:%{public}d", context->errorCode);
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for PreviewOutputNapi::Start");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("PreviewOutputNapi::Start");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value PreviewOutputNapi::Stop(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Stop is called");
    std::unique_ptr<PreviewOutputAsyncContext> asyncContext = std::make_unique<PreviewOutputAsyncContext>(
        "PreviewOutputNapi::Stop", CameraNapiUtils::IncrementAndGet(previewOutputTaskId));
    auto asyncFunction =
        std::make_shared<CameraNapiAsyncFunction>(env, "Stop", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("PreviewOutputNapi::Stop invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("PreviewOutputNapi::Stop running on worker");
            auto context = static_cast<PreviewOutputAsyncContext*>(data);
            CHECK_ERROR_RETURN_LOG(context->objectInfo == nullptr, "PreviewOutputNapi::Stop async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
                context->errorCode = context->objectInfo->previewOutput_->Stop();
                context->status = context->errorCode == CameraErrorCode::SUCCESS;
                MEDIA_INFO_LOG("PreviewOutputNapi::Stop errorCode:%{public}d", context->errorCode);
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for PreviewOutputNapi::Stop");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("PreviewOutputNapi::Stop");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

void PreviewOutputNapi::RegisterFrameStartCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (previewCallback_ == nullptr) {
        previewCallback_ = std::make_shared<PreviewOutputCallback>(env);
        previewOutput_->SetCallback(previewCallback_);
    }
    previewCallback_->SaveCallbackReference(CONST_PREVIEW_FRAME_START, callback, isOnce);
}

void PreviewOutputNapi::UnregisterFrameStartCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (previewCallback_ == nullptr) {
        MEDIA_ERR_LOG("previewCallback is null");
        return;
    }
    previewCallback_->RemoveCallbackRef(CONST_PREVIEW_FRAME_START, callback);
}

void PreviewOutputNapi::RegisterFrameEndCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (previewCallback_ == nullptr) {
        previewCallback_ = std::make_shared<PreviewOutputCallback>(env);
        previewOutput_->SetCallback(previewCallback_);
    }
    previewCallback_->SaveCallbackReference(CONST_PREVIEW_FRAME_END, callback, isOnce);
}
void PreviewOutputNapi::UnregisterFrameEndCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (previewCallback_ == nullptr) {
        MEDIA_ERR_LOG("previewCallback is null");
        return;
    }
    previewCallback_->RemoveCallbackRef(CONST_PREVIEW_FRAME_END, callback);
}

void PreviewOutputNapi::RegisterErrorCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (previewCallback_ == nullptr) {
        previewCallback_ = std::make_shared<PreviewOutputCallback>(env);
        previewOutput_->SetCallback(previewCallback_);
    }
    previewCallback_->SaveCallbackReference(CONST_PREVIEW_FRAME_ERROR, callback, isOnce);
}

void PreviewOutputNapi::UnregisterErrorCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (previewCallback_ == nullptr) {
        MEDIA_ERR_LOG("previewCallback is null");
        return;
    }
    previewCallback_->RemoveCallbackRef(CONST_PREVIEW_FRAME_ERROR, callback);
}

void PreviewOutputNapi::RegisterSketchStatusChangedCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi On sketchStatusChanged is called!");
        return;
    }
    if (previewCallback_ == nullptr) {
        previewCallback_ = std::make_shared<PreviewOutputCallback>(env);
        previewOutput_->SetCallback(previewCallback_);
    }
    previewCallback_->SaveCallbackReference(CONST_SKETCH_STATUS_CHANGED, callback, isOnce);
    previewOutput_->OnNativeRegisterCallback(CONST_SKETCH_STATUS_CHANGED);
}

void PreviewOutputNapi::UnregisterSketchStatusChangedCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi Off sketchStatusChanged is called!");
        return;
    }
    if (previewCallback_ == nullptr) {
        MEDIA_ERR_LOG("previewCallback is null");
        return;
    }
    previewCallback_->RemoveCallbackRef(CONST_SKETCH_STATUS_CHANGED, callback);
    previewOutput_->OnNativeUnregisterCallback(CONST_SKETCH_STATUS_CHANGED);
}

const PreviewOutputNapi::EmitterFunctions& PreviewOutputNapi::GetEmitterFunctions()
{
    static const EmitterFunctions funMap = {
        { CONST_PREVIEW_FRAME_START, {
            &PreviewOutputNapi::RegisterFrameStartCallbackListener,
            &PreviewOutputNapi::UnregisterFrameStartCallbackListener } },
        { CONST_PREVIEW_FRAME_END, {
            &PreviewOutputNapi::RegisterFrameEndCallbackListener,
            &PreviewOutputNapi::UnregisterFrameEndCallbackListener } },
        { CONST_PREVIEW_FRAME_ERROR, {
            &PreviewOutputNapi::RegisterErrorCallbackListener,
            &PreviewOutputNapi::UnregisterErrorCallbackListener } },
        { CONST_SKETCH_STATUS_CHANGED, {
            &PreviewOutputNapi::RegisterSketchStatusChangedCallbackListener,
            &PreviewOutputNapi::UnregisterSketchStatusChangedCallbackListener } } };
    return funMap;
}

napi_value PreviewOutputNapi::IsSketchSupported(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsSketchSupported is called!");
        return nullptr;
    }
    MEDIA_INFO_LOG("PreviewOutputNapi::IsSketchSupported is called");
    PreviewOutputNapi* previewOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, previewOutputNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("PreviewOutputNapi::IsSketchSupported parse parameter occur error");
        return nullptr;
    }

    bool isSupported = previewOutputNapi->previewOutput_->IsSketchSupported();
    return CameraNapiUtils::GetBooleanValue(env, isSupported);
}

napi_value PreviewOutputNapi::GetSketchRatio(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetSketchRatio is called!");
        return nullptr;
    }
    MEDIA_INFO_LOG("PreviewOutputNapi::GetSketchRatio is called");
    PreviewOutputNapi* previewOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, previewOutputNapi);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("PreviewOutputNapi::GetSketchRatio parse parameter occur error");
        return nullptr;
    }
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    float ratio = previewOutputNapi->previewOutput_->GetSketchRatio();
    napi_create_double(env, ratio, &result);
    return result;
}

napi_value PreviewOutputNapi::EnableSketch(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PreviewOutputNapi::EnableSketch enter");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi EnableSketch is called!");
        return nullptr;
    }

    bool isEnableSketch;
    PreviewOutputNapi* previewOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, previewOutputNapi, isEnableSketch);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("PreviewOutputNapi::EnableSketch parse parameter occur error");
        return nullptr;
    }

    int32_t retCode = previewOutputNapi->previewOutput_->EnableSketch(isEnableSketch);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("PreviewOutputNapi::EnableSketch fail! %{public}d", retCode);
        return nullptr;
    }
    MEDIA_DEBUG_LOG("PreviewOutputNapi::EnableSketch success");
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value PreviewOutputNapi::GetPreviewRotation(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetPreviewRotation is called!");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PreviewOutputNapi* previewOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&previewOutputNapi));
    if (status == napi_ok && previewOutputNapi != nullptr) {
        int32_t value;
        napi_status ret = napi_get_value_int32(env, argv[PARAM0], &value);
        if (ret != napi_ok) {
            CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT,
                "GetPreviewRotation parameter missing or parameter type incorrect.");
            return result;
        }
        int32_t retCode = previewOutputNapi->previewOutput_->GetPreviewRotation(value);
        if (retCode == SERVICE_FATL_ERROR) {
            CameraNapiUtils::ThrowError(env, SERVICE_FATL_ERROR,
                "GetPreviewRotation Camera service fatal error.");
            return result;
        }
        napi_create_int32(env, retCode, &result);
        MEDIA_INFO_LOG("PreviewOutputNapi GetPreviewRotation! %{public}d", retCode);
    } else {
        MEDIA_ERR_LOG("PreviewOutputNapi GetPreviewRotation! called failed!");
    }
    return result;
}

napi_value PreviewOutputNapi::SetPreviewRotation(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetPreviewRotation is called!");
    PreviewOutputNapi* previewOutputNapi = nullptr;
    int32_t imageRotation;
    bool isDisplayLocked;
    int32_t retCode;
    CameraNapiParamParser jsParamParser(env, info, previewOutputNapi, imageRotation, isDisplayLocked);
    if (jsParamParser.IsStatusOk()) {
        MEDIA_INFO_LOG("PreviewOutputNapi SetPreviewRotation! %{public}d", imageRotation);
    } else {
        MEDIA_WARNING_LOG("PreviewOutputNapi SetPreviewRotation without isDisplayLocked flag!");
        jsParamParser = CameraNapiParamParser(env, info, previewOutputNapi, imageRotation);
        isDisplayLocked = false;
    }
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("PreviewOutputNapi::SetPreviewRotation invalid argument");
        return nullptr;
    }
    if (previewOutputNapi->previewOutput_ == nullptr) {
        MEDIA_ERR_LOG("PreviewOutputNapi::SetPreviewRotation get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return nullptr;
    }
    retCode = previewOutputNapi->previewOutput_->SetPreviewRotation(imageRotation, isDisplayLocked);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("PreviewOutputNapi::SetPreviewRotation! %{public}d", retCode);
        return nullptr;
    }
    MEDIA_DEBUG_LOG("PreviewOutputNapi::SetPreviewRotation success");
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value PreviewOutputNapi::AttachSketchSurface(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PreviewOutputNapi::AttachSketchSurface enter");
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi AttachSketchSurface is called!");
        return nullptr;
    }

    std::string surfaceId;
    PreviewOutputNapi* previewOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, previewOutputNapi, surfaceId);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error")) {
        MEDIA_ERR_LOG("PreviewOutputNapi::AttachSketchSurface parse parameter occur error");
        return nullptr;
    }

    sptr<Surface> surface = GetSurfaceFromSurfaceId(env, surfaceId);
    if (surface == nullptr) {
        MEDIA_ERR_LOG("PreviewOutputNapi::AttachSketchSurface get surface is null");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "input surface convert fail");
        return nullptr;
    }

    int32_t retCode = previewOutputNapi->previewOutput_->AttachSketchSurface(surface);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("PreviewOutputNapi::AttachSketchSurface! %{public}d", retCode);
        return nullptr;
    }
    MEDIA_DEBUG_LOG("PreviewOutputNapi::AttachSketchSurface success");
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value PreviewOutputNapi::SetFrameRate(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetFrameRate is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
 
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
 
    napi_get_undefined(env, &result);
    PreviewOutputNapi* previewOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&previewOutputNapi));
    if (status == napi_ok && previewOutputNapi != nullptr) {
        int32_t minFrameRate;
        napi_get_value_int32(env, argv[PARAM0], &minFrameRate);
        int32_t maxFrameRate;
        napi_get_value_int32(env, argv[PARAM1], &maxFrameRate);
        int32_t retCode = previewOutputNapi->previewOutput_->SetFrameRate(minFrameRate, maxFrameRate);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            MEDIA_ERR_LOG("PreviewOutputNapi::SetFrameRate! %{public}d", retCode);
            return result;
        }
    } else {
        MEDIA_ERR_LOG("SetFrameRate call Failed!");
    }
    return result;
}
 
napi_value PreviewOutputNapi::GetActiveFrameRate(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetFrameRate is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
 
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ZERO), "requires no parameter.");
 
    napi_get_undefined(env, &result);
    PreviewOutputNapi* previewOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&previewOutputNapi));
    if (status == napi_ok && previewOutputNapi != nullptr) {
        std::vector<int32_t> frameRateRange = previewOutputNapi->previewOutput_->GetFrameRateRange();
        CameraNapiUtils::CreateFrameRateJSArray(env, frameRateRange, result);
    } else {
        MEDIA_ERR_LOG("GetFrameRate call failed!");
    }
    return result;
}
 
napi_value PreviewOutputNapi::GetSupportedFrameRates(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedFrameRates is called");
 
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
 
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ZERO), "requires no parameter.");
    napi_get_undefined(env, &result);
    PreviewOutputNapi* previewOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&previewOutputNapi));
    if (status == napi_ok && previewOutputNapi != nullptr) {
        std::vector<std::vector<int32_t>> supportedFrameRatesRange =
                                          previewOutputNapi->previewOutput_->GetSupportedFrameRates();
        result = CameraNapiUtils::CreateSupportFrameRatesJSArray(env, supportedFrameRatesRange);
    } else {
        MEDIA_ERR_LOG("GetSupportedFrameRates call failed!");
    }
    return result;
}

napi_value PreviewOutputNapi::On(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<PreviewOutputNapi>::On(env, info);
}

napi_value PreviewOutputNapi::Once(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<PreviewOutputNapi>::Once(env, info);
}

napi_value PreviewOutputNapi::Off(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<PreviewOutputNapi>::Off(env, info);
}
} // namespace CameraStandard
} // namespace OHOS
