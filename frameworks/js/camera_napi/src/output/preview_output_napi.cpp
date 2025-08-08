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
#include <uv.h>

#include "camera_error_code.h"
#include "camera_log.h"
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
#include "napi/native_node_api.h"
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
    auto previewOutputAsyncContext = static_cast<PreviewOutputAsyncContext*>(data);
    CHECK_ERROR_RETURN_LOG(previewOutputAsyncContext == nullptr,
        "PreviewOutputNapi AsyncCompleteCallback context is null");
    MEDIA_INFO_LOG("PreviewOutputNapi AsyncCompleteCallback %{public}s, status = %{public}d",
        previewOutputAsyncContext->funcName.c_str(), previewOutputAsyncContext->status);
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = previewOutputAsyncContext->status;
    if (!previewOutputAsyncContext->status) {
        CameraNapiUtils::CreateNapiErrorObject(env, previewOutputAsyncContext->errorCode,
            previewOutputAsyncContext->errorMsg.c_str(), jsContext);
    } else {
        napi_get_undefined(env, &jsContext->data);
    }
    if (!previewOutputAsyncContext->funcName.empty() && previewOutputAsyncContext->taskId > 0) {
        // Finish async trace
        CAMERA_FINISH_ASYNC_TRACE(previewOutputAsyncContext->funcName, previewOutputAsyncContext->taskId);
        jsContext->funcName = previewOutputAsyncContext->funcName;
    }
    CHECK_EXECUTE(previewOutputAsyncContext->work != nullptr,
        CameraNapiUtils::InvokeJSAsyncMethod(env, previewOutputAsyncContext->deferred,
            previewOutputAsyncContext->callbackRef, previewOutputAsyncContext->work, *jsContext));
    previewOutputAsyncContext->FreeHeldNapiValue(env);
    delete previewOutputAsyncContext;
}
} // namespace

thread_local napi_ref PreviewOutputNapi::sConstructor_ = nullptr;
thread_local sptr<PreviewOutput> PreviewOutputNapi::sPreviewOutput_ = nullptr;
thread_local uint32_t PreviewOutputNapi::previewOutputTaskId = CAMERA_PREVIEW_OUTPUT_TASKID;

PreviewOutputCallback::PreviewOutputCallback(napi_env env) : ListenerBase(env) {}

void PreviewOutputCallback::UpdateJSCallbackAsync(PreviewOutputEventType eventType, const int32_t value) const
{
    MEDIA_DEBUG_LOG("UpdateJSCallbackAsync is called");
    std::unique_ptr<PreviewOutputCallbackInfo> callbackInfo =
        std::make_unique<PreviewOutputCallbackInfo>(eventType, value, shared_from_this());
    PreviewOutputCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        PreviewOutputCallbackInfo* callbackInfo = reinterpret_cast<PreviewOutputCallbackInfo *>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            CHECK_EXECUTE(listener, listener->UpdateJSCallback(callbackInfo->eventType_, callbackInfo->value_));
            delete callbackInfo;
        }
    };
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        MEDIA_ERR_LOG("failed to execute work");
    } else {
        callbackInfo.release();
    }
}

void PreviewOutputCallback::OnFrameStarted() const
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("OnFrameStarted is called");
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
    std::shared_ptr<SketchStatusCallbackInfo> callbackInfo =
        std::make_shared<SketchStatusCallbackInfo>(statusData, shared_from_this(), env_);
    auto task = [callbackInfo]() {
        auto listener = callbackInfo->listener_.lock();
        if (listener) {
            listener->OnSketchStatusDataChangedCall(callbackInfo->sketchStatusData_);
        }
    };
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        MEDIA_ERR_LOG("PreviewOutputCallback::OnSketchStatusDataChangedAsync failed to execute work");
    }
}

void PreviewOutputCallback::OnSketchStatusDataChangedCall(SketchStatusData sketchStatusData) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnSketchStatusChangedCall is called");
    ExecuteCallbackScopeSafe(CONST_SKETCH_STATUS_CHANGED, [&]() {
        napi_value errCode = CameraNapiUtils::GetUndefinedValue(env_);
        napi_value callbackObj;
        CameraNapiObject sketchObj {{
            { "status", reinterpret_cast<int32_t*>(&sketchStatusData.status) },
            { "sketchRatio", &sketchStatusData.sketchRatio }
        }};
        callbackObj = sketchObj.CreateNapiObjFromMap(env_);
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
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
    std::string eventName = PreviewOutputEventTypeHelper.GetKeyString(eventType);
    if (eventName.empty()) {
        MEDIA_WARNING_LOG(
            "PreviewOutputCallback::UpdateJSCallback, event type is invalid %d", static_cast<int32_t>(eventType));
        return;
    }
    int32_t nonConstValue = value;
    ExecuteCallbackScopeSafe(eventName, [&]() {
        napi_value errCode = CameraNapiUtils::GetUndefinedValue(env_);
        napi_value callbackObj = CameraNapiUtils::GetUndefinedValue(env_);
        if (eventType == PreviewOutputEventType::PREVIEW_FRAME_ERROR) {
            CameraNapiObject errObj { { { "code", &nonConstValue } } };
            errCode = errObj.CreateNapiObjFromMap(env_);
        }
        return ExecuteCallbackData(env_, errCode, callbackObj);
    });
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
            CHECK_ERROR_RETURN_RET(status == napi_ok, exports);
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
        CHECK_ERROR_RETURN_RET_LOG(sPreviewOutput_ == nullptr, result, "failed to create previewOutput");
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
    MEDIA_INFO_LOG("PreviewOutputNapi::CreatePreviewOutput is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        uint64_t iSurfaceId;
        std::istringstream iStringStream(surfaceId);
        iStringStream >> iSurfaceId;
        sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
        if (!surface) {
            surface = Media::ImageReceiver::getSurfaceById(surfaceId);
        }
        CHECK_ERROR_RETURN_RET_LOG(surface == nullptr, result,
            "PreviewOutputNapi::CreatePreviewOutput failed to get surface");

        surface->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
        int retCode = CameraManager::GetInstance()->CreatePreviewOutput(profile, surface, &sPreviewOutput_);
        CHECK_ERROR_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        CHECK_ERROR_RETURN_RET_LOG(sPreviewOutput_ == nullptr, result,
            "PreviewOutputNapi::CreatePreviewOutput failed to create previewOutput");
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sPreviewOutput_ = nullptr;

        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("PreviewOutputNapi::CreatePreviewOutput Failed to create preview output instance");
        }
    }
    MEDIA_ERR_LOG("PreviewOutputNapi::CreatePreviewOutput call Failed!");
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
        CHECK_ERROR_RETURN_RET_LOG(surface == nullptr, result, "failed to get surface");
        int retCode = CameraManager::GetInstance()->CreatePreviewOutputWithoutProfile(surface, &sPreviewOutput_);
        CHECK_ERROR_RETURN_RET(!CameraNapiUtils::CheckError(env, retCode), nullptr);
        CHECK_ERROR_RETURN_RET_LOG(sPreviewOutput_ == nullptr, result,
            "failed to create previewOutput with only surfaceId");
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sPreviewOutput_ = nullptr;

        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create preview output instance with only surfaceId");
        }
    }
    MEDIA_ERR_LOG("CreatePreviewOutput with only surfaceId call Failed!");
    napi_get_undefined(env, &result);
    return result;
}

napi_value PreviewOutputNapi::CreatePreviewOutputForTransfer(napi_env env, sptr<PreviewOutput> previewOutput)
{
    MEDIA_INFO_LOG("CreatePreviewOutputForTransfer is called");
    CHECK_ERROR_RETURN_RET_LOG(previewOutput == nullptr, nullptr,
        "CreatePreviewOutputForTransfer previewOutput is nullptr");
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sPreviewOutput_ = previewOutput;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sPreviewOutput_ = nullptr;

        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create preview output instance for transfer");
        }
    }
    MEDIA_ERR_LOG("CreatePreviewOutputForTransfer call Failed!");
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
            MEDIA_DEBUG_LOG("PreviewOutputNapi::IsPreviewOutput is failed");
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
    CHECK_ERROR_RETURN_RET_LOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"),
        nullptr, "PreviewOutputNapi::GetActiveProfile parse parameter occur error");
    auto profile = previewOutputNapi->previewOutput_->GetPreviewProfile();
    CHECK_ERROR_RETURN_RET(profile == nullptr, CameraNapiUtils::GetUndefinedValue(env));
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
    CHECK_ERROR_RETURN_RET_LOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument"),
        nullptr, "PreviewOutputNapi::Release invalid argument");
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
    CHECK_ERROR_RETURN_RET(asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE,
        asyncFunction->GetPromise());
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value PreviewOutputNapi::AddDeferredSurface(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("AddDeferredSurface is called");
    CHECK_ERROR_RETURN_RET_LOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi AddDeferredSurface is called!");

    PreviewOutputNapi* previewOutputNapi;
    std::string surfaceId;
    CameraNapiParamParser jsParamParser(env, info, previewOutputNapi, surfaceId);
    CHECK_ERROR_RETURN_RET_LOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument"), nullptr,
        "CameraInputNapi::AddDeferredSurface invalid argument");

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
    CHECK_EXECUTE(previewProfile != nullptr,
        surface->SetUserData(CameraManager::surfaceFormat, std::to_string(previewProfile->GetCameraFormat())));
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
    CHECK_ERROR_RETURN_RET_LOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument"),
        nullptr, "PreviewOutputNapi::Start invalid argument");
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
    CHECK_ERROR_RETURN_RET(asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE,
        asyncFunction->GetPromise());
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value PreviewOutputNapi::Stop(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("PreviewOutputNapi::Stop is called");
    std::unique_ptr<PreviewOutputAsyncContext> asyncContext = std::make_unique<PreviewOutputAsyncContext>(
        "PreviewOutputNapi::Stop", CameraNapiUtils::IncrementAndGet(previewOutputTaskId));
    auto asyncFunction =
        std::make_shared<CameraNapiAsyncFunction>(env, "Stop", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunction);
    CHECK_ERROR_RETURN_RET_LOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument"), nullptr,
        "PreviewOutputNapi::Stop invalid argument");
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
    CHECK_ERROR_RETURN_RET(asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE,
        asyncFunction->GetPromise());
    return CameraNapiUtils::GetUndefinedValue(env);
}

void PreviewOutputNapi::RegisterFrameStartCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    auto listener = RegisterCallbackListener(eventName, env, callback, args, isOnce);
    CHECK_ERROR_RETURN_LOG(
        listener == nullptr, "PreviewOutputNapi::RegisterFrameStartCallbackListener listener is null");
    previewOutput_->SetCallback(listener);
}

void PreviewOutputNapi::RegisterFrameEndCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    auto listener = RegisterCallbackListener(eventName, env, callback, args, isOnce);
    CHECK_ERROR_RETURN_LOG(listener == nullptr, "PreviewOutputNapi::RegisterFrameEndCallbackListener listener is null");
    previewOutput_->SetCallback(listener);
}

void PreviewOutputNapi::RegisterErrorCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    auto listener = RegisterCallbackListener(eventName, env, callback, args, isOnce);
    CHECK_ERROR_RETURN_LOG(listener == nullptr, "PreviewOutputNapi::RegisterErrorCallbackListener listener is null");
    previewOutput_->SetCallback(listener);
}

void PreviewOutputNapi::UnregisterCommonCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    auto listener = UnregisterCallbackListener(eventName, env, callback, args);
    CHECK_ERROR_RETURN_LOG(listener == nullptr,
        "PreviewOutputNapi::UnregisterCommonCallbackListener %{public}s listener is null", eventName.c_str());
    if (listener->IsEmpty(eventName)) {
        previewOutput_->RemoveCallback(listener);
    }
}

void PreviewOutputNapi::RegisterSketchStatusChangedCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(!CameraNapiSecurity::CheckSystemApp(env), "SystemApi On sketchStatusChanged is called!");
    auto listener = RegisterCallbackListener(eventName, env, callback, args, isOnce);
    CHECK_ERROR_RETURN_LOG(
        listener == nullptr, "PreviewOutputNapi::RegisterSketchStatusChangedCallbackListener listener is null");
    previewOutput_->SetCallback(listener);
    previewOutput_->OnNativeRegisterCallback(eventName);
}

void PreviewOutputNapi::UnregisterSketchStatusChangedCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi Off sketchStatusChanged is called!");
        return;
    }

    auto listener = UnregisterCallbackListener(eventName, env, callback, args);
    CHECK_ERROR_RETURN_LOG(
        listener == nullptr, "PreviewOutputNapi::UnregisterSketchStatusChangedCallbackListener listener is null");
    previewOutput_->OnNativeUnregisterCallback(eventName);
    if (listener->IsEmpty(eventName)) {
        previewOutput_->RemoveCallback(listener);
    }
}

const PreviewOutputNapi::EmitterFunctions& PreviewOutputNapi::GetEmitterFunctions()
{
    static const EmitterFunctions funMap = {
        { CONST_PREVIEW_FRAME_START, {
            &PreviewOutputNapi::RegisterFrameStartCallbackListener,
            &PreviewOutputNapi::UnregisterCommonCallbackListener } },
        { CONST_PREVIEW_FRAME_END, {
            &PreviewOutputNapi::RegisterFrameEndCallbackListener,
            &PreviewOutputNapi::UnregisterCommonCallbackListener } },
        { CONST_PREVIEW_FRAME_ERROR, {
            &PreviewOutputNapi::RegisterErrorCallbackListener,
            &PreviewOutputNapi::UnregisterCommonCallbackListener } },
        { CONST_SKETCH_STATUS_CHANGED, {
            &PreviewOutputNapi::RegisterSketchStatusChangedCallbackListener,
            &PreviewOutputNapi::UnregisterSketchStatusChangedCallbackListener } } };
    return funMap;
}

napi_value PreviewOutputNapi::IsSketchSupported(napi_env env, napi_callback_info info)
{
    CHECK_ERROR_RETURN_RET_LOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi IsSketchSupported is called!");
    MEDIA_INFO_LOG("PreviewOutputNapi::IsSketchSupported is called");
    PreviewOutputNapi* previewOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, previewOutputNapi);
    CHECK_ERROR_RETURN_RET_LOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"),
        nullptr, "PreviewOutputNapi::IsSketchSupported parse parameter occur error");

    bool isSupported = previewOutputNapi->previewOutput_->IsSketchSupported();
    return CameraNapiUtils::GetBooleanValue(env, isSupported);
}

napi_value PreviewOutputNapi::GetSketchRatio(napi_env env, napi_callback_info info)
{
    CHECK_ERROR_RETURN_RET_LOG(!CameraNapiSecurity::CheckSystemApp(env),
        nullptr, "SystemApi GetSketchRatio is called!");
    MEDIA_INFO_LOG("PreviewOutputNapi::GetSketchRatio is called");
    PreviewOutputNapi* previewOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, previewOutputNapi);
    CHECK_ERROR_RETURN_RET_LOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"),
        nullptr, "PreviewOutputNapi::GetSketchRatio parse parameter occur error");
    auto result = CameraNapiUtils::GetUndefinedValue(env);
    float ratio = previewOutputNapi->previewOutput_->GetSketchRatio();
    napi_create_double(env, ratio, &result);
    return result;
}

napi_value PreviewOutputNapi::EnableSketch(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PreviewOutputNapi::EnableSketch enter");
    CHECK_ERROR_RETURN_RET_LOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr, "SystemApi EnableSketch is called!");

    bool isEnableSketch;
    PreviewOutputNapi* previewOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, previewOutputNapi, isEnableSketch);
    CHECK_ERROR_RETURN_RET_LOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "PreviewOutputNapi::EnableSketch parse parameter occur error");

    int32_t retCode = previewOutputNapi->previewOutput_->EnableSketch(isEnableSketch);
    CHECK_ERROR_RETURN_RET_LOG(!CameraNapiUtils::CheckError(env, retCode), nullptr,
        "PreviewOutputNapi::EnableSketch fail! %{public}d", retCode);
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
        if (retCode == INVALID_ARGUMENT) {
            CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT,
                "GetPreviewRotation Camera invalid argument.");
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
    int32_t imageRotation = 0;
    bool isDisplayLocked;
    int32_t retCode = 0;
    CameraNapiParamParser jsParamParser(env, info, previewOutputNapi, imageRotation, isDisplayLocked);
    if (jsParamParser.IsStatusOk()) {
        MEDIA_INFO_LOG("PreviewOutputNapi SetPreviewRotation! %{public}d", imageRotation);
    } else {
        MEDIA_WARNING_LOG("PreviewOutputNapi SetPreviewRotation without isDisplayLocked flag!");
        jsParamParser = CameraNapiParamParser(env, info, previewOutputNapi, imageRotation);
        isDisplayLocked = false;
    }
    CHECK_ERROR_RETURN_RET_LOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument"), nullptr,
        "PreviewOutputNapi::SetPreviewRotation invalid argument");
    if (previewOutputNapi->previewOutput_ == nullptr || imageRotation < 0 ||
        imageRotation > ROTATION_270 || (imageRotation % ROTATION_90 != 0)) {
        MEDIA_ERR_LOG("PreviewOutputNapi::SetPreviewRotation get native object fail");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "get native object fail");
        return nullptr;
    }
    retCode = previewOutputNapi->previewOutput_->SetPreviewRotation(imageRotation, isDisplayLocked);
    CHECK_ERROR_RETURN_RET_LOG(!CameraNapiUtils::CheckError(env, retCode), nullptr,
        "PreviewOutputNapi::SetPreviewRotation! %{public}d", retCode);
    MEDIA_DEBUG_LOG("PreviewOutputNapi::SetPreviewRotation success");
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value PreviewOutputNapi::AttachSketchSurface(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PreviewOutputNapi::AttachSketchSurface enter");
    CHECK_ERROR_RETURN_RET_LOG(!CameraNapiSecurity::CheckSystemApp(env), nullptr,
        "SystemApi AttachSketchSurface is called!");

    std::string surfaceId;
    PreviewOutputNapi* previewOutputNapi = nullptr;
    CameraNapiParamParser jsParamParser(env, info, previewOutputNapi, surfaceId);
    CHECK_ERROR_RETURN_RET_LOG(!jsParamParser.AssertStatus(INVALID_ARGUMENT, "parse parameter occur error"), nullptr,
        "PreviewOutputNapi::AttachSketchSurface parse parameter occur error");

    sptr<Surface> surface = GetSurfaceFromSurfaceId(env, surfaceId);
    if (surface == nullptr) {
        MEDIA_ERR_LOG("PreviewOutputNapi::AttachSketchSurface get surface is null");
        CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "input surface convert fail");
        return nullptr;
    }

    int32_t retCode = previewOutputNapi->previewOutput_->AttachSketchSurface(surface);
    CHECK_ERROR_RETURN_RET_LOG(!CameraNapiUtils::CheckError(env, retCode), nullptr,
        "PreviewOutputNapi::AttachSketchSurface! %{public}d", retCode);
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
        CHECK_ERROR_RETURN_RET_LOG(!CameraNapiUtils::CheckError(env, retCode), result,
            "PreviewOutputNapi::SetFrameRate! %{public}d", retCode);
    } else {
        MEDIA_ERR_LOG("SetFrameRate call Failed!");
    }
    return result;
}
 
napi_value PreviewOutputNapi::GetActiveFrameRate(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetActiveFrameRate is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    MEDIA_DEBUG_LOG("PreviewOutputNapi::GetActiveFrameRate get js args");
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ZERO), "requires no parameter.");
 
    napi_get_undefined(env, &result);
    PreviewOutputNapi* previewOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&previewOutputNapi));
    if (status == napi_ok && previewOutputNapi != nullptr) {
        std::vector<int32_t> frameRateRange = previewOutputNapi->previewOutput_->GetFrameRateRange();
        CameraNapiUtils::CreateFrameRateJSArray(env, frameRateRange, result);
    } else {
        MEDIA_ERR_LOG("GetActiveFrameRate call failed!");
    }
    return result;
}
 
napi_value PreviewOutputNapi::GetSupportedFrameRates(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PreviewOutputNapi::GetSupportedFrameRates is called");
 
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    MEDIA_DEBUG_LOG("PreviewOutputNapi::GetSupportedFrameRates get js args");
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

extern "C" {
napi_value GetPreviewOutputNapi(napi_env env, sptr<PreviewOutput> previewOutput)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    return PreviewOutputNapi::CreatePreviewOutputForTransfer(env, previewOutput);
}

bool GetNativePreviewOutput(void *previewOutputNapiPtr, sptr<PreviewOutput> &nativePreviewOutput)
{
    MEDIA_INFO_LOG("%{public}s Called", __func__);
    CHECK_ERROR_RETURN_RET_LOG(previewOutputNapiPtr == nullptr,
        false, "%{public}s previewOutputNapiPtr is nullptr", __func__);
    nativePreviewOutput = reinterpret_cast<PreviewOutputNapi*>(previewOutputNapiPtr)->GetPreviewOutput();
    return true;
}
}
} // namespace CameraStandard
} // namespace OHOS
