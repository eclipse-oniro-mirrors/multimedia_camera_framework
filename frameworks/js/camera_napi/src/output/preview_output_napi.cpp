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

#include <unistd.h>
#include <uv.h>

#include "output/camera_sketch_data_napi.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;
namespace {
    constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "PreviewOutputNapi"};
}
thread_local napi_ref PreviewOutputNapi::sConstructor_ = nullptr;
thread_local sptr<PreviewOutput> PreviewOutputNapi::sPreviewOutput_ = nullptr;
thread_local uint32_t PreviewOutputNapi::previewOutputTaskId = CAMERA_PREVIEW_OUTPUT_TASKID;

PreviewOutputCallback::PreviewOutputCallback(napi_env env) : env_(env) {}

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
        std::make_unique<PreviewOutputCallbackInfo>(eventType, value, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        PreviewOutputCallbackInfo* callbackInfo = reinterpret_cast<PreviewOutputCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->UpdateJSCallback(callbackInfo->eventType_, callbackInfo->value_);
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

void PreviewOutputCallback::OnSketchAvailableAsync(SketchData& sketchData) const
{
    MEDIA_DEBUG_LOG("OnSketchAvailableAsync is called");
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
    std::unique_ptr<SketchDataCallbackInfo> callbackInfo = std::make_unique<SketchDataCallbackInfo>(sketchData, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {},
        [](uv_work_t* work, int status) {
            SketchDataCallbackInfo* callbackInfo = reinterpret_cast<SketchDataCallbackInfo*>(work->data);
            if (callbackInfo) {
                callbackInfo->listener_->OnSketchAvailableCall(callbackInfo->sketchData_);
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

void PreviewOutputCallback::OnSketchAvailableCall(SketchData& sketchData) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnSketchAvailableCall is called");
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env_, &scope);
    if (scope == nullptr) {
        return;
    }
    napi_value args[ARGS_TWO];
    napi_value callback = nullptr;
    napi_value retVal;
    napi_get_undefined(env_, &args[PARAM0]);
    for (auto it = sketchAvailableCbList_.begin(); it != sketchAvailableCbList_.end();) {
        napi_env env = (*it)->env_;
        args[PARAM1] = CameraSketchDataNapi::CreateCameraSketchData(env_, sketchData);
        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_call_function(env_, nullptr, callback, ARGS_TWO, args, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            it = sketchAvailableCbList_.erase(it);
        } else {
            it++;
        }
    }
    napi_close_handle_scope(env_, scope);
}

void PreviewOutputCallback::OnSketchAvailable(SketchData& sketchData) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnSketchAvailable is called");
    OnSketchAvailableAsync(sketchData);
}

void PreviewOutputCallback::UpdateJSCallback(PreviewOutputEventType eventType, const int32_t value) const
{
    MEDIA_DEBUG_LOG("UpdateJSCallback is called");
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env_, &scope);
    if (scope == nullptr) {
        return;
    }
    napi_value result[ARGS_TWO];
    napi_value callback = nullptr;
    napi_value retVal;
    napi_value propValue;
    napi_get_undefined(env_, &result[PARAM0]);
    std::vector<std::shared_ptr<AutoRef>>* callbackList;
    switch (eventType) {
        case PreviewOutputEventType::PREVIEW_FRAME_START:
            callbackList = &frameStartCbList_;
            break;
        case PreviewOutputEventType::PREVIEW_FRAME_END:
            callbackList = &frameEndCbList_;
            break;
        case PreviewOutputEventType::PREVIEW_FRAME_ERROR:
            callbackList = &errorCbList_;
            break;
        case PreviewOutputEventType::SKETCH_AVAILABLE:
            callbackList = &sketchAvailableCbList_;
            break;
        default:
            MEDIA_ERR_LOG("Incorrect preview callback event type received from JS");
            return;
    }
    for (auto it = callbackList->begin(); it != callbackList->end();) {
        napi_env env = (*it)->env_;
        if (eventType == PreviewOutputEventType::PREVIEW_FRAME_ERROR) {
            napi_value errJsResult[ARGS_ONE];
            napi_create_object(env, &errJsResult[PARAM0]);
            napi_create_int32(env, value, &propValue);
            napi_set_named_property(env, errJsResult[PARAM0], "code", propValue);
            napi_get_reference_value(env, (*it)->cb_, &callback); // should errorcode be valued as -1
            napi_call_function(env_, nullptr, callback, ARGS_ONE, errJsResult, &retVal);
        } else {
            napi_get_undefined(env, &result[PARAM1]);
            napi_get_reference_value(env, (*it)->cb_, &callback);
            napi_call_function(env_, nullptr, callback, ARGS_TWO, result, &retVal);
        }
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            callbackList->erase(it);
        } else {
            it++;
        }
    }
    napi_close_handle_scope(env_, scope);
}

void PreviewOutputCallback::SaveCallbackReference(const std::string& eventType, napi_value callback, bool isOnce)
{
    std::lock_guard<std::mutex> lock(previewOutputCbMutex_);
    std::vector<std::shared_ptr<AutoRef>>* callbackList;
    auto eventTypeEnum = PreviewOutputEventTypeHelper.ToEnum(eventType);
    switch (eventTypeEnum) {
        case PreviewOutputEventType::PREVIEW_FRAME_START:
            callbackList = &frameStartCbList_;
            break;
        case PreviewOutputEventType::PREVIEW_FRAME_END:
            callbackList = &frameEndCbList_;
            break;
        case PreviewOutputEventType::PREVIEW_FRAME_ERROR:
            callbackList = &errorCbList_;
            break;
        case PreviewOutputEventType::SKETCH_AVAILABLE:
            callbackList = &sketchAvailableCbList_;
            break;
        default:
            MEDIA_ERR_LOG("Incorrect preview callback event type received from JS");
            return;
    }
    for (auto it = callbackList->begin(); it != callbackList->end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        CHECK_AND_RETURN_LOG(!isSameCallback, "SaveCallbackReference: has same callback, nothing to do");
    }
    napi_ref callbackRef = nullptr;
    const int32_t refCount = 1;
    napi_status status = napi_create_reference(env_, callback, refCount, &callbackRef);
    CHECK_AND_RETURN_LOG(
        status == napi_ok && callbackRef != nullptr, "PreviewOutputCallback: creating reference for callback fail");
    std::shared_ptr<AutoRef> cb = std::make_shared<AutoRef>(env_, callbackRef, isOnce);
    callbackList->push_back(cb);
    MEDIA_DEBUG_LOG("Save callback reference success, %{public}s callback list size [%{public}zu]", eventType.c_str(),
        callbackList->size());
}

void PreviewOutputCallback::RemoveCallbackRef(napi_env env, napi_value callback, const std::string& eventType)
{
    std::lock_guard<std::mutex> lock(previewOutputCbMutex_);
    if (callback == nullptr) {
        MEDIA_INFO_LOG("RemoveCallbackRef: js callback is nullptr, remove all callback reference");
        RemoveAllCallbacks(eventType);
        return;
    }
    std::vector<std::shared_ptr<AutoRef>>* callbackList;
    auto eventTypeEnum = PreviewOutputEventTypeHelper.ToEnum(eventType);
    switch (eventTypeEnum) {
        case PreviewOutputEventType::PREVIEW_FRAME_START:
            callbackList = &frameStartCbList_;
            break;
        case PreviewOutputEventType::PREVIEW_FRAME_END:
            callbackList = &frameEndCbList_;
            break;
        case PreviewOutputEventType::PREVIEW_FRAME_ERROR:
            callbackList = &errorCbList_;
            break;
        case PreviewOutputEventType::SKETCH_AVAILABLE:
            callbackList = &sketchAvailableCbList_;
            break;
        default:
            MEDIA_ERR_LOG("Incorrect preview callback event type received from JS");
            return;
    }
    for (auto it = callbackList->begin(); it != callbackList->end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        if (isSameCallback) {
            MEDIA_INFO_LOG("RemoveCallbackRef: find js callback, delete it");
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            (*it)->cb_ = nullptr;
            CHECK_AND_RETURN_LOG(status == napi_ok, "RemoveCallbackRef: delete reference for callback fail");
            callbackList->erase(it);
            return;
        }
    }
    MEDIA_INFO_LOG("RemoveCallbackRef: js callback no find");
}

void PreviewOutputCallback::RemoveAllCallbacks(const std::string& eventType)
{
    std::vector<std::shared_ptr<AutoRef>>* callbackList;
    auto eventTypeEnum = PreviewOutputEventTypeHelper.ToEnum(eventType);
    switch (eventTypeEnum) {
        case PreviewOutputEventType::PREVIEW_FRAME_START:
            callbackList = &frameStartCbList_;
            break;
        case PreviewOutputEventType::PREVIEW_FRAME_END:
            callbackList = &frameEndCbList_;
            break;
        case PreviewOutputEventType::PREVIEW_FRAME_ERROR:
            callbackList = &errorCbList_;
            break;
        case PreviewOutputEventType::SKETCH_AVAILABLE:
            callbackList = &sketchAvailableCbList_;
            break;
        default:
            MEDIA_ERR_LOG("Incorrect preview callback event type received from JS");
            return;
    }
    for (auto it = callbackList->begin(); it != callbackList->end(); ++it) {
        napi_status ret = napi_delete_reference(env_, (*it)->cb_);
        if (ret != napi_ok) {
            MEDIA_ERR_LOG("RemoveAllCallbackReferences: napi_delete_reference err.");
        }
        (*it)->cb_ = nullptr;
    }
    callbackList->clear();
    MEDIA_INFO_LOG("RemoveAllCallbacks: remove all js callbacks success");
}

PreviewOutputNapi::PreviewOutputNapi() : env_(nullptr), wrapper_(nullptr) {}

PreviewOutputNapi::~PreviewOutputNapi()
{
    MEDIA_DEBUG_LOG("~PreviewOutputNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (previewOutput_) {
        previewOutput_ = nullptr;
    }
    if (previewCallback_) {
        previewCallback_ = nullptr;
    }
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
        DECLARE_NAPI_FUNCTION("enableSketch", EnableSketch)
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

            std::shared_ptr<PreviewOutputCallback> callback = std::make_shared<PreviewOutputCallback>(env);
            ((sptr<PreviewOutput>&)(obj->previewOutput_))->SetCallback(callback);
            obj->previewCallback_ = callback;

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

static void CommonCompleteCallback(napi_env env, napi_status status, void* data)
{
    MEDIA_DEBUG_LOG("CommonCompleteCallback is called");
    auto context = static_cast<PreviewOutputAsyncContext*>(data);
    if (context == nullptr) {
        MEDIA_ERR_LOG("Async context is null");
        return;
    }

    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();

    if (!context->status) {
        CameraNapiUtils::CreateNapiErrorObject(env, context->errorCode, context->errorMsg.c_str(), jsContext);
    } else {
        jsContext->status = true;
        napi_get_undefined(env, &jsContext->error);
        if (context->bRetBool) {
            napi_get_boolean(env, context->status, &jsContext->data);
        } else {
            napi_get_undefined(env, &jsContext->data);
        }
    }

    if (!context->funcName.empty() && context->taskId > 0) {
        // Finish async trace
        CAMERA_FINISH_ASYNC_TRACE(context->funcName, context->taskId);
        jsContext->funcName = context->funcName;
    }

    if (context->work != nullptr) {
        CameraNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    delete context;
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

napi_value PreviewOutputNapi::Release(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("Release is called");
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    std::unique_ptr<PreviewOutputAsyncContext> asyncContext = std::make_unique<PreviewOutputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Release");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<PreviewOutputAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "PreviewOutputNapi::Release";
                context->taskId = CameraNapiUtils::IncreamentAndGet(previewOutputTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr && context->objectInfo->previewOutput_ != nullptr) {
                    context->bRetBool = false;
                    context->status = true;
                    ((sptr<PreviewOutput>&)(context->objectInfo->previewOutput_))->Release();
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for PreviewOutputNapi::Release");
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

static napi_value ConvertJSArgsToNative(
    napi_env env, size_t argc, const napi_value argv[], PreviewOutputAsyncContext& asyncContext)
{
    char buffer[PATH_MAX];
    const int32_t refCount = 1;
    napi_value result;
    size_t length = 0;
    auto context = &asyncContext;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_string) {
            if (napi_get_value_string_utf8(env, argv[i], buffer, PATH_MAX, &length) == napi_ok) {
                MEDIA_DEBUG_LOG("surfaceId buffer: %{public}s", buffer);
                context->surfaceId = std::string(buffer);
                MEDIA_DEBUG_LOG("context->surfaceId after convert : %{public}s", context->surfaceId.c_str());
            } else {
                MEDIA_ERR_LOG("Could not able to read surfaceId argument!");
            }
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_status PreviewOutputNapi::CreateAsyncTask(
    napi_env env, napi_value resource, std::unique_ptr<PreviewOutputAsyncContext>& asyncContext)
{
    napi_status status = napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
        auto context = static_cast<PreviewOutputAsyncContext*>(data);
        context->status = false;
        // Start async trace
        context->funcName = "PreviewOutputNapi::AddDeferredSurface";
        context->taskId = CameraNapiUtils::IncreamentAndGet(previewOutputTaskId);
        CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
        if (context->objectInfo != nullptr && context->objectInfo->previewOutput_ != nullptr) {
            context->bRetBool = false;
            context->status = true;
            uint64_t iSurfaceId;
            std::istringstream iss(context->surfaceId);
            iss >> iSurfaceId;
            sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
            if (!surface) {
                surface = Media::ImageReceiver::getSurfaceById(context->surfaceId);
            }
            if (surface == nullptr) {
                MEDIA_ERR_LOG("failed to get surface");
                return;
            }
            CameraFormat format = ((sptr<PreviewOutput> &)(context->objectInfo->previewOutput_))->format;
            surface->SetUserData(CameraManager::surfaceFormat, std::to_string(format));
            ((sptr<PreviewOutput> &)(context->objectInfo->previewOutput_))->AddDeferredSurface(surface);
        }
    },
    CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    return status;
}

napi_value PreviewOutputNapi::AddDeferredSurface(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("AddDeferredSurface is called");
    if (!CameraNapiUtils::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi AddDeferredSurface is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_TWO, argv, ADD_DEFERRED_SURFACE)) {
        return result;
    }
    napi_get_undefined(env, &result);
    std::unique_ptr<PreviewOutputAsyncContext> asyncContext = std::make_unique<PreviewOutputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
    CAMERA_NAPI_CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_TWO) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM1], refCount, asyncContext->callbackRef);
        }
        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "AddDeferredSurface");
        status = CreateAsyncTask(env, resource, asyncContext);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work!");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
            asyncContext.release();
        }
    } else {
        MEDIA_ERR_LOG("AddDeferredSurface call Failed!");
    }
    return result;
}

napi_value PreviewOutputNapi::Start(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Start is called");
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    std::unique_ptr<PreviewOutputAsyncContext> asyncContext = std::make_unique<PreviewOutputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Start");

        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<PreviewOutputAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "PreviewOutputNapi::Start";
                context->taskId = CameraNapiUtils::IncreamentAndGet(previewOutputTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr && context->objectInfo->previewOutput_ != nullptr) {
                    context->bRetBool = false;
                    context->errorCode = context->objectInfo->previewOutput_->Start();
                    context->status = context->errorCode == 0;
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for PreviewOutputNapi::Release");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
            asyncContext.release();
        }
    } else {
        MEDIA_ERR_LOG("Start call Failed!");
    }
    return result;
}

napi_value PreviewOutputNapi::Stop(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Stop is called");
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    std::unique_ptr<PreviewOutputAsyncContext> asyncContext = std::make_unique<PreviewOutputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Stop");

        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<PreviewOutputAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "PreviewOutputNapi::Stop";
                context->taskId = CameraNapiUtils::IncreamentAndGet(previewOutputTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr && context->objectInfo->previewOutput_ != nullptr) {
                    context->bRetBool = false;
                    context->errorCode = context->objectInfo->previewOutput_->Stop();
                    context->status = context->errorCode == 0;
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for PreviewOutputNapi::Release");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
            asyncContext.release();
        }
    } else {
        MEDIA_ERR_LOG("Stop call Failed!");
    }
    return result;
}

napi_value PreviewOutputNapi::RegisterCallback(
    napi_env env, napi_value jsThis, const string& eventType, napi_value callback, bool isOnce)
{
    napi_status status;
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);
    PreviewOutputNapi* previewOutputNapi = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&previewOutputNapi));
    NAPI_ASSERT(
        env, status == napi_ok && previewOutputNapi != nullptr, "Failed to retrieve previewOutputNapi instance.");
    NAPI_ASSERT(env, previewOutputNapi->previewCallback_ != nullptr, "previewCallback is null.");
    if (!eventType.empty()) {
        auto eventTypeEnum = PreviewOutputEventTypeHelper.ToEnum(eventType);
        if (eventTypeEnum == PreviewOutputEventType::SKETCH_AVAILABLE && !CameraNapiUtils::CheckSystemApp(env)) {
            MEDIA_ERR_LOG("SystemApi On sketchAvailable is called!");
            return undefinedResult;
        }
        previewOutputNapi->previewCallback_->SaveCallbackReference(eventType, callback, isOnce);

        if (eventTypeEnum == PreviewOutputEventType::SKETCH_AVAILABLE && status == napi_ok &&
            previewOutputNapi->previewOutput_ != nullptr) {
            previewOutputNapi->previewOutput_->StartSketch();
        }
    } else {
        MEDIA_ERR_LOG("Failed to Register Callback: event type is empty!");
    }
    return undefinedResult;
}

napi_value PreviewOutputNapi::On(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("On is called");
    napi_value undefinedResult = nullptr;
    size_t argCount = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr, nullptr};
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_ARGS(env, info, argCount, argv, thisVar);
    NAPI_ASSERT(env, argCount == ARGS_TWO, "requires 2 parameters");

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string ||
        napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function) {
        return undefinedResult;
    }
    std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[PARAM0]);
    MEDIA_INFO_LOG("On eventType: %{public}s", eventType.c_str());
    return RegisterCallback(env, thisVar, eventType, argv[PARAM1], false);
}

napi_value PreviewOutputNapi::Once(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Once is called");
    napi_value undefinedResult = nullptr;
    size_t argCount = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr, nullptr};
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &undefinedResult);
    CAMERA_NAPI_GET_JS_ARGS(env, info, argCount, argv, thisVar);
    NAPI_ASSERT(env, argCount == ARGS_TWO, "requires 2 parameters");

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string ||
        napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function) {
        return undefinedResult;
    }
    std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[PARAM0]);
    MEDIA_INFO_LOG("Once eventType: %{public}s", eventType.c_str());
    return RegisterCallback(env, thisVar, eventType, argv[PARAM1], true);
}

napi_value PreviewOutputNapi::UnregisterCallback(
    napi_env env, napi_value jsThis, const std::string& eventType, napi_value callback)
{
    MEDIA_DEBUG_LOG("UnregisterCallback is called");
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);
    napi_status status;
    PreviewOutputNapi* previewOutputNapi = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&previewOutputNapi));
    NAPI_ASSERT(
        env, status == napi_ok && previewOutputNapi != nullptr, "Failed to retrieve previewOutputNapi instance.");
    NAPI_ASSERT(env, previewOutputNapi->previewOutput_ != nullptr, "previewOutput is null.");
    NAPI_ASSERT(env, previewOutputNapi->previewCallback_ != nullptr, "previewCallback is null.");
    if (!eventType.empty()) {
        auto eventTypeEnum = PreviewOutputEventTypeHelper.ToEnum(eventType);
        if (eventTypeEnum == PreviewOutputEventType::SKETCH_AVAILABLE && !CameraNapiUtils::CheckSystemApp(env)) {
            MEDIA_ERR_LOG("SystemApi Off sketchAvailable is called!");
            return undefinedResult;
        }
        // unset callback for error
        previewOutputNapi->previewCallback_->RemoveCallbackRef(env, callback, eventType);
        if (eventTypeEnum == PreviewOutputEventType::SKETCH_AVAILABLE && status == napi_ok &&
            previewOutputNapi->previewOutput_ != nullptr) {
            previewOutputNapi->previewOutput_->StopSketch();
        }
    } else {
        MEDIA_ERR_LOG("Incorrect callback event type provided for camera input!");
    }
    return undefinedResult;
}

napi_value PreviewOutputNapi::Off(napi_env env, napi_callback_info info)
{
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);
    const size_t minArgCount = 1;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr, nullptr};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (argc < minArgCount) {
        return undefinedResult;
    }

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string) {
        return undefinedResult;
    }

    napi_valuetype secondArgsType = napi_undefined;
    if (argc > minArgCount &&
        (napi_typeof(env, argv[PARAM1], &secondArgsType) != napi_ok || secondArgsType != napi_function)) {
        return undefinedResult;
    }
    std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[PARAM0]);
    MEDIA_INFO_LOG("Off eventType: %{public}s", eventType.c_str());
    return UnregisterCallback(env, thisVar, eventType, argv[PARAM1]);
}

napi_value PreviewOutputNapi::IsSketchSupported(napi_env env, napi_callback_info info)
{
    if (!CameraNapiUtils::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsSketchSupported is called!");
        return nullptr;
    }
    MEDIA_INFO_LOG("IsSketchSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PreviewOutputNapi* previewOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&previewOutputNapi));
    if (status == napi_ok && previewOutputNapi != nullptr && previewOutputNapi->previewOutput_ != nullptr) {
        bool isSupported = previewOutputNapi->previewOutput_->IsSketchSupported();
        napi_get_boolean(env, isSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsSketchSupported call Failed!");
    }
    return result;
}

napi_value PreviewOutputNapi::GetSketchRatio(napi_env env, napi_callback_info info)
{
    if (!CameraNapiUtils::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi GetSketchRatio is called!");
        return nullptr;
    }
    MEDIA_INFO_LOG("GetSketchRatio is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PreviewOutputNapi* previewOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&previewOutputNapi));
    if (status == napi_ok && previewOutputNapi != nullptr && previewOutputNapi->previewOutput_ != nullptr) {
        float ratio = previewOutputNapi->previewOutput_->GetSketchRatio();
        napi_create_double(env, ratio, &result);
    } else {
        MEDIA_ERR_LOG("GetSketchRatio call Failed!");
    }
    return result;
}

napi_value PreviewOutputNapi::EnableSketch(napi_env env, napi_callback_info info)
{
    if (!CameraNapiUtils::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi EnableSketch is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires one parameter");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType != napi_boolean && !CameraNapiUtils::CheckError(env, INVALID_ARGUMENT)) {
        return result;
    }
    napi_get_undefined(env, &result);
    PreviewOutputNapi* previewOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&previewOutputNapi));
    if (status == napi_ok && previewOutputNapi != nullptr && previewOutputNapi->previewOutput_ != nullptr) {
        bool isEnableSketch;
        napi_get_value_bool(env, argv[PARAM0], &isEnableSketch);
        int32_t retCode = previewOutputNapi->previewOutput_->EnableSketch(isEnableSketch);
        if (retCode != 0 && !CameraNapiUtils::CheckError(env, retCode)) {
            return result;
        }
    }
    return result;
}
} // namespace CameraStandard
} // namespace OHOS
