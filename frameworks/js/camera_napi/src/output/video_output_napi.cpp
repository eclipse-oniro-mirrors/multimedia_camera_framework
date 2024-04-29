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

#include "output/video_output_napi.h"

#include <uv.h>

#include "camera_napi_template_utils.h"
#include "camera_napi_utils.h"
#include "napi/native_api.h"

namespace OHOS {
namespace CameraStandard {
thread_local napi_ref VideoOutputNapi::sConstructor_ = nullptr;
thread_local sptr<VideoOutput> VideoOutputNapi::sVideoOutput_ = nullptr;
thread_local uint32_t VideoOutputNapi::videoOutputTaskId = CAMERA_VIDEO_OUTPUT_TASKID;

VideoCallbackListener::VideoCallbackListener(napi_env env) : env_(env) {}

void VideoCallbackListener::UpdateJSCallbackAsync(VideoOutputEventType eventType, const int32_t value) const
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
    std::unique_ptr<VideoOutputCallbackInfo> callbackInfo =
        std::make_unique<VideoOutputCallbackInfo>(eventType, value, shared_from_this());
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        VideoOutputCallbackInfo* callbackInfo = reinterpret_cast<VideoOutputCallbackInfo *>(work->data);
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
    }  else {
        callbackInfo.release();
    }
}

void VideoCallbackListener::OnFrameStarted() const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnFrameStarted is called");
    UpdateJSCallbackAsync(VideoOutputEventType::VIDEO_FRAME_START, -1);
}

void VideoCallbackListener::OnFrameEnded(const int32_t frameCount) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnFrameEnded is called, frameCount: %{public}d", frameCount);
    UpdateJSCallbackAsync(VideoOutputEventType::VIDEO_FRAME_END, frameCount);
}

void VideoCallbackListener::OnError(const int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnError is called, errorCode: %{public}d", errorCode);
    UpdateJSCallbackAsync(VideoOutputEventType::VIDEO_FRAME_ERROR, errorCode);
}

void VideoCallbackListener::UpdateJSCallback(VideoOutputEventType eventType, const int32_t value) const
{
    MEDIA_DEBUG_LOG("UpdateJSCallback is called");
    napi_value result[ARGS_TWO];
    napi_value callback = nullptr;
    napi_value retVal;
    napi_value propValue;
    napi_get_undefined(env_, &result[PARAM0]);
    std::vector<std::shared_ptr<AutoRef>> *callbackList;
    switch (eventType) {
        case VideoOutputEventType::VIDEO_FRAME_START:
            callbackList = &frameStartCbList_;
            break;
        case VideoOutputEventType::VIDEO_FRAME_END:
            callbackList = &frameEndCbList_;
            break;
        case VideoOutputEventType::VIDEO_FRAME_ERROR:
            callbackList = &errorCbList_;
            break;
        default:
            MEDIA_ERR_LOG("Incorrect video callback event type received from JS");
            return;
    }
    for (auto it = callbackList->begin(); it != callbackList->end();) {
        napi_env env = (*it)->env_;
        if (eventType == VideoOutputEventType::VIDEO_FRAME_ERROR) {
            napi_value errJsResult[ARGS_ONE];
            napi_create_object(env, &errJsResult[PARAM0]);
            napi_create_int32(env, value, &propValue);
            napi_set_named_property(env, errJsResult[PARAM0], "code", propValue);
            napi_get_reference_value(env, (*it)->cb_, &callback); // should errorcode be valued as -1
            napi_call_function(env, nullptr, callback, ARGS_ONE, errJsResult, &retVal);
        } else {
            napi_get_undefined(env, &result[PARAM1]);
            napi_get_reference_value(env, (*it)->cb_, &callback);
            napi_call_function(env, nullptr, callback, ARGS_TWO, result, &retVal);
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
}

void VideoCallbackListener::SaveCallbackReference(const std::string& eventType, napi_value callback, bool isOnce)
{
    std::lock_guard<std::mutex> lock(videoOutputMutex_);
    std::vector<std::shared_ptr<AutoRef>>* callbackList;
    auto eventTypeEnum = VideoOutputEventTypeHelper.ToEnum(eventType);
    switch (eventTypeEnum) {
        case VideoOutputEventType::VIDEO_FRAME_START:
            callbackList = &frameStartCbList_;
            break;
        case VideoOutputEventType::VIDEO_FRAME_END:
            callbackList = &frameEndCbList_;
            break;
        case VideoOutputEventType::VIDEO_FRAME_ERROR:
            callbackList = &errorCbList_;
            break;
        default:
            MEDIA_ERR_LOG("Incorrect video callback event type received from JS");
            CameraNapiUtils::ThrowError(env_, INVALID_ARGUMENT, "Incorrect video callback event type received from JS");
            return;
    }
    for (auto it = callbackList->begin(); it != callbackList->end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        CHECK_AND_RETURN_LOG(!isSameCallback, "SaveCallbackReference: has same callback, nothing to do");
    }
    napi_ref callbackRef = nullptr;
    const int32_t refCount = 1;
    napi_status status = napi_create_reference(env_, callback, refCount, &callbackRef);
    CHECK_AND_RETURN_LOG(status == napi_ok && callbackRef != nullptr, "creating reference for callback fail");
    std::shared_ptr<AutoRef> cb = std::make_shared<AutoRef>(env_, callbackRef, isOnce);
    callbackList->push_back(cb);
}

void VideoCallbackListener::RemoveCallbackRef(napi_env env, napi_value callback, const std::string &eventType)
{
    std::lock_guard<std::mutex> lock(videoOutputMutex_);
    if (callback == nullptr) {
        MEDIA_INFO_LOG("RemoveCallbackRef: js callback is nullptr, remove all callback reference");
        RemoveAllCallbacks(eventType);
        return;
    }
    std::vector<std::shared_ptr<AutoRef>> *callbackList;
    auto eventTypeEnum = VideoOutputEventTypeHelper.ToEnum(eventType);
    switch (eventTypeEnum) {
        case VideoOutputEventType::VIDEO_FRAME_START:
            callbackList = &frameStartCbList_;
            break;
        case VideoOutputEventType::VIDEO_FRAME_END:
            callbackList = &frameEndCbList_;
            break;
        case VideoOutputEventType::VIDEO_FRAME_ERROR:
            callbackList = &errorCbList_;
            break;
        default:
            MEDIA_ERR_LOG("Incorrect video callback event type received from JS");
            CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "Incorrect video callback event type received from JS");
            return;
    }
    for (auto it = callbackList->begin(); it != callbackList->end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        if (isSameCallback) {
            MEDIA_INFO_LOG("RemoveCallbackRef: find js callback, delete it");
            napi_status status = napi_delete_reference(env_, (*it)->cb_);
            (*it)->cb_ = nullptr;
            CHECK_AND_RETURN_LOG(status == napi_ok, "RemoveCallbackRef: delete reference for callback fail");
            callbackList->erase(it);
            return;
        }
    }
    MEDIA_INFO_LOG("RemoveCallbackRef: js callback no find");
}

void VideoCallbackListener::RemoveAllCallbacks(const std::string &eventType)
{
    std::vector<std::shared_ptr<AutoRef>> *callbackList;
    auto eventTypeEnum = VideoOutputEventTypeHelper.ToEnum(eventType);
    switch (eventTypeEnum) {
        case VideoOutputEventType::VIDEO_FRAME_START:
            callbackList = &frameStartCbList_;
            break;
        case VideoOutputEventType::VIDEO_FRAME_END:
            callbackList = &frameEndCbList_;
            break;
        case VideoOutputEventType::VIDEO_FRAME_ERROR:
            callbackList = &errorCbList_;
            break;
        default:
            MEDIA_ERR_LOG("Incorrect video callback event type received from JS");
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

VideoOutputNapi::VideoOutputNapi() : env_(nullptr), wrapper_(nullptr)
{
}

VideoOutputNapi::~VideoOutputNapi()
{
    MEDIA_DEBUG_LOG("~VideoOutputNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (videoOutput_) {
        videoOutput_ = nullptr;
    }
    if (videoCallback_) {
        videoCallback_ = nullptr;
    }
}

void VideoOutputNapi::VideoOutputNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("VideoOutputNapiDestructor is called");
    VideoOutputNapi* videoOutput = reinterpret_cast<VideoOutputNapi*>(nativeObject);
    if (videoOutput != nullptr) {
        delete videoOutput;
    }
}

napi_value VideoOutputNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor video_output_props[] = {
        DECLARE_NAPI_FUNCTION("start", Start),
        DECLARE_NAPI_FUNCTION("stop", Stop),
        DECLARE_NAPI_FUNCTION("getFrameRateRange", GetFrameRateRange),
        DECLARE_NAPI_FUNCTION("setFrameRateRange", SetFrameRateRange),
        DECLARE_NAPI_FUNCTION("setFrameRate", SetFrameRate),
        DECLARE_NAPI_FUNCTION("getActiveFrameRate", GetActiveFrameRate),
        DECLARE_NAPI_FUNCTION("getSupportedFrameRates", GetSupportedFrameRates),
        DECLARE_NAPI_FUNCTION("release", Release),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("once", Once),
        DECLARE_NAPI_FUNCTION("off", Off)
    };

    status = napi_define_class(env, CAMERA_VIDEO_OUTPUT_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               VideoOutputNapiConstructor, nullptr,
                               sizeof(video_output_props) / sizeof(video_output_props[PARAM0]),
                               video_output_props, &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_VIDEO_OUTPUT_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

// Constructor callback
napi_value VideoOutputNapi::VideoOutputNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("VideoOutputNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<VideoOutputNapi> obj = std::make_unique<VideoOutputNapi>();
        if (obj != nullptr) {
            obj->env_ = env;
            obj->videoOutput_ = sVideoOutput_;

            status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                               VideoOutputNapi::VideoOutputNapiDestructor, nullptr, nullptr);
            if (status == napi_ok) {
                obj.release();
                return thisVar;
            } else {
                MEDIA_ERR_LOG("Failure wrapping js to native napi");
            }
        }
    }
    MEDIA_ERR_LOG("VideoOutputNapiConstructor call Failed!");
    return result;
}

static napi_value ConvertJSArgsToNative(napi_env env, size_t argc, const napi_value argv[],
    VideoOutputAsyncContext &asyncContext)
{
    MEDIA_DEBUG_LOG("ConvertJSArgsToNative is called");
    std::string str = "";
    std::vector<std::string> strArr;
    std::string order = "";
    const int32_t refCount = 1;
    napi_value result;
    auto context = &asyncContext;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &context->minFrameRate);
        } else if (i == PARAM1 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &context->maxFrameRate);
        } else if (i == PARAM2 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

static void CommonCompleteCallback(napi_env env, napi_status status, void* data)
{
    MEDIA_DEBUG_LOG("CommonCompleteCallback is called");
    auto context = static_cast<VideoOutputAsyncContext*>(data);

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
        CameraNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                             context->work, *jsContext);
    }
    delete context;
}

sptr<VideoOutput> VideoOutputNapi::GetVideoOutput()
{
    return videoOutput_;
}

bool VideoOutputNapi::IsVideoOutput(napi_env env, napi_value obj)
{
    MEDIA_DEBUG_LOG("IsVideoOutput is called");
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

napi_value VideoOutputNapi::CreateVideoOutput(napi_env env, VideoProfile &profile, std::string surfaceId)
{
    MEDIA_DEBUG_LOG("CreateVideoOutput is called");
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
        if (surface == nullptr) {
            MEDIA_ERR_LOG("failed to get surface from SurfaceUtils");
            return result;
        }
        surface->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
        int retCode = CameraManager::GetInstance()->CreateVideoOutput(profile, surface, &sVideoOutput_);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        if (sVideoOutput_ == nullptr) {
            MEDIA_ERR_LOG("failed to create VideoOutput");
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sVideoOutput_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create video output instance");
        }
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("CreateVideoOutput call Failed!");
    return result;
}

napi_value VideoOutputNapi::Start(napi_env env, napi_callback_info info)
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
    std::unique_ptr<VideoOutputAsyncContext> asyncContext = std::make_unique<VideoOutputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }
        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Start");
        status = napi_create_async_work(env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<VideoOutputAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "VideoOutputNapi::Start";
                context->taskId = CameraNapiUtils::IncreamentAndGet(videoOutputTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr && context->objectInfo->videoOutput_ != nullptr) {
                    context->bRetBool = false;
                    context->errorCode = ((sptr<VideoOutput> &)(context->objectInfo->videoOutput_))->Start();
                    context->status = context->errorCode == 0;
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for VideoOutputNapi::Start");
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

napi_value VideoOutputNapi::Stop(napi_env env, napi_callback_info info)
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
    NAPI_ASSERT(env, argc <= 1, "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    std::unique_ptr<VideoOutputAsyncContext> asyncContext = std::make_unique<VideoOutputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }
        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Stop");
        status = napi_create_async_work(env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<VideoOutputAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "VideoOutputNapi::Stop";
                context->taskId = CameraNapiUtils::IncreamentAndGet(videoOutputTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr && context->objectInfo->videoOutput_ != nullptr) {
                    context->bRetBool = false;
                    context->errorCode = ((sptr<VideoOutput> &)(context->objectInfo->videoOutput_))->Stop();
                    context->status = true;
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for VideoOutputNapi::Stop");
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

void GetFrameRateRangeAsyncCallbackComplete(napi_env env, napi_status status, void* data)
{
    MEDIA_DEBUG_LOG("GetFrameRateRangeAsyncCallbackComplete is called");
    auto context = static_cast<VideoOutputAsyncContext*>(data);
    napi_value frameRateRange = nullptr;

    CAMERA_NAPI_CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = true;
    napi_get_undefined(env, &jsContext->error);
    if ((!context->vecFrameRateRangeList.empty()) && (napi_create_array(env, &frameRateRange) == napi_ok)) {
        int32_t j = 0;
        for (size_t i = 0; i < context->vecFrameRateRangeList.size(); i++) {
            int32_t  frameRate = context->vecFrameRateRangeList[i];
            napi_value value;
            if (napi_create_int32(env, frameRate, &value) == napi_ok) {
                napi_set_element(env, frameRateRange, j, value);
                j++;
            }
        }
        jsContext->data = frameRateRange;
    } else {
        MEDIA_ERR_LOG("vecFrameRateRangeList is empty or failed to create array!");
        CameraNapiUtils::CreateNapiErrorObject(env, context->errorCode,
            "vecFrameRateRangeList is empty or failed to create array!", jsContext);
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

napi_value VideoOutputNapi::SetFrameRate(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetFrameRate is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
 
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_TWO), "requires 2 parameters maximum.");
 
    napi_get_undefined(env, &result);
    VideoOutputNapi* videoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&videoOutputNapi));
    if (status == napi_ok && videoOutputNapi != nullptr) {
        int32_t minFrameRate;
        napi_get_value_int32(env, argv[PARAM0], &minFrameRate);
        int32_t maxFrameRate;
        napi_get_value_int32(env, argv[PARAM1], &maxFrameRate);
        int32_t retCode = videoOutputNapi->videoOutput_->SetFrameRate(minFrameRate, maxFrameRate);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            MEDIA_ERR_LOG("PreviewOutputNapi::SetFrameRate! %{public}d", retCode);
            return result;
        }
    } else {
        MEDIA_ERR_LOG("SetFrameRate call Failed!");
    }
    return result;
}
 
napi_value VideoOutputNapi::GetActiveFrameRate(napi_env env, napi_callback_info info)
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
    VideoOutputNapi* videoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&videoOutputNapi));
    if (status == napi_ok && videoOutputNapi != nullptr) {
        std::vector<int32_t> frameRateRange = videoOutputNapi->videoOutput_->GetFrameRateRange();
        CameraNapiUtils::CreateFrameRateJSArray(env, frameRateRange, result);
    } else {
        MEDIA_ERR_LOG("GetFrameRate call failed!");
    }
    return result;
}
 
napi_value VideoOutputNapi::GetSupportedFrameRates(napi_env env, napi_callback_info info)
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
    VideoOutputNapi* videoOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&videoOutputNapi));
    if (status == napi_ok && videoOutputNapi != nullptr) {
        std::vector<std::vector<int32_t>> supportedFrameRatesRange =
                                          videoOutputNapi->videoOutput_->GetSupportedFrameRates();
        result = CameraNapiUtils::CreateSupportFrameRatesJSArray(env, supportedFrameRatesRange);
    } else {
        MEDIA_ERR_LOG("GetSupportedFrameRates call failed!");
    }
    return result;
}

napi_value VideoOutputNapi::GetFrameRateRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetFrameRateRange is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc <= ARGS_ONE), "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    auto asyncContext = std::make_unique<VideoOutputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }
        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "GetFrameRateRange");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<VideoOutputAsyncContext*>(data);
                context->status = false;
                if (context->objectInfo != nullptr) {
                    if (!context->vecFrameRateRangeList.empty()) {
                        context->status = true;
                    } else {
                        context->status = false;
                        MEDIA_ERR_LOG("GetFrameRateRange vecFrameRateRangeList is empty!");
                    }
                }
            },
            GetFrameRateRangeAsyncCallbackComplete, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for GetFrameRateRange");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
            asyncContext.release();
        }
    } else {
        MEDIA_ERR_LOG("GetFrameRateRange call Failed!");
    }
    return result;
}

bool isFrameRateRangeAvailable(napi_env env, void* data)
{
    MEDIA_DEBUG_LOG("isFrameRateRangeAvailable is called");
    bool invalidFrameRate = true;
    const int32_t FRAME_RATE_RANGE_STEP = 2;
    auto context = static_cast<VideoOutputAsyncContext*>(data);
    if (context == nullptr) {
        MEDIA_ERR_LOG("Async context is null");
        return invalidFrameRate;
    }

    if (!context->vecFrameRateRangeList.empty()) {
        for (size_t i = 0; i < (context->vecFrameRateRangeList.size() - 1); i += FRAME_RATE_RANGE_STEP) {
            int32_t minVal = context->vecFrameRateRangeList[i];
            int32_t maxVal = context->vecFrameRateRangeList[i + 1];
            if ((context->minFrameRate == minVal) && (context->maxFrameRate == maxVal)) {
                invalidFrameRate = false;
                break;
            }
        }
    } else {
        MEDIA_ERR_LOG("isFrameRateRangeAvailable: vecFrameRateRangeList is empty!");
    }
    return invalidFrameRate;
}

napi_value VideoOutputNapi::SetFrameRateRange(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetFrameRateRange is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value resource = nullptr;
    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_TWO || argc == ARGS_THREE), "requires 3 parameters maximum");

    napi_get_undefined(env, &result);
    auto asyncContext = std::make_unique<VideoOutputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        CAMERA_NAPI_CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");
        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "SetFrameRateRange");
        status = napi_create_async_work(
            env, nullptr, resource,
            SetFrameRateRangeAsyncTask,
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for SetFrameRateRange");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
            asyncContext.release();
        }
    } else {
        MEDIA_ERR_LOG("SetFrameRateRange call Failed!");
    }
    return result;
}

void VideoOutputNapi::SetFrameRateRangeAsyncTask(napi_env env, void* data)
{
    auto context = static_cast<VideoOutputAsyncContext*>(data);
    context->status = false;
    // Start async trace
    context->funcName = "VideoOutputNapi::SetFrameRateRange";
    context->taskId = CameraNapiUtils::IncreamentAndGet(videoOutputTaskId);
    CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
    if (context->objectInfo != nullptr) {
        context->bRetBool = false;
        bool isValidRange = isFrameRateRangeAvailable(env, data);
        if (!isValidRange) {
            context->status = true;
        } else {
            MEDIA_ERR_LOG("Failed to get range values for SetFrameRateRange");
            context->errorMsg = "Failed to get range values for SetFrameRateRange";
        }
    }
}

napi_value VideoOutputNapi::Release(napi_env env, napi_callback_info info)
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
    NAPI_ASSERT(env, argc <= 1, "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    std::unique_ptr<VideoOutputAsyncContext> asyncContext = std::make_unique<VideoOutputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Release");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<VideoOutputAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "VideoOutputNapi::Release";
                context->taskId = CameraNapiUtils::IncreamentAndGet(videoOutputTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr && context->objectInfo->videoOutput_ != nullptr) {
                    context->bRetBool = false;
                    context->status = true;
                    ((sptr<VideoOutput> &)(context->objectInfo->videoOutput_))->Release();
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for VideoOutputNapi::Release");
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

void VideoOutputNapi::RegisterFrameStartCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (videoCallback_ == nullptr) {
        videoCallback_ = make_shared<VideoCallbackListener>(env);
        videoOutput_->SetCallback(videoCallback_);
    }
    videoCallback_->SaveCallbackReference(CONST_VIDEO_FRAME_START, callback, isOnce);
}

void VideoOutputNapi::UnregisterFrameStartCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (videoCallback_ == nullptr) {
        MEDIA_ERR_LOG("videoCallback is null");
        return;
    }
    videoCallback_->RemoveCallbackRef(env, callback, CONST_VIDEO_FRAME_START);
}

void VideoOutputNapi::RegisterFrameEndCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (videoCallback_ == nullptr) {
        videoCallback_ = make_shared<VideoCallbackListener>(env);
        videoOutput_->SetCallback(videoCallback_);
    }
    videoCallback_->SaveCallbackReference(CONST_VIDEO_FRAME_END, callback, isOnce);
}
void VideoOutputNapi::UnregisterFrameEndCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (videoCallback_ == nullptr) {
        MEDIA_ERR_LOG("videoCallback is null");
        return;
    }
    videoCallback_->RemoveCallbackRef(env, callback, CONST_VIDEO_FRAME_END);
}

void VideoOutputNapi::RegisterErrorCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (videoCallback_ == nullptr) {
        videoCallback_ = make_shared<VideoCallbackListener>(env);
        videoOutput_->SetCallback(videoCallback_);
    }
    videoCallback_->SaveCallbackReference(CONST_VIDEO_FRAME_ERROR, callback, isOnce);
}

void VideoOutputNapi::UnregisterErrorCallbackListener(
    napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (videoCallback_ == nullptr) {
        MEDIA_ERR_LOG("videoCallback is null");
        return;
    }
    videoCallback_->RemoveCallbackRef(env, callback, CONST_VIDEO_FRAME_ERROR);
}

const VideoOutputNapi::EmitterFunctions& VideoOutputNapi::GetEmitterFunctions()
{
    static const EmitterFunctions funMap = {
        { CONST_VIDEO_FRAME_START, {
            &VideoOutputNapi::RegisterFrameStartCallbackListener,
            &VideoOutputNapi::UnregisterFrameStartCallbackListener } },
        { CONST_VIDEO_FRAME_END, {
            &VideoOutputNapi::RegisterFrameEndCallbackListener,
            &VideoOutputNapi::UnregisterFrameEndCallbackListener } },
        { CONST_VIDEO_FRAME_ERROR, {
            &VideoOutputNapi::RegisterErrorCallbackListener,
            &VideoOutputNapi::UnregisterErrorCallbackListener } } };
    return funMap;
}

napi_value VideoOutputNapi::On(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<VideoOutputNapi>::On(env, info);
}

napi_value VideoOutputNapi::Once(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<VideoOutputNapi>::Once(env, info);
}

napi_value VideoOutputNapi::Off(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<VideoOutputNapi>::Off(env, info);
}
} // namespace CameraStandard
} // namespace OHOS
