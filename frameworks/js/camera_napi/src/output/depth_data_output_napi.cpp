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

#include "output/depth_data_output_napi.h"

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
#include "camera_output_capability.h"
#include "depth_data_output.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "listener_base.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "native_image.h"
#include "output/photo_napi.h"
#include "pixel_map_napi.h"
#include "refbase.h"
#include "surface_utils.h"
#include "video_key_info.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
thread_local napi_ref DepthDataOutputNapi::sConstructor_ = nullptr;
thread_local sptr<DepthDataOutput> DepthDataOutputNapi::sDepthDataOutput_ = nullptr;
thread_local sptr<Surface> DepthDataOutputNapi::sDepthDataSurface_ = nullptr;
thread_local std::shared_ptr<DepthProfile> DepthDataOutputNapi::depthProfile_ = nullptr;
thread_local uint32_t DepthDataOutputNapi::depthDataOutputTaskId = CAMERA_DEPTH_DATA_OUTPUT_TASKID;
static std::mutex g_depthDataMutex;

DepthDataListener::DepthDataListener(napi_env env, const sptr<Surface> depthDataSurface,
                                     sptr<DepthDataOutput> depthDataOutput)
    : ListenerBase(env), depthDataSurface_(depthDataSurface), depthDataOutput_(depthDataOutput)
{
    if (bufferProcessor_ == nullptr && depthDataSurface != nullptr) {
        bufferProcessor_ = std::make_shared<DepthDataBufferProcessor>(depthDataSurface);
    }
}

void DepthDataListener::OnBufferAvailable()
{
    std::lock_guard<std::mutex> lock(g_depthDataMutex);
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("DepthDataListener::OnBufferAvailable is called");
    if (!depthDataSurface_) {
        MEDIA_ERR_LOG("DepthDataListener napi depthDataSurface_ is null");
        return;
    }
    UpdateJSCallbackAsync(depthDataSurface_);
}

void DepthDataListener::ExecuteDepthData(sptr<SurfaceBuffer> surfaceBuffer) const
{
    MEDIA_INFO_LOG("ExecuteDepthData");
    napi_value result[ARGS_TWO] = {nullptr, nullptr};
    napi_value retVal;

    // create pixelMap
    int32_t depthDataWidth = static_cast<int32_t>(depthProfile_->GetSize().width);
    int32_t depthDataHeight = static_cast<int32_t>(depthProfile_->GetSize().height);
    Media::InitializationOptions opts;
    opts.srcPixelFormat = Media::PixelFormat::RGBA_F16;
    opts.pixelFormat = Media::PixelFormat::RGBA_F16;
    opts.size = { .width = depthDataWidth, .height = depthDataHeight };
    MEDIA_INFO_LOG("ExecuteDepthData depthDataWidth:%{public}d, depthDataHeight: %{public}d",
        depthDataWidth, depthDataHeight);
    const int32_t formatSize = 4;
    auto pixelMap = Media::PixelMap::Create(static_cast<const uint32_t*>(surfaceBuffer->GetVirAddr()),
        depthDataWidth * depthDataHeight * formatSize, 0, depthDataWidth, opts, true);
    if (pixelMap == nullptr) {
        MEDIA_ERR_LOG("create pixelMap failed, pixelMap is null");
    }
    napi_value depthMap;
    napi_get_undefined(env_, &depthMap);
    depthMap = Media::PixelMapNapi::CreatePixelMap(env_, std::move(pixelMap));

    napi_value format;
    napi_get_undefined(env_, &format);
    int32_t nativeFormat = 0;
    nativeFormat = static_cast<int32_t>(depthProfile_->GetCameraFormat());
    napi_create_int32(env_, nativeFormat, &format);

    napi_value qualityLevel;
    napi_get_undefined(env_, &qualityLevel);
    int32_t nativeQualityLevel = 0;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::depthDataQualityLevel, nativeQualityLevel);
    napi_create_int32(env_, nativeQualityLevel, &qualityLevel);

    napi_value accuracy;
    napi_get_undefined(env_, &accuracy);
    int32_t nativeAccuracy = 0;
    nativeAccuracy = static_cast<int32_t>(depthProfile_->GetDataAccuracy());
    napi_create_int32(env_, nativeAccuracy, &accuracy);

    result[1] = DepthDataNapi::CreateDepthData(env_, format, depthMap, qualityLevel, accuracy);

    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback(CONST_DEPTH_DATA_AVAILABLE, callbackNapiPara);
    depthDataSurface_->ReleaseBuffer(surfaceBuffer, -1);
}

void DepthDataListener::UpdateJSCallback(sptr<Surface> depthSurface) const
{
    MEDIA_DEBUG_LOG("DepthDataListener UpdateJSCallback enter");
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;

    SurfaceError surfaceRet = depthSurface->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    if (surfaceRet != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("DepthDataListener Failed to acquire surface buffer");
        return;
    }

    ExecuteDepthData(surfaceBuffer);
}

void DepthDataListener::UpdateJSCallbackAsync(sptr<Surface> depthSurface) const
{
    MEDIA_DEBUG_LOG("DepthDataListener UpdateJSCallbackAsync enter");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (!loop) {
        MEDIA_ERR_LOG("DepthDataListener:UpdateJSCallbackAsync() failed to get event loop");
        return;
    }
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (!work) {
        MEDIA_ERR_LOG("DepthDataListener:UpdateJSCallbackAsync() failed to allocate work");
        return;
    }
    std::unique_ptr<DepthDataListenerInfo> callbackInfo =
        std::unique_ptr<DepthDataListenerInfo> callbackInfo =
        std::make_unique<DepthDataListenerInfo>(
            depthSurface,
            wptr<DepthDataListener>(const_cast<DepthDataListener*>(this))
        );
    work->data = callbackInfo.get();
    MEDIA_DEBUG_LOG("DepthDataListener UpdateJSCallbackAsync uv_queue_work_with_qos start");
    int ret = uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {},
        [](uv_work_t* work, int status) {
            DepthDataListenerInfo* callbackInfo = reinterpret_cast<DepthDataListenerInfo*>(work->data);
            if (callbackInfo) {
                auto listener = callbackInfo->listener_.promote();
                if (listener != nullptr) {
                    listener->UpdateJSCallback(callbackInfo->depthDataSurface_);
                }
                MEDIA_INFO_LOG("DepthDataListener:UpdateJSCallbackAsync() complete");
                callbackInfo->depthDataSurface_ = nullptr;
                callbackInfo->listener_ = nullptr;
                delete callbackInfo;
            }
            delete work;
        },
        uv_qos_user_initiated);
    if (ret) {
        MEDIA_ERR_LOG("DepthDataListenerInfo:UpdateJSCallbackAsync() failed to execute work");
        delete work;
    } else {
        callbackInfo.release();
    }
}

void DepthDataListener::SaveCallback(const std::string eventName, napi_value callback)
{
    MEDIA_INFO_LOG("DepthDataListener::SaveCallback is called eventName:%{public}s", eventName.c_str());
    SaveCallbackReference(eventName, callback, false);
}

void DepthDataListener::RemoveCallback(const std::string eventName, napi_value callback)
{
    MEDIA_INFO_LOG("DepthDataListener::RemoveCallback is called eventName:%{public}s", eventName.c_str());
    RemoveCallbackRef(eventName, callback);
}

void DepthDataListener::SetDepthProfile(std::shared_ptr<DepthProfile> depthProfile)
{
    depthProfile_ = depthProfile;
}

DepthDataOutputCallback::DepthDataOutputCallback(napi_env env) : ListenerBase(env) {}

void DepthDataOutputCallback::OnDepthDataError(const int32_t errorCode) const
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("OnDepthDataError is called, errorCode: %{public}d", errorCode);
    UpdateJSCallbackAsync(DepthDataOutputEventType::DEPTH_DATA_ERROR, errorCode);
}

void DepthDataOutputCallback::UpdateJSCallbackAsync(DepthDataOutputEventType eventType, const int32_t value) const
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
    std::unique_ptr<DepthDataOutputCallbackInfo> callbackInfo =
        std::make_unique<DepthDataOutputCallbackInfo>(eventType, value, shared_from_this());
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        DepthDataOutputCallbackInfo* callbackInfo = reinterpret_cast<DepthDataOutputCallbackInfo *>(work->data);
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

void DepthDataOutputCallback::UpdateJSCallback(DepthDataOutputEventType eventType, const int32_t value) const
{
    MEDIA_DEBUG_LOG("UpdateJSCallback is called");
    napi_value result[ARGS_ONE];
    napi_value retVal;
    napi_value propValue;
    napi_get_undefined(env_, &result[PARAM0]);
    std::string eventName = DepthDataOutputEventTypeHelper.GetKeyString(eventType);
    if (eventName.empty()) {
        MEDIA_WARNING_LOG(
            "DepthDataOutputCallback::UpdateJSCallback, event type is invalid %d", static_cast<int32_t>(eventType));
        return;
    }

    if (eventType == DepthDataOutputEventType::DEPTH_DATA_ERROR) {
        napi_create_object(env_, &result[PARAM0]);
        napi_create_int32(env_, value, &propValue);
        napi_set_named_property(env_, result[PARAM0], "code", propValue);
    }
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_ONE, .argv = result, .result = &retVal };
    ExecuteCallback(eventName, callbackNapiPara);
}

DepthDataOutputNapi::DepthDataOutputNapi() : env_(nullptr) {}

DepthDataOutputNapi::~DepthDataOutputNapi()
{
    MEDIA_DEBUG_LOG("~DepthDataOutputNapi is called");
}

void DepthDataOutputNapi::DepthDataOutputNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("DepthDataOutputNapiDestructor is called");
    DepthDataOutputNapi* cameraObj = reinterpret_cast<DepthDataOutputNapi*>(nativeObject);
    if (cameraObj != nullptr) {
        delete cameraObj;
    }
}

napi_value DepthDataOutputNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor depth_data_output_props[] = {
        DECLARE_NAPI_FUNCTION("start", Start),
        DECLARE_NAPI_FUNCTION("stop", Stop),
        DECLARE_NAPI_FUNCTION("release", Release),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("once", Once),
        DECLARE_NAPI_FUNCTION("off", Off),
    };

    status = napi_define_class(env, CAMERA_DEPTH_DATA_OUTPUT_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               DepthDataOutputNapiConstructor, nullptr,
                               sizeof(depth_data_output_props) / sizeof(depth_data_output_props[PARAM0]),
                               depth_data_output_props, &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_DEPTH_DATA_OUTPUT_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

// Constructor callback
napi_value DepthDataOutputNapi::DepthDataOutputNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("DepthDataOutputNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<DepthDataOutputNapi> obj = std::make_unique<DepthDataOutputNapi>();
        if (obj != nullptr) {
            obj->env_ = env;
            obj->depthDataOutput_ = sDepthDataOutput_;

            status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                               DepthDataOutputNapi::DepthDataOutputNapiDestructor, nullptr, nullptr);
            if (status == napi_ok) {
                obj.release();
                return thisVar;
            } else {
                MEDIA_ERR_LOG("Failure wrapping js to native napi");
            }
        }
    }
    MEDIA_ERR_LOG("DepthDataOutputNapiConstructor call Failed!");
    return result;
}

static void CommonCompleteCallback(napi_env env, napi_status status, void* data)
{
    MEDIA_DEBUG_LOG("CommonCompleteCallback is called");
    auto context = static_cast<DepthDataOutputAsyncContext*>(data);
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

napi_value DepthDataOutputNapi::CreateDepthDataOutput(napi_env env, DepthProfile& depthProfile)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi CreateDepthDataOutput is called!");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("CreateDepthDataOutput is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    napi_get_undefined(env, &result);
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sptr<Surface> depthDataSurface;
        MEDIA_INFO_LOG("create surface as consumer");
        depthDataSurface = Surface::CreateSurfaceAsConsumer("depthDataOutput");
        sDepthDataSurface_ = depthDataSurface;
        if (depthDataSurface == nullptr) {
            MEDIA_ERR_LOG("failed to get surface");
            return result;
        }

        sptr<IBufferProducer> surfaceProducer = depthDataSurface->GetProducer();
        MEDIA_INFO_LOG("depthProfile width: %{public}d, height: %{public}d, format = %{public}d, "
                       "surface width: %{public}d, height: %{public}d", depthProfile.GetSize().width,
                       depthProfile.GetSize().height, static_cast<int32_t>(depthProfile.GetCameraFormat()),
                       depthDataSurface->GetDefaultWidth(), depthDataSurface->GetDefaultHeight());
        int retCode = CameraManager::GetInstance()->CreateDepthDataOutput(depthProfile, surfaceProducer,
            &sDepthDataOutput_);
        if (!CameraNapiUtils::CheckError(env, retCode) || sDepthDataOutput_ == nullptr) {
            MEDIA_ERR_LOG("failed to create CreateDepthDataOutput");
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sDepthDataOutput_ = nullptr;

        if (status == napi_ok && result != nullptr) {
            depthProfile_ = std::make_shared<DepthProfile>(depthProfile);
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create depth data output instance");
        }
    }
    MEDIA_ERR_LOG("CreateDepthDataOutput call Failed!");
    return result;
}

sptr<DepthDataOutput> DepthDataOutputNapi::GetDepthDataOutput()
{
    return depthDataOutput_;
}

bool DepthDataOutputNapi::IsDepthDataOutput(napi_env env, napi_value obj)
{
    MEDIA_DEBUG_LOG("IsDepthDataOutput is called");
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

napi_value DepthDataOutputNapi::Release(napi_env env, napi_callback_info info)
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
    std::unique_ptr<DepthDataOutputAsyncContext> asyncContext = std::make_unique<DepthDataOutputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Release");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<DepthDataOutputAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "DepthDataOutputNapi::Release";
                context->taskId = CameraNapiUtils::IncrementAndGet(depthDataOutputTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->bRetBool = false;
                    context->status = true;
                    ((sptr<DepthDataOutput>&)(context->objectInfo->depthDataOutput_))->Release();
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for DepthDataOutputNapi::Release");
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

napi_value DepthDataOutputNapi::Start(napi_env env, napi_callback_info info)
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
    std::unique_ptr<DepthDataOutputAsyncContext> asyncContext = std::make_unique<DepthDataOutputAsyncContext>();
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
                auto context = static_cast<DepthDataOutputAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "DepthDataOutputNapi::Start";
                context->taskId = CameraNapiUtils::IncrementAndGet(depthDataOutputTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->bRetBool = false;
                    context->errorCode = context->objectInfo->depthDataOutput_->Start();
                    context->status = context->errorCode == 0;
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for DepthDataOutputNapi::Release");
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

napi_value DepthDataOutputNapi::Stop(napi_env env, napi_callback_info info)
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
    std::unique_ptr<DepthDataOutputAsyncContext> asyncContext = std::make_unique<DepthDataOutputAsyncContext>();
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
                auto context = static_cast<DepthDataOutputAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "DepthDataOutputNapi::Stop";
                context->taskId = CameraNapiUtils::IncrementAndGet(depthDataOutputTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->bRetBool = false;
                    context->errorCode = context->objectInfo->depthDataOutput_->Stop();
                    context->status = context->errorCode == 0;
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for DepthDataOutputNapi::Release");
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

void DepthDataOutputNapi::RegisterDepthDataAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (sDepthDataSurface_ == nullptr) {
        MEDIA_ERR_LOG("sDepthDataSurface_ is null!");
        return;
    }
    if (depthDataListener_ == nullptr) {
        MEDIA_INFO_LOG("new depthDataListener_ and register surface consumer listener");
        sptr<DepthDataListener> depthDataListener = new (std::nothrow) DepthDataListener(env, sDepthDataSurface_,
            depthDataOutput_);
        SurfaceError ret = sDepthDataSurface_->RegisterConsumerListener((
            sptr<IBufferConsumerListener>&)depthDataListener);
        if (ret != SURFACE_ERROR_OK) {
            MEDIA_ERR_LOG("register surface consumer listener failed!");
        }
        depthDataListener_ = depthDataListener;
    }
    depthDataListener_->SetDepthProfile(depthProfile_);
    depthDataListener_->SaveCallback(CONST_DEPTH_DATA_AVAILABLE, callback);
}

void DepthDataOutputNapi::UnregisterDepthDataAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (depthDataListener_ != nullptr) {
        depthDataListener_->RemoveCallback(CONST_DEPTH_DATA_AVAILABLE, callback);
    }
}

void DepthDataOutputNapi::RegisterErrorCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (depthDataCallback_ == nullptr) {
        depthDataCallback_ = std::make_shared<DepthDataOutputCallback>(env);
        depthDataOutput_->SetCallback(depthDataCallback_);
    }
    depthDataCallback_->SaveCallbackReference(CONST_DEPTH_DATA_ERROR, callback, isOnce);
}

void DepthDataOutputNapi::UnregisterErrorCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (depthDataCallback_ == nullptr) {
        MEDIA_ERR_LOG("depthDataCallback is null");
        return;
    }
    depthDataCallback_->RemoveCallbackRef(CONST_DEPTH_DATA_ERROR, callback);
}

const DepthDataOutputNapi::EmitterFunctions& DepthDataOutputNapi::GetEmitterFunctions()
{
    static const EmitterFunctions funMap = {
        { CONST_DEPTH_DATA_AVAILABLE, {
            &DepthDataOutputNapi::RegisterDepthDataAvailableCallbackListener,
            &DepthDataOutputNapi::UnregisterDepthDataAvailableCallbackListener } },
        { CONST_DEPTH_DATA_ERROR, {
            &DepthDataOutputNapi::RegisterErrorCallbackListener,
            &DepthDataOutputNapi::UnregisterErrorCallbackListener } } };
    return funMap;
}

napi_value DepthDataOutputNapi::On(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<DepthDataOutputNapi>::On(env, info);
}

napi_value DepthDataOutputNapi::Once(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<DepthDataOutputNapi>::Once(env, info);
}

napi_value DepthDataOutputNapi::Off(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<DepthDataOutputNapi>::Off(env, info);
}
} // namespace CameraStandard
} // namespace OHOS
