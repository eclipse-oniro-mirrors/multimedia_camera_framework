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
#include "camera_napi_template_utils.h"
#include "camera_napi_utils.h"
#include "input/camera_manager_for_sys.h"
#include "output/depth_data_napi.h"
#include "output/depth_data_output.h"
#include "native_image.h"
#include "pixel_map_napi.h"
#include "refbase.h"
#include "video_key_info.h"
#include "napi/native_node_api.h"

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
    CHECK_RETURN_ELOG(!depthDataSurface_, "DepthDataListener napi depthDataSurface_ is null");
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
    CHECK_PRINT_ELOG(pixelMap == nullptr, "create pixelMap failed, pixelMap is null");
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
    CHECK_RETURN_ELOG(surfaceRet != SURFACE_ERROR_OK, "DepthDataListener Failed to acquire surface buffer");

    ExecuteDepthData(surfaceBuffer);
}

void DepthDataListener::UpdateJSCallbackAsync(sptr<Surface> depthSurface) const
{
    MEDIA_DEBUG_LOG("DepthDataListener UpdateJSCallbackAsync enter");
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    CHECK_RETURN_ELOG(!loop, "DepthDataListener:UpdateJSCallbackAsync() failed to get event loop");
    uv_work_t* work = new (std::nothrow) uv_work_t;
    CHECK_RETURN_ELOG(!work, "DepthDataListener:UpdateJSCallbackAsync() failed to allocate work");
    std::unique_ptr<DepthDataListenerInfo> callbackInfo =
        std::make_unique<DepthDataListenerInfo>(depthSurface, shared_from_this());
    work->data = callbackInfo.get();
    MEDIA_DEBUG_LOG("DepthDataListener UpdateJSCallbackAsync uv_queue_work_with_qos_internal start");
    int ret = uv_queue_work_with_qos_internal(
        loop, work, [](uv_work_t* work) {},
        [](uv_work_t* work, int status) {
            DepthDataListenerInfo* callbackInfo = reinterpret_cast<DepthDataListenerInfo*>(work->data);
            if (callbackInfo) {
                auto listener = callbackInfo->listener_.lock();
                CHECK_EXECUTE(listener != nullptr, listener->UpdateJSCallback(callbackInfo->depthDataSurface_));
                MEDIA_INFO_LOG("DepthDataListener:UpdateJSCallbackAsync() complete");
                callbackInfo->depthDataSurface_ = nullptr;
                callbackInfo->listener_.reset();
                delete callbackInfo;
            }
            delete work;
        },
        uv_qos_user_initiated, "DepthDataListener::UpdateJSCallbackAsync[DepthDataAvailable]");
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
    std::unique_ptr<DepthDataOutputCallbackInfo> callbackInfo =
        std::make_unique<DepthDataOutputCallbackInfo>(eventType, value, shared_from_this());
    DepthDataOutputCallbackInfo *event = callbackInfo.get();
    auto task = [event]() {
        DepthDataOutputCallbackInfo* callbackInfo = reinterpret_cast<DepthDataOutputCallbackInfo *>(event);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            CHECK_EXECUTE(listener, listener->UpdateJSCallback(callbackInfo->eventType_, callbackInfo->value_));
            delete callbackInfo;
        }
    };
    std::unordered_map<std::string, std::string> params = {
        {"eventType", DepthDataOutputEventTypeHelper.GetKeyString(eventType)},
    };
    string taskName = CameraNapiUtils::GetTaskName("DepthDataOutputCallback::UpdateJSCallbackAsync", params);
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate, taskName.c_str())) {
        MEDIA_ERR_LOG("failed to execute work");
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

void DepthDataOutputNapi::Init(napi_env env)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;

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
    CHECK_RETURN_ELOG(status != napi_ok, "DepthDataOutputNapi defined class failed");
    status = NapiRefManager::CreateMemSafetyRef(env, ctorObj, &sConstructor_);
    CHECK_RETURN_ELOG(status != napi_ok, "DepthDataOutputNapi Init failed");
    MEDIA_DEBUG_LOG("DepthDataOutputNapi Init success");
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
    auto depthDataOutputAsyncContext = static_cast<DepthDataOutputAsyncContext*>(data);
    CHECK_RETURN_ELOG(depthDataOutputAsyncContext == nullptr, "Async context is null");
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    if (!depthDataOutputAsyncContext->status) {
        CameraNapiUtils::CreateNapiErrorObject(env, depthDataOutputAsyncContext->errorCode,
            depthDataOutputAsyncContext->errorMsg.c_str(), jsContext);
    } else {
        jsContext->status = true;
        napi_get_undefined(env, &jsContext->error);
        if (depthDataOutputAsyncContext->bRetBool) {
            napi_get_boolean(env, depthDataOutputAsyncContext->status, &jsContext->data);
        } else {
            napi_get_undefined(env, &jsContext->data);
        }
    }
    if (!depthDataOutputAsyncContext->funcName.empty() && depthDataOutputAsyncContext->taskId > 0) {
        // Finish async trace
        CAMERA_FINISH_ASYNC_TRACE(depthDataOutputAsyncContext->funcName, depthDataOutputAsyncContext->taskId);
        jsContext->funcName = depthDataOutputAsyncContext->funcName;
    }
    CHECK_EXECUTE(depthDataOutputAsyncContext->work != nullptr,
        CameraNapiUtils::InvokeJSAsyncMethod(env, depthDataOutputAsyncContext->deferred,
            depthDataOutputAsyncContext->callbackRef, depthDataOutputAsyncContext->work, *jsContext));
    delete depthDataOutputAsyncContext;
}

napi_value DepthDataOutputNapi::CreateDepthDataOutput(napi_env env, DepthProfile& depthProfile)
{
    MEDIA_DEBUG_LOG("CreateDepthDataOutput is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    napi_get_undefined(env, &result);
    if (sConstructor_ == nullptr) {
        DepthDataOutputNapi::Init(env);
        CHECK_RETURN_RET_ELOG(sConstructor_ == nullptr, result, "sConstructor_ is null");
    }
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sptr<Surface> depthDataSurface;
        MEDIA_INFO_LOG("create surface as consumer");
        depthDataSurface = Surface::CreateSurfaceAsConsumer("depthDataOutput");
        sDepthDataSurface_ = depthDataSurface;
        CHECK_RETURN_RET_ELOG(depthDataSurface == nullptr, result, "failed to get surface");

        sptr<IBufferProducer> surfaceProducer = depthDataSurface->GetProducer();
        MEDIA_INFO_LOG("depthProfile width: %{public}d, height: %{public}d, format = %{public}d, "
                       "surface width: %{public}d, height: %{public}d", depthProfile.GetSize().width,
                       depthProfile.GetSize().height, static_cast<int32_t>(depthProfile.GetCameraFormat()),
                       depthDataSurface->GetDefaultWidth(), depthDataSurface->GetDefaultHeight());
        int retCode = CameraManagerForSys::GetInstance()->CreateDepthDataOutput(depthProfile, surfaceProducer,
            &sDepthDataOutput_);
        CHECK_RETURN_RET_ELOG(!CameraNapiUtils::CheckError(env, retCode) || sDepthDataOutput_ == nullptr,
            result, "failed to create CreateDepthDataOutput");
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
            MEDIA_DEBUG_LOG("DepthDataOutputNapi::IsDepthDataOutput is failed");
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
    napi_value releaseArgv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, releaseArgv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    std::unique_ptr<DepthDataOutputAsyncContext> asyncContext = std::make_unique<DepthDataOutputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        CHECK_EXECUTE(argc == ARGS_ONE,
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, releaseArgv[PARAM0], refCount, asyncContext->callbackRef));

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
    napi_value startArgv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, startArgv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    std::unique_ptr<DepthDataOutputAsyncContext> asyncContext = std::make_unique<DepthDataOutputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        CHECK_EXECUTE(argc == ARGS_ONE,
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, startArgv[PARAM0], refCount, asyncContext->callbackRef));

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
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for DepthDataOutputNapi::Start");
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
        CHECK_EXECUTE(argc == ARGS_ONE,
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef));

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
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for DepthDataOutputNapi::Stop");
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
    CHECK_RETURN_ELOG(sDepthDataSurface_ == nullptr, "sDepthDataSurface_ is null!");
    if (depthDataListener_ == nullptr) {
        MEDIA_INFO_LOG("new depthDataListener_ and register surface consumer listener");
        sptr<DepthDataListener> depthDataListener = new (std::nothrow) DepthDataListener(env, sDepthDataSurface_,
            depthDataOutput_);
        SurfaceError ret = sDepthDataSurface_->RegisterConsumerListener((
            sptr<IBufferConsumerListener>&)depthDataListener);
        CHECK_PRINT_ELOG(ret != SURFACE_ERROR_OK, "register surface consumer listener failed!");
        depthDataListener_ = depthDataListener;
    }
    if (depthDataListener_ == nullptr) {
        MEDIA_ERR_LOG("depthDataListener_ is null!");
        return;
    }
    depthDataListener_->SetDepthProfile(depthProfile_);
    depthDataListener_->SaveCallback(CONST_DEPTH_DATA_AVAILABLE, callback);
}

void DepthDataOutputNapi::UnregisterDepthDataAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    CHECK_EXECUTE(depthDataListener_ != nullptr,
        depthDataListener_->RemoveCallback(CONST_DEPTH_DATA_AVAILABLE, callback));
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
    CHECK_RETURN_ELOG(depthDataCallback_ == nullptr, "depthDataCallback is null");
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

extern "C" napi_value createDepthDataOutputInstance(napi_env env, DepthProfile& depthProfile)
{
    MEDIA_DEBUG_LOG("createDepthDataOutputInstance is called");
    return DepthDataOutputNapi::CreateDepthDataOutput(env, depthProfile);
}

extern "C" bool checkAndGetOutput(napi_env env, napi_value obj, sptr<CaptureOutput> &output)
{
    if (DepthDataOutputNapi::IsDepthDataOutput(env, obj)) {
        MEDIA_DEBUG_LOG("depth data output adding..");
        DepthDataOutputNapi* depthDataOutputNapiObj = nullptr;
        napi_unwrap(env, obj, reinterpret_cast<void**>(&depthDataOutputNapiObj));
        CHECK_RETURN_RET_ELOG(depthDataOutputNapiObj == nullptr, false, "depthDataOutputNapiObj unwrap failed!");
        output = depthDataOutputNapiObj->GetDepthDataOutput();
    } else {
        return false;
    }
    return true;
}
} // namespace CameraStandard
} // namespace OHOS
