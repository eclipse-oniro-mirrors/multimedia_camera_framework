/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "output/depth_data_napi.h"

#include "camera_log.h"
#include "camera_napi_utils.h"
#include "camera_util.h"
#include "napi/native_common.h"

namespace OHOS {
namespace CameraStandard {
thread_local napi_ref DepthDataNapi::sConstructor_ = nullptr;
thread_local napi_value DepthDataNapi::sFormat_ = nullptr;
thread_local napi_value DepthDataNapi::sDepthMap_ = nullptr;
thread_local napi_value DepthDataNapi::sQualityLevel_ = nullptr;
thread_local napi_value DepthDataNapi::sAccuracy_ = nullptr;
thread_local uint32_t DepthDataNapi::depthDataTaskId = DEPTH_DATA_TASKID;

DepthDataNapi::DepthDataNapi() : env_(nullptr), format_(nullptr), depthMap_(nullptr),
    qualityLevel_(nullptr), accuracy_(nullptr)
{}

DepthDataNapi::~DepthDataNapi()
{
    MEDIA_DEBUG_LOG("~PhotoNapi is called");
}

// Constructor callback
napi_value DepthDataNapi::DepthDataNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("DepthDataNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<DepthDataNapi> obj = std::make_unique<DepthDataNapi>();
        obj->env_ = env;
        obj->format_ = sFormat_;
        obj->depthMap_ = sDepthMap_;
        obj->qualityLevel_ = sQualityLevel_;
        obj->accuracy_ = sAccuracy_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           DepthDataNapi::DepthDataNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("DepthDataNapiConstructor call Failed!");
    return result;
}

void DepthDataNapi::DepthDataNapiDestructor(napi_env env, void *nativeObject, void *finalize)
{
    MEDIA_DEBUG_LOG("DepthDataNapiDestructor is called");
    DepthDataNapi* depthData = reinterpret_cast<DepthDataNapi*>(nativeObject);
    if (depthData != nullptr) {
        delete depthData;
    }
}

napi_value DepthDataNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = PARAM1;

    napi_property_descriptor depth_data_properties[] = {
        DECLARE_NAPI_GETTER("format", GetFormat),
        DECLARE_NAPI_GETTER("depthMap", GetDepthMap),
        DECLARE_NAPI_GETTER("qualityLevel", GetQualityLevel),
        DECLARE_NAPI_GETTER("dataAccurary", GetAccuracy),
        DECLARE_NAPI_FUNCTION("release", Release),
    };

    status = napi_define_class(env, DEPTH_DATA_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               DepthDataNapiConstructor, nullptr,
                               sizeof(depth_data_properties) / sizeof(depth_data_properties[PARAM0]),
                               depth_data_properties, &ctorObj);
    if (status == napi_ok) {
        if (napi_create_reference(env, ctorObj, refCount, &sConstructor_) == napi_ok) {
            status = napi_set_named_property(env, exports, DEPTH_DATA_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call failed!");
    return nullptr;
}

napi_value DepthDataNapi::CreateDepthData(napi_env env, napi_value format, napi_value depthMap,
    napi_value qualityLevel, napi_value accuracy)
{
    MEDIA_DEBUG_LOG("CreateDepthData is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    napi_get_undefined(env, &result);

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sFormat_ = format;
        sDepthMap_ = depthMap;
        sQualityLevel_ = qualityLevel;
        sAccuracy_ = accuracy;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sFormat_ = nullptr;
        sDepthMap_ = nullptr;
        sQualityLevel_ = nullptr;
        sAccuracy_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create depthData obj instance");
        }
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("CreateDepthData call Failed");
    return result;
}

napi_value DepthDataNapi::GetFormat(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetFormat is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    DepthDataNapi* depthDataNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&depthDataNapi));
    if (status == napi_ok && depthDataNapi != nullptr) {
        result = depthDataNapi->format_;
        return result;
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("DepthDataNapi::GetFormat call Failed");
    return result;
}

napi_value DepthDataNapi::GetDepthMap(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetDepthMap is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    DepthDataNapi* depthDataNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&depthDataNapi));
    if (status == napi_ok && depthDataNapi != nullptr) {
        result = depthDataNapi->depthMap_;
        return result;
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("DepthDataNapi::GetDepthMap call Failed");
    return result;
}

napi_value DepthDataNapi::GetQualityLevel(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetQualityLevel is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    DepthDataNapi* depthDataNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&depthDataNapi));
    if (status == napi_ok && depthDataNapi != nullptr) {
        result = depthDataNapi->qualityLevel_;
        return result;
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("DepthDataNapi::GetQualityLevel call Failed");
    return result;
}

napi_value DepthDataNapi::GetAccuracy(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetAccuracy is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    DepthDataNapi* depthDataNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&depthDataNapi));
    if (status == napi_ok && depthDataNapi != nullptr) {
        result = depthDataNapi->accuracy_;
        return result;
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("DepthDataNapi::GetAccuracy call Failed");
    return result;
}

napi_value DepthDataNapi::Release(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Release is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value resource = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    std::unique_ptr<DepthDataAsyncContext> asyncContext = std::make_unique<DepthDataAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Release");

        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<DepthDataAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "DepthDataNapi::Release";
                context->taskId = CameraNapiUtils::IncrementAndGet(depthDataTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->status = true;
                    context->objectInfo->format_ = nullptr;
                    context->objectInfo->depthMap_ = nullptr;
                    context->objectInfo->qualityLevel_ = nullptr;
                    context->objectInfo->accuracy_ = nullptr;
                }
            },
            [](napi_env env, napi_status status, void* data) {
                auto context = static_cast<DepthDataAsyncContext*>(data);
                napi_resolve_deferred(env, context->deferred, nullptr);
                napi_delete_async_work(env, context->work);
                delete context->objectInfo;
                delete context;
            }, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for DepthDataNapi::Release");
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

}  // namespace CameraStandard
}  // namespace OHOS
