/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "image_napi.h"
#include "pixel_map_napi.h"
#include "hilog/log.h"
#include "camera_log.h"
#include "output/deferred_photo_proxy_napi.h"

namespace OHOS {
namespace CameraStandard {
thread_local napi_ref DeferredPhotoProxyNapi::sConstructor_ = nullptr;
thread_local napi_value DeferredPhotoProxyNapi::sThumbnailPixelMap_ = nullptr;
thread_local sptr<DeferredPhotoProxy> DeferredPhotoProxyNapi::sDeferredPhotoProxy_ = nullptr;
thread_local uint32_t DeferredPhotoProxyNapi::deferredPhotoProxyTaskId = DEFERRED_PHOTO_PROXY_TASKID;
DeferredPhotoProxyNapi::DeferredPhotoProxyNapi() : env_(nullptr), wrapper_(nullptr), thumbnailPixelMap_(nullptr)
{
}

DeferredPhotoProxyNapi::~DeferredPhotoProxyNapi()
{
    MEDIA_DEBUG_LOG("~DeferredPhotoProxyNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    thumbnailPixelMap_ = nullptr;
    if (deferredPhotoProxy_) {
        deferredPhotoProxy_ = nullptr;
    }
}

// Constructor callback
napi_value DeferredPhotoProxyNapi::DeferredPhotoProxyNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("DeferredPhotoProxyNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<DeferredPhotoProxyNapi> obj = std::make_unique<DeferredPhotoProxyNapi>();
        obj->env_ = env;
        obj->deferredPhotoProxy_ = sDeferredPhotoProxy_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           DeferredPhotoProxyNapi::DeferredPhotoProxyNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("DeferredPhotoProxyNapiConstructor call Failed!");
    return result;
}

void DeferredPhotoProxyNapi::DeferredPhotoProxyNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("DeferredPhotoProxyNapiDestructor is called");
    DeferredPhotoProxyNapi* deferredPhotoProxy = reinterpret_cast<DeferredPhotoProxyNapi*>(nativeObject);
    if (deferredPhotoProxy != nullptr) {
        delete deferredPhotoProxy;
    }
}

napi_value DeferredPhotoProxyNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor deferred_photo_proxy_properties[] = {
        // DeferredPhotoProxy
        DECLARE_NAPI_FUNCTION("getThumbnail", GetThumbnail),
        DECLARE_NAPI_FUNCTION("release", Release),
    };

    status = napi_define_class(env, DEFERRED_PHOTO_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
        DeferredPhotoProxyNapiConstructor, nullptr,
        sizeof(deferred_photo_proxy_properties) / sizeof(deferred_photo_proxy_properties[PARAM0]),
        deferred_photo_proxy_properties, &ctorObj);
    if (status == napi_ok) {
        if (napi_create_reference(env, ctorObj, refCount, &sConstructor_) == napi_ok) {
            status = napi_set_named_property(env, exports, DEFERRED_PHOTO_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value DeferredPhotoProxyNapi::CreateDeferredPhotoProxy(napi_env env, sptr<DeferredPhotoProxy> deferredPhotoProxy)
{
    MEDIA_DEBUG_LOG("CreateDeferredPhotoProxy is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    napi_get_undefined(env, &result);
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sDeferredPhotoProxy_ = deferredPhotoProxy;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sDeferredPhotoProxy_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create deferredPhotoProxy obj instance");
        }
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("CreateDeferredPhotoProxy call Failed");
    return result;
}

napi_value DeferredPhotoProxyNapi::GetThumbnail(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetThumbnail is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value resource = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    napi_get_undefined(env, &result);
    std::unique_ptr<DeferredPhotoProxAsyncContext> asyncContext = std::make_unique<DeferredPhotoProxAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "GetThumbnail");
        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<DeferredPhotoProxAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "DeferredPhotoProxyNapi::GetThumbnail";
                context->taskId = CameraNapiUtils::IncreamentAndGet(deferredPhotoProxyTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->status = true;
                }
            },
            DeferredPhotoAsyncTaskComplete, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for DeferredPhotoProxyNapi::GetThumbnail");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
            asyncContext.release();
        }
    } else {
        MEDIA_ERR_LOG("GetThumbnail call Failed!");
    }
    return result;
}

void DeferredPhotoProxyNapi::DeferredPhotoAsyncTaskComplete(napi_env env, napi_status status, void* data)
{
    auto context = static_cast<DeferredPhotoProxAsyncContext*>(data);
    void* fdAddr = context->objectInfo->deferredPhotoProxy_->GetFileDataAddr();
    int32_t thumbnailWidth = context->objectInfo->deferredPhotoProxy_->GetWidth();
    int32_t thumbnailHeight = context->objectInfo->deferredPhotoProxy_->GetHeight();
    Media::InitializationOptions opts;
    opts.srcPixelFormat = Media::PixelFormat::RGBA_8888;
    opts.pixelFormat = Media::PixelFormat::RGBA_8888;
    opts.size = { .width = thumbnailWidth, .height = thumbnailHeight };
    MEDIA_INFO_LOG("thumbnailWidth:%{public}d, thumbnailheight: %{public}d",
        thumbnailWidth, thumbnailHeight);
    auto pixelMap = Media::PixelMap::Create(static_cast<const uint32_t*>(fdAddr),
        thumbnailWidth * thumbnailHeight * 4, 0, thumbnailWidth, opts, true);
    napi_value thumbnail = Media::PixelMapNapi::CreatePixelMap(env, std::move(pixelMap));
    napi_resolve_deferred(env, context->deferred, thumbnail);
    napi_delete_async_work(env, context->work);
}

napi_value DeferredPhotoProxyNapi::Release(napi_env env, napi_callback_info info)
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
    std::unique_ptr<DeferredPhotoProxAsyncContext> asyncContext = std::make_unique<DeferredPhotoProxAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Release");
        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<DeferredPhotoProxAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "DeferredPhotoProxyNapi::Release";
                context->taskId = CameraNapiUtils::IncreamentAndGet(deferredPhotoProxyTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->status = true;
                }
            },
            [](napi_env env, napi_status status, void* data) {
                auto context = static_cast<DeferredPhotoProxAsyncContext*>(data);
                napi_resolve_deferred(env, context->deferred, nullptr);
                napi_delete_async_work(env, context->work);
                delete context->objectInfo;
                delete context;
            }, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for DeferredPhotoProxyNapi::Release");
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
} // namespace CameraStandard
} // namespace OHOS