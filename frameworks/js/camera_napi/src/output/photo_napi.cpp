/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "hilog/log.h"
#include "camera_log.h"
#include "output/photo_napi.h"

namespace OHOS {
namespace CameraStandard {
thread_local napi_ref PhotoNapi::sConstructor_ = nullptr;
thread_local napi_value PhotoNapi::sMainImage_ = nullptr;
thread_local napi_value PhotoNapi::sRawImage_ = nullptr;
thread_local uint32_t PhotoNapi::photoTaskId = PHOTO_TASKID;

PhotoNapi::PhotoNapi() : env_(nullptr), wrapper_(nullptr), mainImage_(nullptr), rawImage_(nullptr)
{
}

PhotoNapi::~PhotoNapi()
{
    MEDIA_DEBUG_LOG("~PhotoNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (mainImage_) {
        mainImage_ = nullptr;
    }
    if (rawImage_) {
        rawImage_ = nullptr;
    }
}

// Constructor callback
napi_value PhotoNapi::PhotoNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PhotoNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<PhotoNapi> obj = std::make_unique<PhotoNapi>();
        obj->env_ = env;
        obj->mainImage_ = sMainImage_;
        obj->rawImage_ = sRawImage_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           PhotoNapi::PhotoNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("PhotoNapiConstructor call Failed!");
    return result;
}

void PhotoNapi::PhotoNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("PhotoNapiDestructor is called");
    PhotoNapi* photo = reinterpret_cast<PhotoNapi*>(nativeObject);
    if (photo != nullptr) {
        delete photo;
    }
}

napi_value PhotoNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor photo_properties[] = {
        // Photo
        DECLARE_NAPI_GETTER("main", GetMain),
        DECLARE_NAPI_GETTER("rawImage", GetRaw),
        DECLARE_NAPI_FUNCTION("release", Release),
    };

    status = napi_define_class(env, PHOTO_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               PhotoNapiConstructor, nullptr,
                               sizeof(photo_properties) / sizeof(photo_properties[PARAM0]),
                               photo_properties, &ctorObj);
    if (status == napi_ok) {
        if (napi_create_reference(env, ctorObj, refCount, &sConstructor_) == napi_ok) {
            status = napi_set_named_property(env, exports, PHOTO_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value PhotoNapi::CreatePhoto(napi_env env, napi_value mainImage)
{
    MEDIA_DEBUG_LOG("CreatePhoto is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    napi_get_undefined(env, &result);

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sMainImage_ = mainImage;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sMainImage_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create photo obj instance");
        }
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("CreatePhoto call Failed");
    return result;
}

napi_value PhotoNapi::GetMain(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetMain is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PhotoNapi* photoNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoNapi));
    if (status == napi_ok && photoNapi != nullptr) {
        result = photoNapi->mainImage_;
        MEDIA_ERR_LOG("PhotoNapi::GetMain Success");
        return result;
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("PhotoNapi::GetMain call Failed");
    return result;
}

napi_value PhotoNapi::CreateRawPhoto(napi_env env, napi_value rawImage)
{
    MEDIA_DEBUG_LOG("CreateRawPhoto is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    napi_get_undefined(env, &result);

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sRawImage_ = rawImage;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sRawImage_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create photo obj instance");
        }
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("CreateRawPhoto call Failed");
    return result;
}

napi_value PhotoNapi::GetRaw(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetRaw is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PhotoNapi* photoNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoNapi));
    if (status == napi_ok && photoNapi != nullptr) {
        result = photoNapi->rawImage_;
        MEDIA_DEBUG_LOG("PhotoNapi::GetRaw Success");
        return result;
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("PhotoNapi::GetRaw call Failed");
    return result;
}

napi_value PhotoNapi::Release(napi_env env, napi_callback_info info)
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
    std::unique_ptr<PhotoAsyncContext> asyncContext = std::make_unique<PhotoAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Release");

        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<PhotoAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "PhotoNapi::Release";
                context->taskId = CameraNapiUtils::IncreamentAndGet(photoTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->status = true;
                    context->objectInfo->mainImage_ = nullptr;
                    context->objectInfo->rawImage_ = nullptr;
                }
            },
            [](napi_env env, napi_status status, void* data) {
                auto context = static_cast<PhotoAsyncContext*>(data);
                napi_resolve_deferred(env, context->deferred, nullptr);
                napi_delete_async_work(env, context->work);
                delete context->objectInfo;
                delete context;
            }, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for PhotoNapi::Release");
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