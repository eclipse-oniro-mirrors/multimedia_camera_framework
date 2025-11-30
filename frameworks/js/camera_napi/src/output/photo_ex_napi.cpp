/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "output/photo_ex_napi.h"

#include "camera_log.h"
#include "hilog/log.h"
#include "image_napi.h"
#include "napi/native_common.h"
#include "napi_ref_manager.h"

namespace OHOS {
namespace CameraStandard {
thread_local napi_ref PhotoExNapi::sConstructor_ = nullptr;
thread_local napi_ref PhotoExNapi::sMainImageRef_ = nullptr;
thread_local napi_ref PhotoExNapi::sPictureRef_ = nullptr;
sptr<SurfaceBuffer> PhotoExNapi::imageBuffer_ = nullptr;
thread_local uint32_t PhotoExNapi::photoTaskId = PHOTO_TASKID;
bool PhotoExNapi::isCompressed_ = false;

PhotoExNapi::PhotoExNapi() : env_(nullptr), mainImageRef_(nullptr), pictureRef_(nullptr) {}

PhotoExNapi::~PhotoExNapi()
{
    MEDIA_DEBUG_LOG("~PhotoExNapi is called");
}

// Constructor callback
napi_value PhotoExNapi::PhotoExNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("PhotoExNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<PhotoExNapi> obj = std::make_unique<PhotoExNapi>();
        obj->env_ = env;
        obj->mainImageRef_ = sMainImageRef_;
        obj->pictureRef_ = sPictureRef_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           PhotoExNapi::PhotoExNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("PhotoExNapiConstructor call Failed!");
    return result;
}

void PhotoExNapi::PhotoExNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("PhotoExNapiDestructor is called");
    PhotoExNapi* photo = reinterpret_cast<PhotoExNapi*>(nativeObject);
    if (photo != nullptr) {
        delete photo;
    }
}

napi_value PhotoExNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;

    napi_property_descriptor photo_properties[] = {
        // PhotoEx
        DECLARE_NAPI_GETTER("main", GetMain),
        DECLARE_NAPI_FUNCTION("release", Release),
    };

    status = napi_define_class(env, PHOTO_EX_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               PhotoExNapiConstructor, nullptr,
                               sizeof(photo_properties) / sizeof(photo_properties[PARAM0]),
                               photo_properties, &ctorObj);
    if (status == napi_ok) {
        if (NapiRefManager::CreateMemSafetyRef(env, ctorObj, &sConstructor_) == napi_ok) {
            status = napi_set_named_property(env, exports, PHOTO_EX_NAPI_CLASS_NAME, ctorObj);
            CHECK_RETURN_RET(status == napi_ok, exports);
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value PhotoExNapi::CreatePhoto(napi_env env, napi_value mainImage, sptr<SurfaceBuffer> imageBuffer)
{
    MEDIA_DEBUG_LOG("CreatePhoto is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    napi_get_undefined(env, &result);

    imageBuffer_ = imageBuffer;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        napi_ref mainImageRef;
        napi_create_reference(env, mainImage, 1, &mainImageRef);
        sMainImageRef_ = mainImageRef;
        MEDIA_DEBUG_LOG("main image");

        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sMainImageRef_  = nullptr;
        isCompressed_ = true;
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

napi_value PhotoExNapi::CreatePicture(napi_env env, napi_value picture, sptr<SurfaceBuffer> pictureBuffer)
{
    MEDIA_DEBUG_LOG("CreatePicture is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    napi_get_undefined(env, &result);

    imageBuffer_ = pictureBuffer;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        napi_ref pictureRef;
        napi_create_reference(env, picture, 1, &pictureRef);
        sPictureRef_ = pictureRef;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sPictureRef_ = nullptr;
        isCompressed_ = false;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create picture obj instance");
        }
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("CreatePicture call Failed");
    return result;
}

napi_value PhotoExNapi::GetMain(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetMain is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    MEDIA_DEBUG_LOG("PhotoExNapi::GetMain get js args");
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    PhotoExNapi* photoExNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&photoExNapi));
    if (status == napi_ok && photoExNapi != nullptr) {
        napi_value photoEx;
        if (photoExNapi->isCompressed_) {
            napi_get_reference_value(env, photoExNapi->mainImageRef_, &photoEx);
        } else {
            napi_get_reference_value(env, photoExNapi->pictureRef_, &photoEx);
        }
        result = photoEx;
        MEDIA_ERR_LOG("PhotoExNapi::GetMain Success");
        return result;
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("PhotoExNapi::GetMain call Failed");
    return result;
}

napi_value PhotoExNapi::Release(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Release is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value resource = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    imageBuffer_ = nullptr;
    napi_get_undefined(env, &result);
    std::unique_ptr<PictureAsyncContext> asyncContext = std::make_unique<PictureAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Release");

        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<PictureAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "PhotoExNapi::Release";
                context->taskId = CameraNapiUtils::IncrementAndGet(photoTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->status = true;
                    context->objectInfo->mainImageRef_ = nullptr;
                    context->objectInfo->pictureRef_ = nullptr;
                }
            },
            [](napi_env env, napi_status status, void* data) {
                auto context = static_cast<PictureAsyncContext*>(data);
                CAMERA_FINISH_ASYNC_TRACE(context->funcName, context->taskId);
                napi_value result = nullptr;
                if (context->objectInfo->isCompressed_) {
                    napi_delete_reference(env, context->objectInfo->mainImageRef_);
                } else {
                    napi_delete_reference(env, context->objectInfo->pictureRef_);
                }
                napi_get_undefined(env, &result);
                napi_resolve_deferred(env, context->deferred, result);
                napi_delete_async_work(env, context->work);
                delete context;
            }, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for PhotoExNapi::Release");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
            asyncContext.release();
        }
    } else {
        MEDIA_ERR_LOG("PhotoExNapi::Release call Failed!");
    }
    return result;
}
} // namespace CameraStandard
} // namespace OHOS