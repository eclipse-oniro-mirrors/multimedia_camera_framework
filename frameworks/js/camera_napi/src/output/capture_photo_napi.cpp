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

#include "output/capture_photo_napi.h"

#include "camera_log.h"
#include "hilog/log.h"
#include "image_napi.h"
#include "napi/native_common.h"
#include "napi_ref_manager.h"

namespace OHOS {
namespace CameraStandard {
thread_local napi_ref CapturePhotoNapi::sConstructor_ = nullptr;
thread_local napi_ref CapturePhotoNapi::sMainImageRef_ = nullptr;
thread_local napi_ref CapturePhotoNapi::sPictureRef_ = nullptr;
sptr<SurfaceBuffer> CapturePhotoNapi::imageBuffer_ = nullptr;
thread_local uint32_t CapturePhotoNapi::photoTaskId = PHOTO_TASKID;
bool CapturePhotoNapi::isCompressed_ = false;

CapturePhotoNapi::CapturePhotoNapi() : env_(nullptr), mainImageRef_(nullptr), pictureRef_(nullptr) {}

CapturePhotoNapi::~CapturePhotoNapi()
{
    MEDIA_DEBUG_LOG("~CapturePhotoNapi is called");
}

// Constructor callback
napi_value CapturePhotoNapi::CapturePhotoNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CapturePhotoNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CapturePhotoNapi> obj = std::make_unique<CapturePhotoNapi>();
        obj->env_ = env;
        obj->mainImageRef_ = sMainImageRef_;
        obj->pictureRef_ = sPictureRef_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           CapturePhotoNapi::CapturePhotoNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("CapturePhotoNapiConstructor call Failed!");
    return result;
}

void CapturePhotoNapi::CapturePhotoNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CapturePhotoNapiDestructor is called");
    CapturePhotoNapi* photo = reinterpret_cast<CapturePhotoNapi*>(nativeObject);
    if (photo != nullptr) {
        delete photo;
    }
}

napi_value CapturePhotoNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;

    napi_property_descriptor photo_properties[] = {
        // CapturePhoto
        DECLARE_NAPI_GETTER("main", GetMain),
        DECLARE_NAPI_FUNCTION("release", Release),
    };

    status = napi_define_class(env, CAPTURE_PHOTO_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               CapturePhotoNapiConstructor, nullptr,
                               sizeof(photo_properties) / sizeof(photo_properties[PARAM0]),
                               photo_properties, &ctorObj);
    if (status == napi_ok) {
        if (NapiRefManager::CreateMemSafetyRef(env, ctorObj, &sConstructor_) == napi_ok) {
            status = napi_set_named_property(env, exports, CAPTURE_PHOTO_NAPI_CLASS_NAME, ctorObj);
            CHECK_RETURN_RET(status == napi_ok, exports);
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value CapturePhotoNapi::CreatePhoto(napi_env env, napi_value mainImage, sptr<SurfaceBuffer> imageBuffer)
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

napi_value CapturePhotoNapi::CreatePicture(napi_env env, napi_value picture, sptr<SurfaceBuffer> pictureBuffer)
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

napi_value CapturePhotoNapi::GetMain(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetMain is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    MEDIA_DEBUG_LOG("CapturePhotoNapi::GetMain get js args");
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CapturePhotoNapi* CapturePhotoNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&CapturePhotoNapi));
    if (status == napi_ok && CapturePhotoNapi != nullptr) {
        napi_value CapturePhoto;
        if (CapturePhotoNapi::isCompressed_) {
            napi_get_reference_value(env, CapturePhotoNapi->mainImageRef_, &CapturePhoto);
        } else {
            napi_get_reference_value(env, CapturePhotoNapi->pictureRef_, &CapturePhoto);
        }
        result = CapturePhoto;
        MEDIA_ERR_LOG("CapturePhotoNapi::GetMain Success");
        return result;
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("CapturePhotoNapi::GetMain call Failed");
    return result;
}

napi_value CapturePhotoNapi::Release(napi_env env, napi_callback_info info)
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
    std::unique_ptr<CapturePhotoAsyncContext> asyncContext = std::make_unique<CapturePhotoAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Release");

        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<CapturePhotoAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "CapturePhotoNapi::Release";
                context->taskId = CameraNapiUtils::IncrementAndGet(photoTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->status = true;
                    context->objectInfo->mainImageRef_ = nullptr;
                    context->objectInfo->pictureRef_ = nullptr;
                }
            },
            [](napi_env env, napi_status status, void* data) {
                auto context = static_cast<CapturePhotoAsyncContext*>(data);
                CAMERA_FINISH_ASYNC_TRACE(context->funcName, context->taskId);
                napi_value result = nullptr;
                CapturePhotoNapi::SafeDeleteReference(env, context->objectInfo->mainImageRef_);
                CapturePhotoNapi::SafeDeleteReference(env, context->objectInfo->pictureRef_);
                napi_get_undefined(env, &result);
                napi_resolve_deferred(env, context->deferred, result);
                napi_delete_async_work(env, context->work);
                delete context;
            }, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for CapturePhotoNapi::Release");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
            asyncContext.release();
        }
    } else {
        MEDIA_ERR_LOG("CapturePhotoNapi::Release call Failed!");
    }
    return result;
}

void CapturePhotoNapi::SafeDeleteReference(napi_env env, napi_ref& ref)
{
    if (ref != nullptr) {
        napi_delete_reference(env, ref);
        ref = nullptr;
    }
}
} // namespace CameraStandard
} // namespace OHOS