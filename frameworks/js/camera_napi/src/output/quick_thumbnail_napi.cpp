/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#include "output/quick_thumbnail_napi.h"

#include "camera_log.h"
#include "napi/native_common.h"
#include "napi_ref_manager.h"

namespace OHOS {
namespace CameraStandard {
namespace {
void AsyncCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto context = static_cast<QuickThumbnailAsyncContext*>(data);
    CAMERA_FINISH_ASYNC_TRACE(context->funcName, context->taskId);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_resolve_deferred(env, context->deferred, result);
    napi_delete_async_work(env, context->work);
    delete context;
}
} // namespace

thread_local napi_ref QuickThumbnailNapi::sConstructor_ = nullptr;
thread_local napi_ref QuickThumbnailNapi::sCaptureIdRef_ = nullptr;
thread_local napi_ref QuickThumbnailNapi::sPixelMapRef_ = nullptr;
thread_local uint32_t QuickThumbnailNapi::quickThumbnailTaskId = QUICK_THUMBNAIL_TASKID;

QuickThumbnailNapi::QuickThumbnailNapi(): env_(nullptr)
{
    MEDIA_INFO_LOG("QuickThumbnailNapi");
}

QuickThumbnailNapi::~QuickThumbnailNapi()
{
    MEDIA_INFO_LOG("~QuickThumbnailNapi");
}

napi_value QuickThumbnailNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("QuickThumbnailNapi::Init is called");
    napi_status status;
    napi_value ctorObj;

    napi_property_descriptor quick_thumbnail_props[] = {
        DECLARE_NAPI_GETTER("captureId", GetCaptureId),
        DECLARE_NAPI_GETTER("thumbnailImage", GetThumbnailImage),
        DECLARE_NAPI_FUNCTION("release", Release),
    };

    status = napi_define_class(env, CAMERA_QUICK_THUMBNAIL_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
        QuickThumbnailNapiConstructor, nullptr, sizeof(quick_thumbnail_props) / sizeof(quick_thumbnail_props[PARAM0]),
        quick_thumbnail_props, &ctorObj);
    if (status == napi_ok) {
        status = NapiRefManager::CreateMemSafetyRef(env, ctorObj, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_QUICK_THUMBNAIL_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value QuickThumbnailNapi::QuickThumbnailNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("QuickThumbnailNapi::QuickThumbnailNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<QuickThumbnailNapi> obj = std::make_unique<QuickThumbnailNapi>();
        obj->env_ = env;
        obj->captureId_ = sCaptureIdRef_;
        obj->pixelMap_ = sPixelMapRef_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            QuickThumbnailNapi::QuickThumbnailNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("QuickThumbnailNapi::QuickThumbnailNapiConstructor call Failed!");
    return result;
}

void QuickThumbnailNapi::QuickThumbnailNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_INFO_LOG("QuickThumbnailNapi::QuickThumbnailNapiDestructor is called");
    QuickThumbnailNapi* obj = reinterpret_cast<QuickThumbnailNapi*>(nativeObject);
    if (obj != nullptr) {
        delete obj;
    }
}

napi_value QuickThumbnailNapi::CreateQuickThumbnail(napi_env env, int32_t captureId, napi_value pixelMap)
{
    MEDIA_INFO_LOG("QuickThumbnailNapi::CreateQuickThumbnail is called");
    napi_value result = nullptr;
    napi_value constructor;
    napi_status status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        // captureId
        napi_value captureIdValue;
        napi_create_int32(env, captureId, &captureIdValue);
        napi_ref captureIdRef;
        napi_create_reference(env, captureIdValue, 1, &captureIdRef);
        sCaptureIdRef_ = captureIdRef;

        // thumbnailImage
        napi_ref pixelMapRef;
        napi_create_reference(env, pixelMap, 1, &pixelMapRef);
        sPixelMapRef_ = pixelMapRef;

        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sCaptureIdRef_ = nullptr;
        sPixelMapRef_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG(" QuickThumbnailNapi::CreateQuickThumbnail Failed to create obj instance");
        }
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("QuickThumbnailNapi::CreateQuickThumbnail Failed");
    return result;
}

napi_value QuickThumbnailNapi::GetCaptureId(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("QuickThumbnailNapi::GetCaptureId is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    QuickThumbnailNapi* obj = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr && obj->captureId_ != nullptr) {
        napi_value captureIdValue;
        napi_get_reference_value(env, obj->captureId_, &captureIdValue);
        result = captureIdValue;
        return result;
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("QuickThumbnailNapi::GetCaptureId call Failed");
    return result;
}

napi_value QuickThumbnailNapi::GetThumbnailImage(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("QuickThumbnailNapi::GetThumbnailImage is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    QuickThumbnailNapi* obj = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr) {
        napi_value pixelMapValue;
        napi_get_reference_value(env, obj->pixelMap_, &pixelMapValue);
        result = pixelMapValue;
        return result;
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("QuickThumbnailNapi::GetThumbnailImage call Failed");
    return result;
}

napi_value QuickThumbnailNapi::Release(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("QuickThumbnailNapi::Release is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value resource = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    std::unique_ptr<QuickThumbnailAsyncContext> asyncContext = std::make_unique<QuickThumbnailAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Release");

        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<QuickThumbnailAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "QuickThumbnailNapi::Release";
                context->taskId = CameraNapiUtils::IncrementAndGet(quickThumbnailTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->status = true;
                    context->objectInfo->captureId_ = nullptr;
                    context->objectInfo->pixelMap_ = nullptr;
                }
            },
            AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for QuickThumbnailNapi::Release");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
            asyncContext.release();
        }
    } else {
        MEDIA_ERR_LOG("QuickThumbnailNapi::Release call Failed!");
    }
    return result;
}
} // namespace CameraStandard
} // namespace OHOS