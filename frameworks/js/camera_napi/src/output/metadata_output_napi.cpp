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

#include "output/metadata_output_napi.h"

#include <uv.h>

#include "camera_log.h"
#include "camera_napi_metadata_utils.h"
#include "camera_napi_object_types.h"
#include "camera_napi_param_parser.h"
#include "camera_napi_template_utils.h"
#include "camera_napi_utils.h"
#include "camera_napi_worker_queue_keeper.h"
#include "camera_security_utils.h"
#include "hilog/log.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace CameraStandard {
thread_local uint32_t MetadataOutputNapi::metadataOutputTaskId = CAMERA_METADATA_OUTPUT_TASKID;
namespace {
void AsyncCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto context = static_cast<MetadataOutputAsyncContext*>(data);
    CHECK_ERROR_RETURN_LOG(context == nullptr, "MetadataOutputNapi AsyncCompleteCallback context is null");
    MEDIA_INFO_LOG("MetadataOutputNapi AsyncCompleteCallback %{public}s, status = %{public}d",
        context->funcName.c_str(), context->status);
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = context->status;
    if (!context->status) {
        CameraNapiUtils::CreateNapiErrorObject(
            env, context->errorCode, "No Metadata object Types or create array failed!", jsContext);
    } else {
        napi_get_undefined(env, &jsContext->data);
    }
    if (!context->funcName.empty() && context->taskId > 0) {
        // Finish async trace
        CAMERA_FINISH_ASYNC_TRACE(context->funcName, context->taskId);
        jsContext->funcName = context->funcName;
    }
    if (context->work != nullptr) {
        CameraNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    context->FreeHeldNapiValue(env);
    delete context;
}
} // namespace

thread_local napi_ref MetadataOutputNapi::sConstructor_ = nullptr;
thread_local sptr<MetadataOutput> MetadataOutputNapi::sMetadataOutput_ = nullptr;

MetadataOutputCallback::MetadataOutputCallback(napi_env env) : ListenerBase(env) {}

void MetadataOutputCallback::OnMetadataObjectsAvailable(const std::vector<sptr<MetadataObject>> metadataObjList) const
{
    MEDIA_DEBUG_LOG("OnMetadataObjectsAvailable is called");
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
    std::unique_ptr<MetadataOutputCallbackInfo> callbackInfo =
        std::make_unique<MetadataOutputCallbackInfo>(metadataObjList, shared_from_this());
    work->data = reinterpret_cast<void *>(callbackInfo.get());
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        MetadataOutputCallbackInfo* callbackInfo = reinterpret_cast<MetadataOutputCallbackInfo *>(work->data);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            if (listener) {
                listener->OnMetadataObjectsAvailableCallback(callbackInfo->info_);
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

napi_value MetadataOutputCallback::CreateMetadataObjJSArray(napi_env env,
    const std::vector<sptr<MetadataObject>> metadataObjList) const
{
    napi_value metadataObjArray = nullptr;
    napi_value metadataObj = nullptr;
    napi_status status;

    if (metadataObjList.empty()) {
        MEDIA_ERR_LOG("CreateMetadataObjJSArray: metadataObjList is empty");
    }

    status = napi_create_array(env, &metadataObjArray);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("CreateMetadataObjJSArray: napi_create_array failed");
        return metadataObjArray;
    }

    size_t j = 0;
    bool isSystemApp = CameraSecurity::CheckSystemApp();
    for (size_t i = 0; i < metadataObjList.size(); i++) {
        metadataObj = CameraNapiObjMetadataObject(*metadataObjList[i]).GenerateNapiValue(env);
        if (isSystemApp) {
            AddMetadataObjExtending(env, metadataObjList[i], metadataObj);
        }
        if ((metadataObj == nullptr) || napi_set_element(env, metadataObjArray, j++, metadataObj) != napi_ok) {
            MEDIA_ERR_LOG("CreateMetadataObjJSArray: Failed to create metadata face object napi wrapper object");
            return nullptr;
        }
    }
    return metadataObjArray;
}

void MetadataOutputCallback::AddMetadataObjExtending(napi_env env, sptr<MetadataObject> metadataObj,
    napi_value &metadataNapiObj) const
{
    if (metadataObj == nullptr) {
        MEDIA_DEBUG_LOG("AddMetadataObjExtending got null metadataObj");
        return;
    }
    auto type = metadataObj->GetType();
    switch (type) {
        case MetadataObjectType::FACE:
            CreateHumanFaceMetaData(env, metadataObj, metadataNapiObj);
            break;
        case MetadataObjectType::CAT_FACE:
            CreateCatFaceMetaData(env, metadataObj, metadataNapiObj);
            break;
        case MetadataObjectType::DOG_FACE:
            CreateDogFaceMetaData(env, metadataObj, metadataNapiObj);
            break;
        default:
            return;
    }
}
 
void MetadataOutputCallback::CreateHumanFaceMetaData(napi_env env, sptr<MetadataObject> metadataObj,
    napi_value &metadataNapiObj) const
{
    napi_value metadataObjResult = nullptr;
    napi_value numberNapiObj = nullptr;
 
    napi_get_undefined(env, &metadataObjResult);
    if (metadataObj == nullptr && metadataNapiObj == nullptr) {
        return;
    }
    MetadataFaceObject* faceObjectPtr = static_cast<MetadataFaceObject*>(metadataObj.GetRefPtr());
    Rect boundingBox = faceObjectPtr->GetLeftEyeBoundingBox();
    metadataObjResult = CameraNapiBoundingBox(boundingBox).GenerateNapiValue(env);
    napi_set_named_property(env, metadataNapiObj, "leftEyeBoundingBox", metadataObjResult);
    boundingBox = faceObjectPtr->GetRightEyeBoundingBox();
    metadataObjResult = CameraNapiBoundingBox(boundingBox).GenerateNapiValue(env);
    napi_set_named_property(env, metadataNapiObj, "rightEyeBoundingBox", metadataObjResult);
 
    napi_create_int32(env, faceObjectPtr->GetEmotion(), &numberNapiObj);
    napi_set_named_property(env, metadataNapiObj, "emotion", numberNapiObj);
    napi_create_int32(env, faceObjectPtr->GetEmotionConfidence(), &numberNapiObj);
    napi_set_named_property(env, metadataNapiObj, "emotionConfidence", numberNapiObj);
    napi_create_int32(env, faceObjectPtr->GetPitchAngle(), &numberNapiObj);
    napi_set_named_property(env, metadataNapiObj, "pitchAngle", numberNapiObj);
    napi_create_int32(env, faceObjectPtr->GetYawAngle(), &numberNapiObj);
    napi_set_named_property(env, metadataNapiObj, "yawAngle", numberNapiObj);
    napi_create_int32(env, faceObjectPtr->GetRollAngle(), &numberNapiObj);
    napi_set_named_property(env, metadataNapiObj, "rollAngle", numberNapiObj);
}
 
void MetadataOutputCallback::CreateCatFaceMetaData(napi_env env, sptr<MetadataObject> metadataObj,
    napi_value &metadataNapiObj) const
{
    napi_value metadataObjResult = nullptr;
 
    napi_get_undefined(env, &metadataObjResult);
    if (metadataObj == nullptr && metadataNapiObj == nullptr) {
        return;
    }
    MetadataCatFaceObject* faceObjectPtr = static_cast<MetadataCatFaceObject*>(metadataObj.GetRefPtr());
    Rect boundingBox = faceObjectPtr->GetLeftEyeBoundingBox();
    metadataObjResult = CameraNapiBoundingBox(boundingBox).GenerateNapiValue(env);
    napi_set_named_property(env, metadataNapiObj, "leftEyeBoundingBox", metadataObjResult);
    boundingBox = faceObjectPtr->GetRightEyeBoundingBox();
    metadataObjResult = CameraNapiBoundingBox(boundingBox).GenerateNapiValue(env);
    napi_set_named_property(env, metadataNapiObj, "rightEyeBoundingBox", metadataObjResult);
}
 
void MetadataOutputCallback::CreateDogFaceMetaData(napi_env env, sptr<MetadataObject> metadataObj,
    napi_value &metadataNapiObj) const
{
    napi_value metadataObjResult = nullptr;
 
    napi_get_undefined(env, &metadataObjResult);
    if (metadataObj == nullptr && metadataNapiObj == nullptr) {
        return;
    }
    MetadataDogFaceObject* faceObjectPtr = static_cast<MetadataDogFaceObject*>(metadataObj.GetRefPtr());
    Rect boundingBox = faceObjectPtr->GetLeftEyeBoundingBox();
    metadataObjResult = CameraNapiBoundingBox(boundingBox).GenerateNapiValue(env);
    napi_set_named_property(env, metadataNapiObj, "leftEyeBoundingBox", metadataObjResult);
    boundingBox = faceObjectPtr->GetRightEyeBoundingBox();
    metadataObjResult = CameraNapiBoundingBox(boundingBox).GenerateNapiValue(env);
    napi_set_named_property(env, metadataNapiObj, "rightEyeBoundingBox", metadataObjResult);
}

void MetadataOutputCallback::OnMetadataObjectsAvailableCallback(
    const std::vector<sptr<MetadataObject>> metadataObjList) const
{
    MEDIA_DEBUG_LOG("OnMetadataObjectsAvailableCallback is called");
    napi_value result[ARGS_TWO];
    napi_value retVal;

    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);
    result[PARAM1] = CreateMetadataObjJSArray(env_, metadataObjList);
    MEDIA_INFO_LOG("OnMetadataObjectsAvailableCallback metadataObjList size = %{public}zu", metadataObjList.size());
    if (result[PARAM1] == nullptr) {
        MEDIA_ERR_LOG("invoke CreateMetadataObjJSArray failed");
        return;
    }

    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_TWO, .argv = result, .result = &retVal };
    ExecuteCallback("metadataObjectsAvailable", callbackNapiPara);
}

MetadataStateCallbackNapi::MetadataStateCallbackNapi(napi_env env) : ListenerBase(env) {}

void MetadataStateCallbackNapi::OnErrorCallbackAsync(const int32_t errorType) const
{
    MEDIA_DEBUG_LOG("OnErrorCallbackAsync is called");
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
    std::unique_ptr<MetadataStateCallbackInfo> callbackInfo =
        std::make_unique<MetadataStateCallbackInfo>(errorType, shared_from_this());
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        MetadataStateCallbackInfo* callbackInfo = reinterpret_cast<MetadataStateCallbackInfo *>(work->data);
        if (callbackInfo) {
            auto listener = callbackInfo->listener_.lock();
            if (listener) {
                listener->OnErrorCallback(callbackInfo->errorType_);
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

void MetadataStateCallbackNapi::OnErrorCallback(const int32_t errorType) const
{
    MEDIA_DEBUG_LOG("OnErrorCallback is called");
    napi_value result;
    napi_value retVal;
    napi_value propValue;

    napi_create_int32(env_, errorType, &propValue);
    napi_create_object(env_, &result);
    napi_set_named_property(env_, result, "code", propValue);
    ExecuteCallbackNapiPara callbackNapiPara { .recv = nullptr, .argc = ARGS_ONE, .argv = &result, .result = &retVal };
    ExecuteCallback("error", callbackNapiPara);
}

void MetadataStateCallbackNapi::OnError(const int32_t errorType) const
{
    MEDIA_DEBUG_LOG("OnError is called!, errorType: %{public}d", errorType);
    OnErrorCallbackAsync(errorType);
}

MetadataOutputNapi::MetadataOutputNapi() : env_(nullptr) {}

MetadataOutputNapi::~MetadataOutputNapi()
{
    MEDIA_DEBUG_LOG("~MetadataOutputNapi is called");
}

void MetadataOutputNapi::MetadataOutputNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("MetadataOutputNapiDestructor is called");
    MetadataOutputNapi* metadataOutput = reinterpret_cast<MetadataOutputNapi*>(nativeObject);
    if (metadataOutput != nullptr) {
        delete metadataOutput;
    }
}

napi_value MetadataOutputNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor metadata_output_props[] = {
        DECLARE_NAPI_FUNCTION("addMetadataObjectTypes", AddMetadataObjectTypes),
        DECLARE_NAPI_FUNCTION("removeMetadataObjectTypes", RemoveMetadataObjectTypes),
        DECLARE_NAPI_FUNCTION("start", Start),
        DECLARE_NAPI_FUNCTION("stop", Stop),
        DECLARE_NAPI_FUNCTION("release", Release),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("once", Once),
        DECLARE_NAPI_FUNCTION("off", Off)
    };

    status = napi_define_class(env, CAMERA_METADATA_OUTPUT_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               MetadataOutputNapiConstructor, nullptr,
                               sizeof(metadata_output_props) / sizeof(metadata_output_props[PARAM0]),
                               metadata_output_props, &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_METADATA_OUTPUT_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value MetadataOutputNapi::MetadataOutputNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("MetadataOutputNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<MetadataOutputNapi> obj = std::make_unique<MetadataOutputNapi>();
        obj->env_ = env;
        obj->metadataOutput_ = sMetadataOutput_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           MetadataOutputNapi::MetadataOutputNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("MetadataOutputNapiConstructor call Failed!");
    return result;
}

bool MetadataOutputNapi::IsMetadataOutput(napi_env env, napi_value obj)
{
    MEDIA_DEBUG_LOG("IsMetadataOutput is called");
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
    MEDIA_INFO_LOG("IsMetadataOutput(%{public}d)", result);
    return result;
}

sptr<MetadataOutput> MetadataOutputNapi::GetMetadataOutput()
{
    return metadataOutput_;
}

napi_value MetadataOutputNapi::CreateMetadataOutput(napi_env env, std::vector<MetadataObjectType> metadataObjectTypes)
{
    MEDIA_DEBUG_LOG("CreateMetadataOutput is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        int retCode = CameraManager::GetInstance()->CreateMetadataOutput(sMetadataOutput_, metadataObjectTypes);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        if (sMetadataOutput_ == nullptr) {
            MEDIA_ERR_LOG("failed to create MetadataOutput");
            return result;
        }
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sMetadataOutput_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            MEDIA_ERR_LOG("Failed to create metadata output instance");
        }
    }
    MEDIA_ERR_LOG("CreateMetadataOutput call Failed!");
    napi_get_undefined(env, &result);
    return result;
}

napi_value MetadataOutputNapi::AddMetadataObjectTypes(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("AddMetadataObjectTypes is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter maximum");
 
    napi_get_undefined(env, &result);
    MetadataOutputNapi* metadataOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&metadataOutputNapi));
    if (status != napi_ok || metadataOutputNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap failure!");
        return result;
    }
    std::vector<MetadataObjectType> metadataObjectType;
    CameraNapiUtils::ParseMetadataObjectTypes(env, argv[PARAM0], metadataObjectType);
    int32_t retCode = metadataOutputNapi->metadataOutput_->AddMetadataObjectTypes(metadataObjectType);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("AddMetadataObjectTypes failure!");
    }
    return result;
}
 
napi_value MetadataOutputNapi::RemoveMetadataObjectTypes(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("RemoveMetadataObjectTypes is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter maximum");
 
    napi_get_undefined(env, &result);
    MetadataOutputNapi* metadataOutputNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&metadataOutputNapi));
    if (status != napi_ok || metadataOutputNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap failure!");
        return result;
    }
    std::vector<MetadataObjectType> metadataObjectType;
    CameraNapiUtils::ParseMetadataObjectTypes(env, argv[PARAM0], metadataObjectType);
    int32_t retCode = metadataOutputNapi->metadataOutput_->RemoveMetadataObjectTypes(metadataObjectType);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        MEDIA_ERR_LOG("RemoveMetadataObjectTypes failure!");
    }
    return result;
}

napi_value MetadataOutputNapi::Start(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Start is called");
    std::unique_ptr<MetadataOutputAsyncContext> asyncContext = std::make_unique<MetadataOutputAsyncContext>(
        "MetadataOutputNapi::Start", CameraNapiUtils::IncrementAndGet(metadataOutputTaskId));
    auto asyncFunction =
        std::make_shared<CameraNapiAsyncFunction>(env, "Start", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("MetadataOutputNapi::Start invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("MetadataOutputNapi::Start running on worker");
            auto context = static_cast<MetadataOutputAsyncContext*>(data);
            CHECK_ERROR_RETURN_LOG(context->objectInfo == nullptr, "MetadataOutputNapi::Start async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
                context->errorCode = context->objectInfo->metadataOutput_->Start();
                context->status = context->errorCode == CameraErrorCode::SUCCESS;
                MEDIA_INFO_LOG("MetadataOutputNapi::Start errorCode:%{public}d", context->errorCode);
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for MetadataOutputNapi::Start");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("MetadataOutputNapi::Start");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value MetadataOutputNapi::Stop(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Stop is called");
    std::unique_ptr<MetadataOutputAsyncContext> asyncContext = std::make_unique<MetadataOutputAsyncContext>(
        "MetadataOutputNapi::Stop", CameraNapiUtils::IncrementAndGet(metadataOutputTaskId));
    auto asyncFunction =
        std::make_shared<CameraNapiAsyncFunction>(env, "Stop", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("MetadataOutputNapi::Stop invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("MetadataOutputNapi::Stop running on worker");
            auto context = static_cast<MetadataOutputAsyncContext*>(data);
            CHECK_ERROR_RETURN_LOG(context->objectInfo == nullptr, "MetadataOutputNapi::Stop async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
                context->errorCode = context->objectInfo->metadataOutput_->Stop();
                // Always true, ignore error code
                context->status = true;
                MEDIA_INFO_LOG("MetadataOutputNapi::Stop errorCode:%{public}d", context->errorCode);
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for MetadataOutputNapi::Stop");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("MetadataOutputNapi::Stop");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

napi_value MetadataOutputNapi::Release(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("MetadataOutputNapi::Release is called");
    std::unique_ptr<MetadataOutputAsyncContext> asyncContext = std::make_unique<MetadataOutputAsyncContext>(
        "MetadataOutputNapi::Release", CameraNapiUtils::IncrementAndGet(metadataOutputTaskId));
    auto asyncFunction =
        std::make_shared<CameraNapiAsyncFunction>(env, "Release", asyncContext->callbackRef, asyncContext->deferred);
    CameraNapiParamParser jsParamParser(env, info, asyncContext->objectInfo, asyncFunction);
    if (!jsParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
        MEDIA_ERR_LOG("MetadataOutputNapi::Release invalid argument");
        return nullptr;
    }
    asyncContext->HoldNapiValue(env, jsParamParser.GetThisVar());
    napi_status status = napi_create_async_work(
        env, nullptr, asyncFunction->GetResourceName(),
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("MetadataOutputNapi::Release running on worker");
            auto context = static_cast<MetadataOutputAsyncContext*>(data);
            CHECK_ERROR_RETURN_LOG(context->objectInfo == nullptr, "MetadataOutputNapi::Release async info is nullptr");
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            CameraNapiWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(context->queueTask, [&context]() {
                context->errorCode = context->objectInfo->metadataOutput_->Release();
                context->status = context->errorCode == CameraErrorCode::SUCCESS;
            });
        },
        AsyncCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for MetadataOutputNapi::Release");
        asyncFunction->Reset();
    } else {
        asyncContext->queueTask =
            CameraNapiWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("MetadataOutputNapi::Release");
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    if (asyncFunction->GetAsyncFunctionType() == ASYNC_FUN_TYPE_PROMISE) {
        return asyncFunction->GetPromise();
    }
    return CameraNapiUtils::GetUndefinedValue(env);
}

void MetadataOutputNapi::RegisterMetadataObjectsAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (metadataOutputCallback_ == nullptr) {
        metadataOutputCallback_ = make_shared<MetadataOutputCallback>(env);
        metadataOutput_->SetCallback(metadataOutputCallback_);
    }
    metadataOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void MetadataOutputNapi::UnregisterMetadataObjectsAvailableCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (metadataOutputCallback_ == nullptr) {
        MEDIA_ERR_LOG("metadataOutputCallback is null");
    } else {
        metadataOutputCallback_->RemoveCallbackRef(eventName, callback);
    }
}

void MetadataOutputNapi::RegisterErrorCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce)
{
    if (metadataStateCallback_ == nullptr) {
        metadataStateCallback_ = make_shared<MetadataStateCallbackNapi>(env);
        metadataOutput_->SetCallback(metadataStateCallback_);
    }
    metadataStateCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void MetadataOutputNapi::UnregisterErrorCallbackListener(
    const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args)
{
    if (metadataStateCallback_ == nullptr) {
        MEDIA_ERR_LOG("metadataStateCallback is null");
    } else {
        metadataStateCallback_->RemoveCallbackRef(eventName, callback);
    }
}

const MetadataOutputNapi::EmitterFunctions& MetadataOutputNapi::GetEmitterFunctions()
{
    const static EmitterFunctions funMap = {
        { "metadataObjectsAvailable", {
            &MetadataOutputNapi::RegisterMetadataObjectsAvailableCallbackListener,
            &MetadataOutputNapi::UnregisterMetadataObjectsAvailableCallbackListener } },
        { "error", {
            &MetadataOutputNapi::RegisterErrorCallbackListener,
            &MetadataOutputNapi::UnregisterErrorCallbackListener } } };
    return funMap;
}

napi_value MetadataOutputNapi::On(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<MetadataOutputNapi>::On(env, info);
}

napi_value MetadataOutputNapi::Once(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<MetadataOutputNapi>::Once(env, info);
}

napi_value MetadataOutputNapi::Off(napi_env env, napi_callback_info info)
{
    return ListenerTemplate<MetadataOutputNapi>::Off(env, info);
}
} // namespace CameraStandard
} // namespace OHOS