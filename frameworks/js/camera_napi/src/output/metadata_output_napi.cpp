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

#include <uv.h>
#include "hilog/log.h"
#include "output/metadata_object_napi.h"
#include "output/metadata_output_napi.h"

namespace OHOS {
namespace CameraStandard {
using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;
namespace {
    constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "MetadataOutputNapi"};
}
thread_local napi_ref MetadataOutputNapi::sConstructor_ = nullptr;
thread_local sptr<MetadataOutput> MetadataOutputNapi::sMetadataOutput_ = nullptr;

MetadataOutputCallback::MetadataOutputCallback(napi_env env) : env_(env) {}

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
        std::make_unique<MetadataOutputCallbackInfo>(metadataObjList, this);
    work->data = reinterpret_cast<void *>(callbackInfo.get());
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        MetadataOutputCallbackInfo* callbackInfo = reinterpret_cast<MetadataOutputCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnMetadataObjectsAvailableCallback(callbackInfo->info_);
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

static napi_value CreateMetadataObjJSArray(napi_env env,
    const std::vector<sptr<MetadataObject>> metadataObjList)
{
    MEDIA_DEBUG_LOG("CreateMetadataObjJSArray is called");
    napi_value metadataObjArray = nullptr;
    napi_value metadataObj = nullptr;
    napi_status status;

    if (metadataObjList.empty()) {
        MEDIA_ERR_LOG("CreateMetadataObjJSArray: metadataObjList is empty");
        return metadataObjArray;
    }

    status = napi_create_array(env, &metadataObjArray);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("CreateMetadataObjJSArray: napi_create_array failed");
        return metadataObjArray;
    }

    for (size_t i = 0; i < metadataObjList.size(); i++) {
        size_t j = 0;
        metadataObj = MetadataObjectNapi::CreateMetaFaceObj(env, metadataObjList[i]);
        if ((metadataObj == nullptr) || napi_set_element(env, metadataObjArray, j++, metadataObj) != napi_ok) {
            MEDIA_ERR_LOG("CreateMetadataObjJSArray: Failed to create metadata face object napi wrapper object");
            return nullptr;
        }
    }
    return metadataObjArray;
}

void MetadataOutputCallback::OnMetadataObjectsAvailableCallback(
    const std::vector<sptr<MetadataObject>> metadataObjList) const
{
    MEDIA_DEBUG_LOG("OnMetadataObjectsAvailableCallback is called");
    napi_value result[ARGS_TWO];
    napi_value callback = nullptr;
    napi_value retVal;
    CAMERA_NAPI_CHECK_AND_RETURN_LOG((metadataObjList.size() != 0), "callback metadataObjList is null");
    for (auto it = metadataOutputCbList_.begin(); it != metadataOutputCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_get_undefined(env, &result[PARAM0]);
        napi_get_undefined(env, &result[PARAM1]);
        result[PARAM1] = CreateMetadataObjJSArray(env, metadataObjList);
        if (result[PARAM1] == nullptr) {
            MEDIA_ERR_LOG("invoke CreateMetadataObjJSArray failed");
            return;
        }

        CAMERA_NAPI_CHECK_NULL_PTR_RETURN_VOID((*it)->cb_,
                                               "metadataObjectsAvailable callback is not registered by JS");
        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_call_function(env, nullptr, callback, ARGS_TWO, result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference((*it)->env_, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            metadataOutputCbList_.erase(it);
        } else {
            it++;
        }
    }
}

void MetadataOutputCallback::SaveCallbackReference(const std::string &eventType, napi_value callback, bool isOnce)
{
    std::lock_guard<std::mutex> lock(metadataOutputCbMutex_);
    bool isSameCallback = true;
    for (auto it = metadataOutputCbList_.begin(); it != metadataOutputCbList_.end(); ++it) {
        isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        CHECK_AND_RETURN_LOG(!isSameCallback, "SaveCallbackReference: has same callback, nothing to do");
    }
    napi_ref callbackRef = nullptr;
    const int32_t refCount = 1;
    napi_status status = napi_create_reference(env_, callback, refCount, &callbackRef);
    CHECK_AND_RETURN_LOG(status == napi_ok && callbackRef != nullptr,
                         "CameraManagerCallbackNapi: creating reference for callback fail");
    std::shared_ptr<AutoRef> cb = std::make_shared<AutoRef>(env_, callbackRef, isOnce);
    metadataOutputCbList_.push_back(cb);
    MEDIA_INFO_LOG("Save callback reference success, metadataOutput callback list size [%{public}zu]",
                   metadataOutputCbList_.size());
}

void MetadataOutputCallback::RemoveCallbackRef(napi_env env, napi_value callback)
{
    std::lock_guard<std::mutex> lock(metadataOutputCbMutex_);

    if (callback == nullptr) {
        MEDIA_INFO_LOG("RemoveCallbackReference: js callback is nullptr, remove all callback reference");
        RemoveAllCallbacks();
        return;
    }
    for (auto it = metadataOutputCbList_.begin(); it != metadataOutputCbList_.end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        if (isSameCallback) {
            MEDIA_INFO_LOG("RemoveCallbackReference: find js callback, delete it");
            napi_delete_reference(env, (*it)->cb_);
            (*it)->cb_ = nullptr;
            metadataOutputCbList_.erase(it);
            return;
        }
    }
    MEDIA_INFO_LOG("RemoveCallbackReference: js callback no find");
}

void MetadataOutputCallback::RemoveAllCallbacks()
{
    for (auto it = metadataOutputCbList_.begin(); it != metadataOutputCbList_.end(); ++it) {
        napi_status ret = napi_delete_reference(env_, (*it)->cb_);
        if (ret != napi_ok) {
            MEDIA_ERR_LOG("RemoveAllCallbackReferences: napi_delete_reference err.");
        }
        (*it)->cb_ = nullptr;
    }
    metadataOutputCbList_.clear();
    MEDIA_INFO_LOG("RemoveAllCallbacks: remove all js callbacks success");
}

MetadataStateCallbackNapi::MetadataStateCallbackNapi(napi_env env) : env_(env) {}

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
        std::make_unique<MetadataStateCallbackInfo>(errorType, this);
    work->data = callbackInfo.get();
    int ret = uv_queue_work_with_qos(loop, work, [] (uv_work_t* work) {}, [] (uv_work_t* work, int status) {
        MetadataStateCallbackInfo* callbackInfo = reinterpret_cast<MetadataStateCallbackInfo *>(work->data);
        if (callbackInfo) {
            callbackInfo->listener_->OnErrorCallback(callbackInfo->errorType_);
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
    napi_value callback = nullptr;
    napi_value retVal;
    napi_value propValue;

    for (auto it = metadataStateCbList_.begin(); it != metadataStateCbList_.end();) {
        napi_env env = (*it)->env_;
        napi_create_int32(env, errorType, &propValue);
        napi_create_object(env, &result);
        napi_set_named_property(env, result, "code", propValue);
        napi_get_reference_value(env, (*it)->cb_, &callback);
        napi_call_function(env, nullptr, callback, ARGS_ONE, &result, &retVal);
        if ((*it)->isOnce_) {
            napi_status status = napi_delete_reference((*it)->env_, (*it)->cb_);
            CHECK_AND_RETURN_LOG(status == napi_ok, "Remove once cb ref: delete reference for callback fail");
            (*it)->cb_ = nullptr;
            metadataStateCbList_.erase(it);
        } else {
            it++;
        }
    }
}

void MetadataStateCallbackNapi::OnError(const int32_t errorType) const
{
    MEDIA_DEBUG_LOG("OnError is called!, errorType: %{public}d", errorType);
    OnErrorCallbackAsync(errorType);
}

void MetadataStateCallbackNapi::SaveCallbackReference(const std::string &eventType, napi_value callback, bool isOnce)
{
    std::lock_guard<std::mutex> lock(metadataStateCbMutex_);
    napi_ref callbackRef = nullptr;
    const int32_t refCount = 1;

    bool isSameCallback = true;
    for (auto it = metadataStateCbList_.begin(); it != metadataStateCbList_.end(); ++it) {
        isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        CHECK_AND_RETURN_LOG(!isSameCallback, "SaveCallbackReference: has same callback, nothing to do");
    }
    napi_status status = napi_create_reference(env_, callback, refCount, &callbackRef);
    CHECK_AND_RETURN_LOG(status == napi_ok && callbackRef != nullptr,
                         "metadataStateCb: creating reference for callback fail");
    std::shared_ptr<AutoRef> cb = std::make_shared<AutoRef>(env_, callbackRef, isOnce);
    metadataStateCbList_.push_back(cb);
    MEDIA_INFO_LOG("Save callback reference success, metadataState callback list size [%{public}zu]",
        metadataStateCbList_.size());
}

void MetadataStateCallbackNapi::RemoveCallbackRef(napi_env env, napi_value callback)
{
    std::lock_guard<std::mutex> lock(metadataStateCbMutex_);

    if (callback == nullptr) {
        MEDIA_INFO_LOG("RemoveCallbackReference: js callback is nullptr, remove all callback reference");
        RemoveAllCallbacks();
        return;
    }
    for (auto it = metadataStateCbList_.begin(); it != metadataStateCbList_.end(); ++it) {
        bool isSameCallback = CameraNapiUtils::IsSameCallback(env_, callback, (*it)->cb_);
        if (isSameCallback) {
            MEDIA_INFO_LOG("RemoveCallbackReference: find js callback, delete it");
            napi_status status = napi_delete_reference(env, (*it)->cb_);
            (*it)->cb_ = nullptr;
            CHECK_AND_RETURN_LOG(status == napi_ok, "RemoveCallbackReference: delete reference for callback fail");
            metadataStateCbList_.erase(it);
            return;
        }
    }
    MEDIA_INFO_LOG("RemoveCallbackReference: js callback no find");
}

void MetadataStateCallbackNapi::RemoveAllCallbacks()
{
    for (auto it = metadataStateCbList_.begin(); it != metadataStateCbList_.end(); ++it) {
        napi_delete_reference(env_, (*it)->cb_);
        (*it)->cb_ = nullptr;
    }
    metadataStateCbList_.clear();
    MEDIA_INFO_LOG("RemoveAllCallbacks: remove all js callbacks success");
}

MetadataOutputNapi::MetadataOutputNapi() : env_(nullptr), wrapper_(nullptr)
{
}

MetadataOutputNapi::~MetadataOutputNapi()
{
    MEDIA_DEBUG_LOG("~MetadataOutputNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (metadataOutput_) {
        metadataOutput_ = nullptr;
    }
    if (metadataOutputCallback_) {
        metadataOutputCallback_->RemoveCallbackRef(env_, nullptr);
        metadataOutputCallback_ = nullptr;
    }
    if (metadataStateCallback_) {
        metadataStateCallback_->RemoveCallbackRef(env_, nullptr);
        metadataStateCallback_ = nullptr;
    }
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
        DECLARE_NAPI_FUNCTION("getSupportedMetadataObjectTypes", GetSupportedMetadataObjectTypes),
        DECLARE_NAPI_FUNCTION("setCapturingMetadataObjectTypes", SetCapturingMetadataObjectTypes),
        DECLARE_NAPI_FUNCTION("start", Start),
        DECLARE_NAPI_FUNCTION("stop", Stop),
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
        std::shared_ptr<MetadataOutputCallback> metadataOutputCallback =
            std::make_shared<MetadataOutputCallback>(env);
        obj->metadataOutputCallback_ = metadataOutputCallback;
        ((sptr<MetadataOutput> &)(obj->metadataOutput_))->SetCallback(metadataOutputCallback);
        std::shared_ptr<MetadataStateCallbackNapi> metadataStateCallback =
                std::make_shared<MetadataStateCallbackNapi>(env);
        ((sptr<MetadataOutput> &)(obj->metadataOutput_))->SetCallback(metadataStateCallback);
        obj->metadataStateCallback_ = metadataStateCallback;

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
    MEDIA_ERR_LOG("IsMetadataOutput call Failed!");
    return result;
}

sptr<MetadataOutput> MetadataOutputNapi::GetMetadataOutput()
{
    return metadataOutput_;
}

napi_value MetadataOutputNapi::CreateMetadataOutput(napi_env env)
{
    MEDIA_DEBUG_LOG("CreateMetadataOutput is called");
    CAMERA_SYNC_TRACE;
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        int retCode = CameraManager::GetInstance()->CreateMetadataOutput(&sMetadataOutput_);
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

static void CommonCompleteCallback(napi_env env, napi_status status, void* data)
{
    MEDIA_DEBUG_LOG("CommonCompleteCallback is called");
    auto context = static_cast<MetadataOutputAsyncContext*>(data);
    if (context == nullptr) {
        MEDIA_ERR_LOG("Async context is null");
        return;
    }

    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();

    if (!context->status) {
        CameraNapiUtils::CreateNapiErrorObject(env, context->errorCode,
                                               "No Metadata object Types or create array failed!", jsContext);
    } else {
        jsContext->status = true;
        napi_get_undefined(env, &jsContext->error);
        if (context->bRetBool) {
            napi_get_boolean(env, context->isSupported, &jsContext->data);
        } else {
            napi_get_undefined(env, &jsContext->data);
        }
    }

    if (!context->funcName.empty()) {
        jsContext->funcName = context->funcName;
    }

    if (context->work != nullptr) {
        CameraNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                             context->work, *jsContext);
    }
    delete context;
}

static int32_t ConvertJSArrayToNative(napi_env env, size_t argc, const napi_value argv[], size_t &i,
    MetadataOutputAsyncContext &asyncContext)
{
    MEDIA_DEBUG_LOG("ConvertJSArrayToNative is called");
    uint32_t len = 0;
    auto context = &asyncContext;

    if (napi_get_array_length(env, argv[i], &len) != napi_ok) {
        return -1;
    }

    for (uint32_t j = 0; j < len; j++) {
        napi_value metadataObjectType = nullptr;
        napi_valuetype valueType = napi_undefined;

        napi_get_element(env, argv[j], j, &metadataObjectType);
        napi_typeof(env, metadataObjectType, &valueType);
        if (valueType == napi_number) {
            bool isValid = true;
            int32_t metadataObjectTypeVal = 0;
            MetadataObjectType nativeMetadataObjType;
            napi_get_value_int32(env, metadataObjectType, &metadataObjectTypeVal);
            CameraNapiUtils::MapMetadataObjSupportedTypesEnumFromJS(
                metadataObjectTypeVal, nativeMetadataObjType, isValid);
            if (!isValid) {
                MEDIA_ERR_LOG("Unsupported metadata object type: napi object:%{public}d",
                    metadataObjectTypeVal);
                continue;
            }
            context->setSupportedMetadataObjectTypes.push_back(nativeMetadataObjType);
        }
        i++;
    }
    return static_cast<int32_t>(len);
}

static napi_value ConvertJSArgsToNative(napi_env env, size_t argc, const napi_value argv[],
    MetadataOutputAsyncContext &asyncContext)
{
    MEDIA_DEBUG_LOG("ConvertJSArgsToNative is called");
    const int32_t refCount = 1;
    napi_value result;
    auto context = &asyncContext;
    bool isArray = false;
    int32_t ArrayLen = 0;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if ((i == PARAM0) && (napi_is_array(env, argv[i], &isArray) == napi_ok)
            && (isArray == true)) {
            ArrayLen = ConvertJSArrayToNative(env, argc, argv, i, asyncContext);
            if (ArrayLen == -1) {
                napi_get_boolean(env, false, &result);
                return result;
            }
        } else if ((i == static_cast<size_t>(PARAM1 + ArrayLen)) && (valueType == napi_function)) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

static void GetSupportedMetadataObjectTypesAsyncCallbackComplete(napi_env env, napi_status status, void* data)
{
    MEDIA_DEBUG_LOG("GetSupportedMetadataObjectTypesAsyncCallbackComplete is called");
    auto context = static_cast<MetadataOutputAsyncContext*>(data);
    napi_value metadataObjectTypes = nullptr;
    CAMERA_NAPI_CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = true;
    napi_get_undefined(env, &jsContext->error);

    size_t len = context->SupportedMetadataObjectTypes.size();
    if (context->SupportedMetadataObjectTypes.empty()
        || (napi_create_array(env, &metadataObjectTypes) != napi_ok)) {
        MEDIA_ERR_LOG("No Metadata object Types or create array failed!");
        CameraNapiUtils::CreateNapiErrorObject(env, context->errorCode,
            "No Metadata object Types or create array failed!", jsContext);
    }

    size_t i;
    size_t j = 0;
    for (i = 0; i < len; i++) {
        int32_t iProp;
        CameraNapiUtils::MapMetadataObjSupportedTypesEnum(context->SupportedMetadataObjectTypes[i], iProp);
        napi_value value;
        if (iProp != -1 && napi_create_int32(env, iProp, &value) == napi_ok) {
            napi_set_element(env, metadataObjectTypes, j, value);
            j++;
        }
    }
    jsContext->data = metadataObjectTypes;

    if (!context->funcName.empty()) {
        jsContext->funcName = context->funcName;
    }

    if (context->work != nullptr) {
        CameraNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                             context->work, *jsContext);
    }
    delete context;
}

napi_value MetadataOutputNapi::GetSupportedMetadataObjectTypes(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("GetSupportedMetadataObjectTypes is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    int32_t refCount = 1;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameters maximum");

    napi_get_undefined(env, &result);
    std::unique_ptr<MetadataOutputAsyncContext> asyncContext = std::make_unique<MetadataOutputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }
        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "GetSupportedMetadataObjectTypes");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MetadataOutputAsyncContext*>(data);
                context->status = false;
                if (context->objectInfo != nullptr && context->objectInfo->metadataOutput_ != nullptr) {
                    context->funcName = "MetadataOutputNapi::GetSupportedMetadataObjectTypes";
                    context->SupportedMetadataObjectTypes =
                        context->objectInfo->metadataOutput_->GetSupportedMetadataObjectTypes();
                    context->status = true;
                }
            },
            GetSupportedMetadataObjectTypesAsyncCallbackComplete,
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for PhotoOutputNapi::Release");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
            asyncContext.release();
        }
    } else {
        MEDIA_ERR_LOG("GetSupportedMetadataObjectTypes call Failed!");
    }
    return result;
}

napi_value MetadataOutputNapi::SetCapturingMetadataObjectTypes(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("SetCapturingMetadataObjectTypes is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_TWO, "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    std::unique_ptr<MetadataOutputAsyncContext> asyncContext = std::make_unique<MetadataOutputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        CAMERA_NAPI_CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");
        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "SetCapturingMetadataObjectTypes");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MetadataOutputAsyncContext*>(data);
                context->status = false;
                if (context->objectInfo != nullptr && context->objectInfo->metadataOutput_ != nullptr) {
                    context->bRetBool = false;
                    context->status = true;
                    context->funcName = "MetadataOutputNapi::SetCapturingMetadataObjectTypes";
                    context->objectInfo->metadataOutput_->SetCapturingMetadataObjectTypes(
                        context->setSupportedMetadataObjectTypes);
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()),
            &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for "
                "MetadataOutputNapi::SetCapturingMetadataObjectTypes");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
            asyncContext.release();
        }
    } else {
        MEDIA_ERR_LOG("SetCapturingMetadataObjectTypes call Failed!");
    }
    return result;
}

napi_value MetadataOutputNapi::Start(napi_env env, napi_callback_info info)
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
    std::unique_ptr<MetadataOutputAsyncContext> asyncContext = std::make_unique<MetadataOutputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Start");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MetadataOutputAsyncContext*>(data);
                context->status = false;
                if (context->objectInfo != nullptr && context->objectInfo->metadataOutput_ != nullptr) {
                    context->bRetBool = false;
                    context->funcName = "MetadataOutputNapi::Start";
                    context->errorCode = context->objectInfo->metadataOutput_->Start();
                    context->status = context->errorCode == 0;
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for MetadataOutputNapi::Start");
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

napi_value MetadataOutputNapi::Stop(napi_env env, napi_callback_info info)
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
    std::unique_ptr<MetadataOutputAsyncContext> asyncContext = std::make_unique<MetadataOutputAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == ARGS_ONE) {
            CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Stop");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MetadataOutputAsyncContext*>(data);
                context->status = false;
                if (context->objectInfo != nullptr && context->objectInfo->metadataOutput_ != nullptr) {
                    context->bRetBool = false;
                    context->status = true;
                    context->funcName = "MetadataOutputNapi::Stop";
                    context->errorCode = context->objectInfo->metadataOutput_->Stop();
                    context->status = context->errorCode == 0;
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for MetadataOutputNapi::Stop");
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

napi_value MetadataOutputNapi::UnregisterCallback(napi_env env, napi_value jsThis,
    const std::string& eventType, napi_value callback)
{
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);
    MetadataOutputNapi* metadataOutputNapi = nullptr;
    napi_status status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&metadataOutputNapi));
    NAPI_ASSERT(env, status == napi_ok && metadataOutputNapi != nullptr, "Failed to metadataOutput napi instance.");
    NAPI_ASSERT(env, metadataOutputNapi->metadataOutputCallback_ != nullptr, "metadataOutputCallback is null.");
    if (eventType.compare("metadataObjectsAvailable") == 0) {
        metadataOutputNapi->metadataOutputCallback_->RemoveCallbackRef(env, callback);
    } else if (eventType.compare("error") == 0) {
        metadataOutputNapi->metadataStateCallback_->RemoveCallbackRef(env, callback);
    } else {
        MEDIA_ERR_LOG("Failed to Unregister Callback");
    }
    return undefinedResult;
}

napi_value MetadataOutputNapi::RegisterCallback(napi_env env, napi_value jsThis,
    const string &eventType, napi_value callback, bool isOnce)
{
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);
    MetadataOutputNapi* metadataOutputNapi = nullptr;
    napi_status status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&metadataOutputNapi));
    NAPI_ASSERT(env, status == napi_ok && metadataOutputNapi != nullptr,
        "Failed to retrieve MetadataOutputNapi instance.");
    NAPI_ASSERT(env, metadataOutputNapi->metadataOutput_ != nullptr, "metadataOutput instance is null.");
    if (eventType.compare("metadataObjectsAvailable") == 0) {
        if (metadataOutputNapi->metadataOutputCallback_ != nullptr) {
            metadataOutputNapi->metadataOutputCallback_->SaveCallbackReference(eventType, callback, isOnce);
        }
    } else if (eventType.compare("error") == 0) {
        if (metadataOutputNapi->metadataStateCallback_ == nullptr) {
            std::shared_ptr <MetadataStateCallbackNapi> callback =
                    std::make_shared<MetadataStateCallbackNapi>(env);
            metadataOutputNapi->metadataStateCallback_ = callback;
            metadataOutputNapi->metadataOutput_->SetCallback(callback);
        }
        metadataOutputNapi->metadataStateCallback_->SaveCallbackReference(eventType, callback, isOnce);
    } else {
        MEDIA_ERR_LOG("Failed to Register Callback: event type is empty!");
    }
    return undefinedResult;
}

napi_value MetadataOutputNapi::On(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("On is called");
    napi_value undefinedResult = nullptr;
    size_t argCount = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr, nullptr};
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);

    CAMERA_NAPI_GET_JS_ARGS(env, info, argCount, argv, thisVar);
    NAPI_ASSERT(env, argCount == ARGS_TWO, "requires 2 parameters");

    if (thisVar == nullptr || argv[PARAM0] == nullptr || argv[PARAM1] == nullptr) {
        MEDIA_ERR_LOG("Failed to retrieve details about the callback");
        return undefinedResult;
    }

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string
        || napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function) {
        return undefinedResult;
    }

    std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[PARAM0]);
    MEDIA_INFO_LOG("On eventType: %{public}s", eventType.c_str());
    return RegisterCallback(env, thisVar, eventType, argv[PARAM1], false);
}

napi_value MetadataOutputNapi::Once(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("Once is called");
    napi_value undefinedResult = nullptr;
    size_t argCount = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr, nullptr};
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);

    CAMERA_NAPI_GET_JS_ARGS(env, info, argCount, argv, thisVar);
    NAPI_ASSERT(env, argCount == ARGS_TWO, "requires 2 parameters");

    if (thisVar == nullptr || argv[PARAM0] == nullptr || argv[PARAM1] == nullptr) {
        MEDIA_ERR_LOG("Failed to retrieve details about the callback");
        return undefinedResult;
    }

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string
        || napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function) {
        return undefinedResult;
    }

    std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[PARAM0]);
    MEDIA_INFO_LOG("Once eventType: %{public}s", eventType.c_str());
    return RegisterCallback(env, thisVar, eventType, argv[PARAM1], true);
}

napi_value MetadataOutputNapi::Off(napi_env env, napi_callback_info info)
{
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);
    const size_t minArgCount = 1;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr, nullptr};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (argc < minArgCount) {
        return undefinedResult;
    }

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string) {
        return undefinedResult;
    }

    napi_valuetype secondArgsType = napi_undefined;
    if (argc > minArgCount &&
        (napi_typeof(env, argv[PARAM1], &secondArgsType) != napi_ok || secondArgsType != napi_function)) {
        return undefinedResult;
    }
    std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[0]);
    MEDIA_INFO_LOG("Off eventType: %{public}s", eventType.c_str());
    return UnregisterCallback(env, thisVar, eventType, argv[PARAM1]);
}
} // namespace CameraStandard
} // namespace OHOS