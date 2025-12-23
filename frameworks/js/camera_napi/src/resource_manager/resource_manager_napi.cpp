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

#include "resource_manager/resource_manager_napi.h"

#include <algorithm>
#include <memory>
#include <mutex>
#include <new>
#include <vector>

#include "camera_log.h"
#include "js_native_api.h"
#include "napi/native_common.h"
#include "camera_napi_worker_queue_keeper.h"
#include "camera_napi_param_parser.h"
#include "resource_manager/feature_result_parser.h"
#include "camera_napi_utils.h"
#include "camera_napi_security_utils.h"

namespace OHOS {
namespace CameraStandard {
namespace {
static const char RESOURCE_MANAGER_NAPI_CLASS_NAME[] = "ResourceManager";
}  // namespace

thread_local napi_ref ResourceManagerNapi::sConstructor_ = nullptr;
thread_local uint32_t ResourceManagerNapi::resourceManagerNapiTaskId = RESOURCE_MANAGER_TASKID;
thread_local napi_ref g_ignoreRef_ = nullptr;

void __attribute__((constructor)) Onload()
{
    MEDIA_INFO_LOG("ResourceManagerNapi::OnLoad");
}

void __attribute__((destructor)) OnUnload()
{
    MEDIA_INFO_LOG("ResourceManagerNapi::OnUnload");
}

ResourceManagerNapi::ResourceManagerNapi() : env_(nullptr)
{
    CAMERA_SYNC_TRACE;
}

ResourceManagerNapi::~ResourceManagerNapi()
{
    MEDIA_DEBUG_LOG("~ResourceManagerNapi is called");
}

void InitRequestBody(RequestBodyParams &requestBody)
{
    ReqCallerInfo callerInfo = {.bundleName = ""};
    RequestBodyParams requestBodyTmp{.callerInfo = callerInfo,
                                     .featureId = FeatureId::INVALID_FEATURE_ID,
                                     .typeId = TypeId::INVALID_TYPE_ID,
                                     .templateId = -1,
                                     .resourceId = -1,
                                     .packageType = PackageType::INVALID_PACKAGE_TYPE};
    requestBody = requestBodyTmp;
}

void CommonCompleteCallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<ResourceManagerAsyncContext *>(data);
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
        if (!context->bRetBool) {
            FeatureResultParser featureResultParser(env);
            jsContext->data = (context->requestBody.resourceId != -1) ?
                                featureResultParser.WrapFeatureResult(context->detailFeatureResult) :
                                featureResultParser.WrapFeatureResult(context->featureResult);
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
    context->FreeHeldNapiValue(env);
    delete context;
}

void BaseCompleteCallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<BaseAsyncContext *>(data);
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
        if (!context->bRetBool) {
            FeatureResultParser featureResultParser(env);
            jsContext->data = featureResultParser.WrapBaseResult(context->baseResult);
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
    context->FreeHeldNapiValue(env);
    delete context;
}

void ProcessCompleteCallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<ProcessAsyncContext *>(data);
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
        if (!context->bRetBool) {
            FeatureResultParser featureResultParser(env);
            jsContext->data = featureResultParser.WrapProcess(context->process);
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
    context->FreeHeldNapiValue(env);
    delete context;
}

napi_status AddNamedProperty(napi_env env, napi_value object, const std::string name, int32_t enumValue)
{
    napi_status status;
    napi_value enumNapiValue;
    status = napi_create_int32(env, enumValue, &enumNapiValue);
    if (status == napi_ok) {
        status = napi_set_named_property(env, object, name.c_str(), enumNapiValue);
    }
    return status;
}

napi_value CreateObjectWithMap(napi_env env, const std::string objectName,
                               const std::unordered_map<std::string, int32_t> &inputMap, napi_ref &outputRef)
{
    MEDIA_DEBUG_LOG("Create %{public}s is called", objectName.c_str());
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName;
        for (auto itr = inputMap.begin(); itr != inputMap.end(); ++itr) {
            propName = itr->first;
            status = AddNamedProperty(env, result, propName, itr->second);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add %{public}s property!", objectName.c_str());
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = NapiRefManager::CreateMemSafetyRef(env, result, &outputRef);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("Create %{public}s call Failed!", objectName.c_str());
    napi_get_undefined(env, &result);
    return result;
}

void WrapBaseResultObject(napi_env env, const BaseResult &baseResult, napi_value& result)
{
    napi_value propValue;
    if (napi_create_int32(env, baseResult.resCode, &propValue) == napi_ok) {
        napi_set_named_property(env, result, "resCode", propValue);
    }
    if (napi_create_string_utf8(env, baseResult.resMsg.c_str(), NAPI_AUTO_LENGTH, &propValue) == napi_ok) {
        napi_set_named_property(env, result, "resMsg", propValue);
    }
}

napi_value ResourceManagerNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_INFO_LOG("ResourceManagerNapi::Init is called");
    napi_status status;
    napi_value ctorObj;

    napi_property_descriptor resource_manager_props[] = {};
    napi_property_descriptor resource_manager_static_props[] = {
        DECLARE_NAPI_STATIC_FUNCTION("queryFeatureInfo", QueryFeatureInfo),
        DECLARE_NAPI_STATIC_FUNCTION("requestFeatureInfo", RequestFeatureInfo),
        DECLARE_NAPI_STATIC_FUNCTION("destroy", Destroy),
        DECLARE_NAPI_STATIC_FUNCTION("pauseTask", PauseTask),
        DECLARE_NAPI_STATIC_FUNCTION("resumeTask", ResumeTask),
        DECLARE_NAPI_PROPERTY("ErrorCode", CreateObjectWithMap(env, "ErrorCode", mapErrorCode, g_ignoreRef_)),
        DECLARE_NAPI_PROPERTY("ResourceDownloadStatus", CreateObjectWithMap(env, "ResourceDownloadStatus",
                                                                            mapResourceDownloadStatus, g_ignoreRef_)),
        DECLARE_NAPI_PROPERTY("FeatureId", CreateObjectWithMap(env, "FeatureId", mapFeatureId, g_ignoreRef_)),
        DECLARE_NAPI_PROPERTY("TypeId", CreateObjectWithMap(env, "TypeId", mapTypeId, g_ignoreRef_)),
        DECLARE_NAPI_PROPERTY("PackageType", CreateObjectWithMap(env, "PackageType", mapPackageType, g_ignoreRef_)),
        DECLARE_NAPI_PROPERTY("ParamType", CreateObjectWithMap(env, "ParamType", mapParamType, g_ignoreRef_)),
        DECLARE_NAPI_PROPERTY("SelectorOptions",
                              CreateObjectWithMap(env, "SelectorOptions", mapSelectorOptions, g_ignoreRef_)),
        DECLARE_NAPI_PROPERTY("SelectorType", CreateObjectWithMap(env, "SelectorType", mapSelectorType, g_ignoreRef_)),
        DECLARE_NAPI_PROPERTY("ShapeType", CreateObjectWithMap(env, "ShapeType", mapShapeType, g_ignoreRef_)),
    };
    status = napi_define_class(env, RESOURCE_MANAGER_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH, ResourceManagerNapiConstructor,
                               nullptr, sizeof(resource_manager_props) / sizeof(resource_manager_props[PARAM0]),
                               resource_manager_props, &ctorObj);
    if (status == napi_ok) {
        if (NapiRefManager::CreateMemSafetyRef(env, ctorObj, &sConstructor_) == napi_ok) {
            status = napi_set_named_property(env, exports, RESOURCE_MANAGER_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok &&
                napi_define_properties(
                    env, exports, sizeof(resource_manager_static_props) / sizeof(resource_manager_static_props[PARAM0]),
                    resource_manager_static_props) == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

// Constructor callback
napi_value ResourceManagerNapi::ResourceManagerNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("ResourceManagerNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<ResourceManagerNapi> obj = std::make_unique<ResourceManagerNapi>();
        obj->env_ = env;
        status = napi_wrap(env, thisVar, reinterpret_cast<void *>(obj.get()),
                           ResourceManagerNapi::ResourceManagerNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("ResourceManagerNapiConstructor call Failed!");
    return result;
}

void ResourceManagerNapi::ResourceManagerNapiDestructor(napi_env env, void *nativeObject, void *finalize_hint)
{
    MEDIA_DEBUG_LOG("ResourceManagerNapiDestructor is called");
    ResourceManagerNapi *resource = reinterpret_cast<ResourceManagerNapi *>(nativeObject);
    if (resource != nullptr) {
        delete resource;
    }
}

bool ResourceManagerNapi::CheckFeatureId(int32_t featureId)
{
    std::vector<int32_t> supportedFeatureIds = {
        static_cast<int32_t>(FeatureId::FEATURE_ID_WATERMARK),
    };
    auto it = find(supportedFeatureIds.begin(), supportedFeatureIds.end(), featureId);
    return it != supportedFeatureIds.end();
}

bool ResourceManagerNapi::CheckTypeId(int32_t typeId)
{
    std::vector<int32_t> supportedTypeIds = {static_cast<int32_t>(TypeId::INDIVIDUALITY),
                                             static_cast<int32_t>(TypeId::TIME_LIMIT)};
    auto it = find(supportedTypeIds.begin(), supportedTypeIds.end(), typeId);
    return it != supportedTypeIds.end();
}

bool ResourceManagerNapi::CheckPackageType(int32_t packageType)
{
    std::vector<int32_t> supportedPackageType = {static_cast<int32_t>(PackageType::COVER),
                                                 static_cast<int32_t>(PackageType::FULL)};
    auto it = find(supportedPackageType.begin(), supportedPackageType.end(), packageType);
    return it != supportedPackageType.end();
}

bool ResourceManagerNapi::CheckPositionType(int32_t positionType)
{
    std::vector<int32_t> supportedPositionType = {
        static_cast<int32_t>(PositionType::TEXT), static_cast<int32_t>(PositionType::PICTURE),
        static_cast<int32_t>(PositionType::COLOR), static_cast<int32_t>(PositionType::FONT)};
    auto it = find(supportedPositionType.begin(), supportedPositionType.end(), positionType);
    return it != supportedPositionType.end();
}

void ResourceManagerNapi::ParseRequestBodyParams(napi_env env, napi_value info, RequestBodyParams *requestBody)
{
    napi_value tempValue = nullptr;
    int32_t res;
    if (requestBody == nullptr) {
        return;
    }
    ReqCallerInfo callerInfo;
    if (napi_get_named_property(env, info, "callerInfo", &tempValue) == napi_ok) {
        ParseCallerInfo(env, tempValue, &callerInfo);
        requestBody->callerInfo = callerInfo;
    }
    if (napi_get_named_property(env, info, "featureId", &tempValue) == napi_ok &&
        napi_get_value_int32(env, tempValue, &res) == napi_ok) {
        requestBody->featureId = (FeatureId)res;
    }
    if (napi_get_named_property(env, info, "typeId", &tempValue) == napi_ok &&
        napi_get_value_int32(env, tempValue, &res) == napi_ok) {
        requestBody->typeId = (TypeId)res;
    }
    if (napi_get_named_property(env, info, "templateId", &tempValue) == napi_ok &&
        napi_get_value_int32(env, tempValue, &res) == napi_ok) {
        requestBody->templateId = res;
    }
    if (napi_get_named_property(env, info, "resourceId", &tempValue) == napi_ok &&
        napi_get_value_int32(env, tempValue, &res) == napi_ok) {
        requestBody->resourceId = res;
    }
    if (napi_get_named_property(env, info, "packageType", &tempValue) == napi_ok &&
        napi_get_value_int32(env, tempValue, &res) == napi_ok) {
        requestBody->packageType = (PackageType)res;
    }
}

void ResourceManagerNapi::ParseCallerInfo(napi_env env, napi_value info, ReqCallerInfo *callerInfo)
{
    napi_value tempValue = nullptr;
    if (callerInfo == nullptr) {
        return;
    }
    // ReqCallerInfo->bundleName
    if (napi_get_named_property(env, info, "bundleName", &tempValue) == napi_ok) {
        std::string bundleName = CameraNapiUtils::GetStringArgument(env, tempValue);
        callerInfo->bundleName = bundleName;
    }
    return;
}

void ResourceManagerNapi::ParseDeletePredicates(napi_env env, napi_value info, DeletePredicates *deletePredicates)
{
    napi_value tempValue = nullptr;
    int32_t temp;
    if (deletePredicates == nullptr) {
        return;
    }

    if (napi_get_named_property(env, info, "downloadedDuration", &tempValue) == napi_ok) {
        if (napi_get_value_int32(env, tempValue, &temp) == napi_ok) {
            deletePredicates->downloadedDuration = temp;
        }
    }
    return;
}

napi_value ResourceManagerNapi::QueryFeatureInfo(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi QueryFeatureInfo is called!");
        return nullptr;
    }
    CAMERA_SYNC_TRACE;
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    size_t argc = CameraNapiUtils::GetNapiArgs(env, info);
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    if (napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr) != napi_ok) {
        MEDIA_ERR_LOG("ResourceManagerNapi::QueryFeatureInfo napi_get_cb_info failed");
        return result;
    }
    if (argc != ARGS_TWO) {
        MEDIA_ERR_LOG("ResourceManagerNapi::QueryFeatureInfo arg size=2");
        return result;
    }
    napi_valuetype res = napi_undefined;
    napi_typeof(env, argv[PARAM1], &res);
    if (res != napi_function) {
        MEDIA_ERR_LOG("ResourceManagerNapi::QueryFeatureInfo parameter type error");
        return result;
    }
    RequestBodyParams requestBody;
    InitRequestBody(requestBody);
    ParseRequestBodyParams(env, argv[PARAM0], &requestBody);
    std::unique_ptr<ResourceManagerAsyncContext> asyncContext = std::make_unique<ResourceManagerAsyncContext>();
    int32_t refCount = 1;
    napi_create_reference(env, argv[PARAM1], refCount, &asyncContext->callbackRef);
    asyncContext->funcName = "ResourceManager::QueryFeatureInfo";
    asyncContext->taskId = CameraNapiUtils::IncrementAndGet(resourceManagerNapiTaskId);
    asyncContext->requestBody = requestBody;
    napi_value resource = nullptr;
    CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "QueryFeatureInfo");
    napi_status status = napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {
            auto context = static_cast<ResourceManagerAsyncContext *>(data);
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            MEDIA_INFO_LOG("Execute query operation");
            context->status = true;
        }, CommonCompleteCallback, static_cast<void *>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("ResourceManager::QueryFeatureInfo create async work failed");
    } else {
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    return result;
}

napi_value ResourceManagerNapi::RequestFeatureInfo(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi RequestFeatureInfo is called!");
        return nullptr;
    }
    CAMERA_SYNC_TRACE;
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    size_t argc = CameraNapiUtils::GetNapiArgs(env, info);
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    if (napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr) != napi_ok) {
        MEDIA_ERR_LOG("ResourceManagerNapi::RequestFeatureInfo napi get callback info failed");
        return result;
    }
    if (argc != ARGS_TWO && argc != ARGS_THREE) {
        MEDIA_ERR_LOG("ResourceManagerNapi::RequestFeatureInfo argsize error");
        return result;
    }
    napi_valuetype resParam = napi_undefined;
    napi_typeof(env, argv[PARAM1], &resParam);
    if (resParam != napi_function) {
        MEDIA_ERR_LOG("ResourceManagerNapi::RequestFeatureInfo parameter type error");
        return result;
    }
    RequestBodyParams requestBody;
    InitRequestBody(requestBody);
    ParseRequestBodyParams(env, argv[PARAM0], &requestBody);
    std::unique_ptr<ResourceManagerAsyncContext> asyncContextParam = std::make_unique<ResourceManagerAsyncContext>();
    int32_t refCountParam = 1;
    napi_create_reference(env, argv[PARAM1], refCountParam, &asyncContextParam->callbackRef);
    asyncContextParam->funcName = "ResourceManager::RequestFeatureInfo";
    asyncContextParam->taskId = CameraNapiUtils::IncrementAndGet(resourceManagerNapiTaskId);
    asyncContextParam->requestBody = requestBody;
    napi_value resourceParam = nullptr;
    CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resourceParam, "RequestFeatureInfo");
    napi_status status = napi_create_async_work(env, nullptr, resourceParam, [](napi_env env, void *data) {
            auto context = static_cast<ResourceManagerAsyncContext *>(data);
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            MEDIA_INFO_LOG("Execute request operation");
            context->status = true;
        }, CommonCompleteCallback, static_cast<void *>(asyncContextParam.get()), &asyncContextParam->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("RequestFeatureInfo create async work failed");
    } else {
        napi_queue_async_work_with_qos(env, asyncContextParam->work, napi_qos_user_initiated);
        asyncContextParam.release();
    }
    return result;
}

napi_value ResourceManagerNapi::Destroy(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi Destroy is called!");
        return nullptr;
    }
    CAMERA_SYNC_TRACE;
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    size_t argc = CameraNapiUtils::GetNapiArgs(env, info);
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    if (napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr) != napi_ok) {
        MEDIA_ERR_LOG("ResourceManagerNapi::Destroy get callback info failed");
        return result;
    }
    if (argc != ARGS_ONE) {
        MEDIA_ERR_LOG("ResourceManagerNapi::Destroy argsize error");
        return result;
    }
    RequestBodyParams requestBody;
    InitRequestBody(requestBody);
    ParseRequestBodyParams(env, argv[PARAM0], &requestBody);

    std::unique_ptr<BaseAsyncContext> asyncContext = std::make_unique<BaseAsyncContext>();
    asyncContext->funcName = "ResourceManagerNapi::Destroy";
    asyncContext->taskId = CameraNapiUtils::IncrementAndGet(resourceManagerNapiTaskId);
    asyncContext->requestBody = requestBody;
    if ((asyncContext->callbackRef) == nullptr) {
        MEDIA_ERR_LOG("ResourceManagerNapi::Destroy callbackRef is null");
    }
    CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
    napi_value resource = nullptr;
    CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Destroy");
    napi_status status = napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void *data) {
            auto context = static_cast<BaseAsyncContext *>(data);
            // Start async trace
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            MEDIA_INFO_LOG("Execute destroy operation");
            context->status = true;
        },
        BaseCompleteCallback, static_cast<void *>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("ResourceManagerNapi::Destroy create async work failed");
    } else {
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    return result;
}

napi_value ResourceManagerNapi::PauseTask(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi PauseTask is called!");
        return nullptr;
    }
    CAMERA_SYNC_TRACE;
    napi_value result = nullptr;
    napi_status status = napi_create_object(env, &result);
    if (status != napi_ok) {
        napi_get_undefined(env, &result);
        return result;
    }
    size_t argc = CameraNapiUtils::GetNapiArgs(env, info);
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    if (napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr) != napi_ok) {
        MEDIA_ERR_LOG("ResourceManagerNapi::PauseTask get callback info failed");
        return result;
    }
    if (argc != ARGS_ONE) {
        MEDIA_ERR_LOG("ResourceManagerNapi::PauseTask arg size error");
        return result;
    }
    RequestBodyParams requestBody;
    InitRequestBody(requestBody);
    ParseRequestBodyParams(env, argv[PARAM0], &requestBody);
    std::unique_ptr<BaseAsyncContext> asyncContext = std::make_unique<BaseAsyncContext>();
    asyncContext->funcName = "ResourceManagerNapi::PauseTask";
    asyncContext->taskId = CameraNapiUtils::IncrementAndGet(resourceManagerNapiTaskId);
    asyncContext->requestBody = requestBody;
    if ((asyncContext->callbackRef) == nullptr) {
        MEDIA_INFO_LOG("ResourceManagerNapi::PauseTask callbackRef is null");
    }
    CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
    napi_value resource = nullptr;
    CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "PauseTask");
    status = napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {
            auto context = static_cast<BaseAsyncContext *>(data);
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            MEDIA_INFO_LOG("Execute pause operation");
            context->status = true;
        }, BaseCompleteCallback, static_cast<void *>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("ResourceManagerNapi::PauseTask napi create async work failed");
    } else {
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated);
        asyncContext.release();
    }
    return result;
}

napi_value ResourceManagerNapi::ResumeTask(napi_env env, napi_callback_info info)
{
    if (!CameraNapiSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi ResumeTask is called!");
        return nullptr;
    }
    CAMERA_SYNC_TRACE;
    napi_value result = nullptr;
    napi_status status = napi_create_object(env, &result);
    if (status != napi_ok) {
        napi_get_undefined(env, &result);
        return result;
    }
    BaseResult baseResult{.resCode = 1, .resMsg = "ResumeTask Failed"};
    WrapBaseResultObject(env, baseResult, result);

    size_t argc = CameraNapiUtils::GetNapiArgs(env, info);
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    if (napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr) != napi_ok) {
        MEDIA_ERR_LOG("ResourceManagerNapi::ResumeTask get callback info failed");
        return result;
    }
    if (argc != ARGS_ONE) {
        MEDIA_ERR_LOG("ResourceManagerNapi::ResumeTask argsize error");
        return result;
    }
    RequestBodyParams requestBody;
    InitRequestBody(requestBody);
    ParseRequestBodyParams(env, argv[PARAM0], &requestBody);
    MEDIA_INFO_LOG("Execute resume operation");
    WrapBaseResultObject(env, baseResult, result);
    return result;
}
}  // namespace CameraStandard
}  // namespace OHOS