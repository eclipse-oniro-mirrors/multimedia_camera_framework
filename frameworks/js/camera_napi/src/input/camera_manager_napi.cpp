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

#include "input/camera_napi.h"
#include "input/camera_manager_napi.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;

thread_local napi_ref CameraManagerNapi::sConstructor_ = nullptr;
thread_local uint32_t CameraManagerNapi::cameraManagerTaskId = CAMERA_MANAGER_TASKID;

namespace {
    constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "CameraManager"};
}

CameraManagerNapi::CameraManagerNapi() : env_(nullptr), wrapper_(nullptr)
{
    CAMERA_SYNC_TRACE;
}

CameraManagerNapi::~CameraManagerNapi()
{
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
    if (cameraManager_) {
        cameraManager_ = nullptr;
    }
}

// Constructor callback
napi_value CameraManagerNapi::CameraManagerNapiConstructor(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CameraManagerNapi> obj = std::make_unique<CameraManagerNapi>();
        obj->env_ = env;
        obj->cameraManager_ = CameraManager::GetInstance();
        if (obj->cameraManager_ == nullptr) {
            MEDIA_ERR_LOG("Failure wrapping js to native napi, obj->cameraManager_ null");
            return result;
        }
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           CameraManagerNapi::CameraManagerNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }

    return result;
}

void CameraManagerNapi::CameraManagerNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CameraManagerNapiDestructor enter");
    CameraManagerNapi* camera = reinterpret_cast<CameraManagerNapi*>(nativeObject);
    if (camera != nullptr) {
        delete camera;
    }
}

napi_value CameraManagerNapi::Init(napi_env env, napi_value exports)
{
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor camera_mgr_properties[] = {
        // CameraManager
        DECLARE_NAPI_FUNCTION("getSupportedCameras", GetSupportedCameras),
        DECLARE_NAPI_FUNCTION("getSupportedOutputCapability", GetSupportedOutputCapability),
        DECLARE_NAPI_FUNCTION("isCameraMuted", IsCameraMuted),
        DECLARE_NAPI_FUNCTION("isCameraMuteSupported", IsCameraMuteSupported),
        DECLARE_NAPI_FUNCTION("muteCamera", MuteCamera),
        DECLARE_NAPI_FUNCTION("createCameraInput", CreateCameraInputInstance),
        DECLARE_NAPI_FUNCTION("createCaptureSession", CreateCameraSessionInstance),
        DECLARE_NAPI_FUNCTION("createPreviewOutput", CreatePreviewOutputInstance),
        DECLARE_NAPI_FUNCTION("createDeferredPreviewOutput", CreateDeferredPreviewOutputInstance),
        DECLARE_NAPI_FUNCTION("createPhotoOutput", CreatePhotoOutputInstance),
        DECLARE_NAPI_FUNCTION("createVideoOutput", CreateVideoOutputInstance),
        DECLARE_NAPI_FUNCTION("createMetadataOutput", CreateMetadataOutputInstance),
        DECLARE_NAPI_FUNCTION("on", On)
    };

    status = napi_define_class(env, CAMERA_MANAGER_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH,
                               CameraManagerNapiConstructor, nullptr,
                               sizeof(camera_mgr_properties) / sizeof(camera_mgr_properties[PARAM0]),
                               camera_mgr_properties, &ctorObj);
    if (status == napi_ok) {
        if (napi_create_reference(env, ctorObj, refCount, &sConstructor_) == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_MANAGER_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }

    return nullptr;
}

napi_value CameraManagerNapi::CreateCameraManager(napi_env env)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value ctor;

    status = napi_get_reference_value(env, sConstructor_, &ctor);
    if (status == napi_ok) {
        status = napi_new_instance(env, ctor, 0, nullptr, &result);
        if (status == napi_ok) {
            return result;
        } else {
            MEDIA_ERR_LOG("New instance could not be obtained");
        }
    }
    napi_get_undefined(env, &result);
    return result;
}

static napi_value CreateCameraJSArray(napi_env env, napi_status status,
    std::vector<sptr<CameraDevice>> cameraObjList)
{
    napi_value cameraArray = nullptr;
    napi_value camera = nullptr;

    if (cameraObjList.empty()) {
        MEDIA_ERR_LOG("cameraObjList is empty");
        return cameraArray;
    }

    status = napi_create_array(env, &cameraArray);
    if (status == napi_ok) {
        for (size_t i = 0; i < cameraObjList.size(); i++) {
            camera = CameraDeviceNapi::CreateCameraObj(env, cameraObjList[i]);
            MEDIA_INFO_LOG("GetCameras CreateCameraObj success");
            if (camera == nullptr || napi_set_element(env, cameraArray, i, camera) != napi_ok) {
                MEDIA_ERR_LOG("Failed to create camera napi wrapper object");
                return nullptr;
            }
        }
    }
    return cameraArray;
}

void CameraManagerCommonCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto context = static_cast<CameraManagerContext*>(data);

    CAMERA_NAPI_CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    MEDIA_INFO_LOG("modeForAsync = %{public}d", context->modeForAsync);
    napi_get_undefined(env, &jsContext->error);
    if (context->modeForAsync == CREATE_DEFERRED_PREVIEW_OUTPUT_ASYNC_CALLBACK) {
        jsContext->data = PhotoOutputNapi::CreatePhotoOutput(env, context->profile, context->surfaceId);
        MEDIA_INFO_LOG("CreatePhotoOutput context->photoSurfaceId : %{public}s", context->surfaceId.c_str());
    }

    if (jsContext->data == nullptr) {
        context->status = false;
        context->errString = context->funcName + " failed";
        MEDIA_ERR_LOG("Failed to create napi, funcName = %{public}s", context->funcName.c_str());
        CameraNapiUtils::CreateNapiErrorObject(env, context->errorCode, context->errString.c_str(), jsContext);
    } else {
        jsContext->status = true;
        MEDIA_INFO_LOG("Success to create napi, funcName = %{public}s", context->funcName.c_str());
    }

    // Finish async trace
    if (!context->funcName.empty() && context->taskId > 0) {
        CAMERA_FINISH_ASYNC_TRACE(context->funcName, context->taskId);
        jsContext->funcName = context->funcName;
    }
    if (context->work != nullptr) {
        CameraNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                             context->work, *jsContext);
    }
    MEDIA_INFO_LOG("context->InvokeJSAsyncMethod end");
    delete context;
}

napi_value CameraManagerNapi::CreateCameraSessionInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreateCameraSessionInstance is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);

    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status != napi_ok || cameraManagerNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap failure!");
        return nullptr;
    }
    result = CameraSessionNapi::CreateCameraSession(env);
    return result;
}

bool ParseSize(napi_env env, napi_value root, Size* size)
{
    napi_value tempValue = nullptr;

    if (napi_get_named_property(env, root, "width", &tempValue) == napi_ok) {
        napi_get_value_uint32(env, tempValue, &size->width);
    }

    if (napi_get_named_property(env, root, "height", &tempValue) == napi_ok) {
        napi_get_value_uint32(env, tempValue, &(size->height));
    }

    return true;
}

bool ParseProfile(napi_env env, napi_value root, Profile* profile)
{
    napi_value res = nullptr;

    if (napi_get_named_property(env, root, "size", &res) == napi_ok) {
        ParseSize(env, res, &(profile->size_));
    }

    int32_t intValue = {0};
    if (napi_get_named_property(env, root, "format", &res) == napi_ok) {
        napi_get_value_int32(env, res, &intValue);
        profile->format_ = static_cast<CameraFormat>(intValue);
    }

    return true;
}

bool ParseVideoProfile(napi_env env, napi_value root, VideoProfile* profile)
{
    napi_value res = nullptr;

    if (napi_get_named_property(env, root, "size", &res) == napi_ok) {
        ParseSize(env, res, &(profile->size_));
    }
    int32_t intValue = {0};
    if (napi_get_named_property(env, root, "format", &res) == napi_ok) {
        napi_get_value_int32(env, res, &intValue);
        profile->format_ = static_cast<CameraFormat>(intValue);
    }

    if (napi_get_named_property(env, root, "frameRateRange", &res) == napi_ok) {
        const static int32_t LENGTH = 2;
        std::vector<int32_t> rateRanges(LENGTH);

        int32_t intValue = {0};
        const static uint32_t MIN_INDEX = 0;
        const static uint32_t MAX_INDEX = 1;

        napi_value value;
        if (napi_get_named_property(env, res, "min", &value) == napi_ok) {
            napi_get_value_int32(env, value, &intValue);
            rateRanges[MIN_INDEX] = intValue;
        }
        if (napi_get_named_property(env, res, "max", &value) == napi_ok) {
            napi_get_value_int32(env, value, &intValue);
            rateRanges[MAX_INDEX] = intValue;
        }
        profile->framerates_ = rateRanges;
    }

    return true;
}

static napi_value ConvertJSArgsToNative(napi_env env, size_t argc, const napi_value argv[],
    CameraManagerContext &asyncContext)
{
    char buffer[PATH_MAX];
    const int32_t refCount = 1;
    napi_value result;
    size_t length = 0;
    auto context = &asyncContext;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_object) {
            bool isVideoMode = false;
            (void)napi_has_named_property(env, argv[i], "frameRateRange", &isVideoMode);
            if (!isVideoMode) {
                ParseProfile(env, argv[i], &(context->profile));
                MEDIA_INFO_LOG("ConvertJSArgsToNative ParseProfile "
                    "size.width = %{public}d, size.height = %{public}d, format = %{public}d",
                    context->profile.size_.width, context->profile.size_.height, context->profile.format_);
            } else {
                ParseVideoProfile(env, argv[i], &(context->videoProfile));
                MEDIA_INFO_LOG("ConvertJSArgsToNative ParseVideoProfile "
                    "size.width = %{public}d, size.height = %{public}d, format = %{public}d, "
                    "frameRateRange : min = %{public}d, max = %{public}d",
                    context->videoProfile.size_.width,
                    context->videoProfile.size_.height,
                    context->videoProfile.format_,
                    context->videoProfile.framerates_[0],
                    context->videoProfile.framerates_[1]);
            }
        } else if (i == PARAM1 && valueType == napi_string) {
            if (napi_get_value_string_utf8(env, argv[i], buffer, PATH_MAX, &length) == napi_ok) {
                MEDIA_INFO_LOG("surfaceId buffer --1  : %{public}s", buffer);
                context->surfaceId = std::string(buffer);
                MEDIA_INFO_LOG("context->surfaceId after convert : %{public}s", context->surfaceId.c_str());
            } else {
                MEDIA_ERR_LOG("Could not able to read surfaceId argument!");
            }
        } else if (i == PARAM2 && valueType == napi_function) {
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

napi_value CameraManagerNapi::CreatePreviewOutputInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreatePreviewOutputInstance called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_TWO, argv, CREATE_PREVIEW_OUTPUT_INSTANCE)) {
        MEDIA_INFO_LOG("CheckInvalidArgument napi_throw_type_error ");
        return result;
    }
    MEDIA_INFO_LOG("CheckInvalidArgument pass");
    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status != napi_ok || cameraManagerNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap failure!");
        return nullptr;
    }
    Profile profile;
    ParseProfile(env, argv[PARAM0], &profile);
    MEDIA_INFO_LOG("ConvertJSArgsToNative ParseProfile "
                   "size.width = %{public}d, size.height = %{public}d, format = %{public}d",
                   profile.size_.width, profile.size_.height, profile.format_);

    char buffer[PATH_MAX];
    size_t length = 0;
    if (napi_get_value_string_utf8(env, argv[PARAM1], buffer, PATH_MAX, &length) == napi_ok) {
        MEDIA_INFO_LOG("surfaceId buffer --1  : %{public}s", buffer);
        std::string surfaceId = std::string(buffer);
        result = PreviewOutputNapi::CreatePreviewOutput(env, profile, surfaceId);
        MEDIA_INFO_LOG("surfaceId after convert : %{public}s", surfaceId.c_str());
    } else {
        MEDIA_ERR_LOG("Could not able to read surfaceId argument!");
    }
    return result;
}

napi_value CameraManagerNapi::CreateDeferredPreviewOutputInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreateDeferredPreviewOutputInstance is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value resource = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_TWO, "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    std::unique_ptr<CameraManagerContext> asyncContext = std::make_unique<CameraManagerContext>();
    result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
    CAMERA_NAPI_CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");
    CAMERA_NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
    CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "CreateDeferredPreviewOutput");
    status = napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void* data) {
            auto context = static_cast<CameraManagerContext*>(data);
            // Start async trace
            context->funcName = "CameraManagerNapi::CreateDeferredPreviewOutputInstance";
            context->taskId = CameraNapiUtils::IncreamentAndGet(cameraManagerTaskId);
            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            MEDIA_INFO_LOG("cameraManager_->CreateDeferredPreviewOutputInstance()");
            context->status = true;
            context->modeForAsync = CREATE_DEFERRED_PREVIEW_OUTPUT_ASYNC_CALLBACK;
        },
        CameraManagerCommonCompleteCallback, static_cast<void*>(asyncContext.get()), &asyncContext->work);
    if (status != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for CreatePhotoOutputInstance");
        napi_get_undefined(env, &result);
    } else {
        napi_queue_async_work(env, asyncContext->work);
        asyncContext.release();
    }

    return result;
}

napi_value CameraManagerNapi::CreatePhotoOutputInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreatePhotoOutputInstance is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_TWO, argv, CREATE_PHOTO_OUTPUT_INSTANCE)) {
        return result;
    }

    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status != napi_ok || cameraManagerNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap failure!");
        return nullptr;
    }

    Profile profile;
    ParseProfile(env, argv[PARAM0], &profile);
    MEDIA_INFO_LOG("ParseProfile "
                   "size.width = %{public}d, size.height = %{public}d, format = %{public}d",
                   profile.size_.width, profile.size_.height, profile.format_);

    char buffer[PATH_MAX];
    size_t length = 0;
    if (napi_get_value_string_utf8(env, argv[PARAM1], buffer, PATH_MAX, &length) == napi_ok) {
        MEDIA_INFO_LOG("surfaceId buffer --1  : %{public}s", buffer);
        std::string surfaceId = std::string(buffer);
        result = PhotoOutputNapi::CreatePhotoOutput(env, profile, surfaceId);
        MEDIA_INFO_LOG("surfaceId after convert : %{public}s", surfaceId.c_str());
    } else {
        MEDIA_ERR_LOG("Could not able to read surfaceId argument!");
    }
    return result;
}

napi_value CameraManagerNapi::CreateVideoOutputInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreateVideoOutputInstance is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_TWO, argv, CREATE_VIDEO_OUTPUT_INSTANCE)) {
        return result;
    }

    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status != napi_ok || cameraManagerNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap failure!");
        return nullptr;
    }
    VideoProfile vidProfile;
    ParseVideoProfile(env, argv[0], &(vidProfile));
                MEDIA_INFO_LOG("ConvertJSArgsToNative ParseVideoProfile "
                    "size.width = %{public}d, size.height = %{public}d, format = %{public}d, "
                    "frameRateRange : min = %{public}d, max = %{public}d",
                    vidProfile.size_.width,
                    vidProfile.size_.height,
                    vidProfile.format_,
                    vidProfile.framerates_[0],
                    vidProfile.framerates_[1]);
    char buffer[PATH_MAX];
    size_t length = 0;
    if (napi_get_value_string_utf8(env, argv[PARAM1], buffer, PATH_MAX, &length) == napi_ok) {
        MEDIA_INFO_LOG("surfaceId buffer --1  : %{public}s", buffer);
        std::string surfaceId = std::string(buffer);
        result = VideoOutputNapi::CreateVideoOutput(env, vidProfile, surfaceId);
        MEDIA_INFO_LOG("surfaceId after convert : %{public}s", surfaceId.c_str());
    } else {
        MEDIA_ERR_LOG("Could not able to read surfaceId argument!");
    }
    return result;
}

napi_value ParseMetadataObjectTypes(napi_env env, napi_value arrayParam,
                                    std::vector<MetadataObjectType> &metadataObjectTypes)
{
    napi_value result;
    uint32_t length = 0;
    napi_value value;
    int32_t metadataType;
    napi_get_array_length(env, arrayParam, &length);
    napi_valuetype type = napi_undefined;
    for (uint32_t i = 0; i < length; i++) {
        napi_get_element(env, arrayParam, i, &value);
        napi_typeof(env, value, &type);
        if (type != napi_number) {
            return nullptr;
        }
        napi_get_value_int32(env, value, &metadataType);
        metadataObjectTypes.push_back(static_cast<MetadataObjectType>(metadataType));
    }
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value CameraManagerNapi::CreateMetadataOutputInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreateMetadataOutputInstance is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_ONE, argv, CREATE_METADATA_OUTPUT_INSTANCE)) {
        return result;
    }

    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status != napi_ok || cameraManagerNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap failure!");
        return nullptr;
    }
    std::vector<MetadataObjectType> metadataObjectTypes;
    ParseMetadataObjectTypes(env, argv[PARAM0], metadataObjectTypes);
    result = MetadataOutputNapi::CreateMetadataOutput(env);
    return result;
}

napi_value CameraManagerNapi::GetSupportedCameras(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetSupportedCameras is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ZERO;
    napi_value argv[ARGS_ZERO];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status == napi_ok && cameraManagerNapi != nullptr) {
        std::vector<sptr<CameraDevice>> cameraObjList = cameraManagerNapi->cameraManager_->GetSupportedCameras();
        result = CreateCameraJSArray(env, status, cameraObjList);
    }
    return result;
}

napi_value CameraManagerNapi::GetSupportedOutputCapability(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetSupportedOutputCapability is called");
    napi_status status;

    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    CameraDeviceNapi* cameraDeviceNapi = nullptr;
    CameraManagerNapi* cameraManagerNapi = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status != napi_ok || cameraManagerNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap( ) failure!");
        return result;
    }
    status = napi_unwrap(env, argv[PARAM0], reinterpret_cast<void **>(&cameraDeviceNapi));
    if (status != napi_ok || cameraDeviceNapi == nullptr) {
        MEDIA_ERR_LOG("Could not able to read cameraId argument!");
        return result;
    }
    sptr<CameraDevice> cameraInfo = cameraDeviceNapi->cameraDevice_;
    result = CameraOutputCapabilityNapi::CreateCameraOutputCapability(env, cameraInfo);
    return result;
}

napi_value CameraManagerNapi::IsCameraMuted(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("IsCameraMuted is called");
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameters maximum");
    bool isMuted = CameraManager::GetInstance()->IsCameraMuted();
    MEDIA_INFO_LOG("CameraManager::GetInstance()->IsCameraMuted : %{public}d", isMuted);
    napi_get_boolean(env, isMuted, &result);
    return result;
}

napi_value CameraManagerNapi::IsCameraMuteSupported(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("IsCameraMuteSupported is called");
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameters maximum");

    bool isMuteSupported = CameraManager::GetInstance()->IsCameraMuteSupported();
    MEDIA_INFO_LOG("CameraManager::GetInstance()->IsCameraMuteSupported : %{public}d", isMuteSupported);
    napi_get_boolean(env, isMuteSupported, &result);
    return result;
}

napi_value CameraManagerNapi::MuteCamera(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("MuteCamera is called");
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_TWO, "requires 1 parameters maximum");
    bool isSupported;
    napi_get_value_bool(env, argv[PARAM0], &isSupported);
    CameraManager::GetInstance()->MuteCamera(isSupported);
    MEDIA_INFO_LOG("MuteCamera");
    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraManagerNapi::CreateCameraInputInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreateCameraInputInstance is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_TWO, argv, CREATE_CAMERA_INPUT_INSTANCE)) {
        return result;
    }

    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status != napi_ok || cameraManagerNapi == nullptr) {
        MEDIA_ERR_LOG("napi_unwrap( ) failure!");
        return result;
    }
    sptr<CameraDevice> cameraInfo = nullptr;
    if (argc == ARGS_ONE) {
        CameraDeviceNapi* cameraDeviceNapi = nullptr;
        status = napi_unwrap(env, argv[PARAM0], reinterpret_cast<void **>(&cameraDeviceNapi));
        if (status != napi_ok || cameraDeviceNapi == nullptr) {
            MEDIA_ERR_LOG("napi_unwrap( ) failure!");
            return result;
        }
        cameraInfo = cameraDeviceNapi->cameraDevice_;
    } else if (argc == ARGS_TWO) {
        int32_t numValue;

        napi_get_value_int32(env, argv[PARAM0], &numValue);
        CameraPosition cameraPosition = static_cast<CameraPosition>(numValue);

        napi_get_value_int32(env, argv[PARAM1], &numValue);
        CameraType cameraType = static_cast<CameraType>(numValue);

        std::vector<sptr<CameraDevice>> cameraObjList = cameraManagerNapi->cameraManager_->GetSupportedCameras();
        MEDIA_DEBUG_LOG("cameraInfo is null, cameraManager_->GetSupportedCameras() : %{public}zu",
                        cameraObjList.size());
        for (size_t i = 0; i < cameraObjList.size(); i++) {
            sptr<CameraDevice> cameraDevice = cameraObjList[i];
            if (cameraDevice == nullptr) {
                continue;
            }
            if (cameraDevice->GetPosition() == cameraPosition &&
                cameraDevice->GetCameraType() == cameraType) {
                cameraInfo = cameraDevice;
                break;
            }
        }
    }
    if (cameraInfo != nullptr) {
        sptr<CameraInput> cameraInput = nullptr;
        int retCode = CameraManager::GetInstance()->CreateCameraInput(cameraInfo, &cameraInput);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            return nullptr;
        }
        result = CameraInputNapi::CreateCameraInput(env, cameraInput);
    }
    return result;
}

napi_value CameraManagerNapi::On(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("On is called");
    napi_value undefinedResult = nullptr;
    size_t argCount = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr};
    napi_value thisVar = nullptr;
    size_t res = 0;
    char buffer[SIZE];
    CameraManagerNapi* obj = nullptr;
    napi_status status;

    napi_get_undefined(env, &undefinedResult);

    CAMERA_NAPI_GET_JS_ARGS(env, info, argCount, argv, thisVar);
    NAPI_ASSERT(env, argCount == ARGS_TWO, "requires 2 parameters");

    if (thisVar == nullptr || argv[PARAM0] == nullptr || argv[PARAM1] == nullptr) {
        MEDIA_ERR_LOG("Failed to retrieve details about the callback");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr) {
        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string
            || napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function) {
            return undefinedResult;
        }

        napi_get_value_string_utf8(env, argv[PARAM0], buffer, SIZE, &res);
        std::string eventType = std::string(buffer);

        napi_ref callbackRef;
        const int32_t refCount = 1;
        napi_create_reference(env, argv[PARAM1], refCount, &callbackRef);

        if (!eventType.empty() && (eventType.compare("cameraStatus")==0)) {
            shared_ptr<CameraManagerCallbackNapi> callback =
                make_shared<CameraManagerCallbackNapi>(env, callbackRef);
            obj->cameraManager_->SetCallback(callback);
        } else if (!eventType.empty() && (eventType.compare("cameraMute")==0)) {
            shared_ptr<CameraMuteListenerNapi> listener =
                make_shared<CameraMuteListenerNapi>(env, callbackRef);
            obj->cameraManager_->RegisterCameraMuteListener(listener);
        } else {
            MEDIA_ERR_LOG("Incorrect callback event type provided for camera manager!");
            if (callbackRef != nullptr) {
                napi_delete_reference(env, callbackRef);
            }
        }
    }

    return undefinedResult;
}
} // namespace CameraStandard
} // namespace OHOS
