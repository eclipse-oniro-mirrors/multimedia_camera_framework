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

#include "input/camera_manager_napi.h"
#include "input/camera_napi.h"
#include "input/camera_pre_launch_config_napi.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;
namespace {
    constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "CameraManager"};
}
thread_local napi_ref CameraManagerNapi::sConstructor_ = nullptr;
thread_local uint32_t CameraManagerNapi::cameraManagerTaskId = CAMERA_MANAGER_TASKID;

CameraManagerNapi::CameraManagerNapi() : env_(nullptr), wrapper_(nullptr)
{
    CAMERA_SYNC_TRACE;
}

CameraManagerNapi::~CameraManagerNapi()
{
    MEDIA_DEBUG_LOG("~CameraManagerNapi is called");
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
    MEDIA_DEBUG_LOG("CameraManagerNapiConstructor is called");
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
    MEDIA_ERR_LOG("CameraManagerNapiConstructor call Failed!");
    return result;
}

void CameraManagerNapi::CameraManagerNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CameraManagerNapiDestructor is called");
    CameraManagerNapi* camera = reinterpret_cast<CameraManagerNapi*>(nativeObject);
    if (camera != nullptr) {
        delete camera;
    }
}

napi_value CameraManagerNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
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
        DECLARE_NAPI_FUNCTION("prelaunch", PrelaunchCamera),
        DECLARE_NAPI_FUNCTION("isPrelaunchSupported", IsPrelaunchSupported),
        DECLARE_NAPI_FUNCTION("setPrelaunchConfig", SetPrelaunchConfig),
        DECLARE_NAPI_FUNCTION("createCameraInput", CreateCameraInputInstance),
        DECLARE_NAPI_FUNCTION("createCaptureSession", CreateCameraSessionInstance),
        DECLARE_NAPI_FUNCTION("createPreviewOutput", CreatePreviewOutputInstance),
        DECLARE_NAPI_FUNCTION("createDeferredPreviewOutput", CreateDeferredPreviewOutputInstance),
        DECLARE_NAPI_FUNCTION("createPhotoOutput", CreatePhotoOutputInstance),
        DECLARE_NAPI_FUNCTION("createVideoOutput", CreateVideoOutputInstance),
        DECLARE_NAPI_FUNCTION("createMetadataOutput", CreateMetadataOutputInstance),
        DECLARE_NAPI_FUNCTION("isTorchSupported", IsTorchSupported),
        DECLARE_NAPI_FUNCTION("isTorchModeSupported", IsTorchModeSupported),
        DECLARE_NAPI_FUNCTION("getTorchMode", GetTorchMode),
        DECLARE_NAPI_FUNCTION("setTorchMode", SetTorchMode),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("once", Once),
        DECLARE_NAPI_FUNCTION("off", Off)
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
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value CameraManagerNapi::CreateCameraManager(napi_env env)
{
    MEDIA_INFO_LOG("CreateCameraManager is called");
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
    MEDIA_ERR_LOG("CreateCameraManager call Failed!");
    return result;
}

static napi_value CreateCameraJSArray(napi_env env, napi_status status,
    std::vector<sptr<CameraDevice>> cameraObjList)
{
    MEDIA_DEBUG_LOG("CreateCameraJSArray is called");
    napi_value cameraArray = nullptr;
    napi_value camera = nullptr;

    if (cameraObjList.empty()) {
        MEDIA_ERR_LOG("cameraObjList is empty");
    }

    status = napi_create_array(env, &cameraArray);
    if (status == napi_ok) {
        for (size_t i = 0; i < cameraObjList.size(); i++) {
            camera = CameraDeviceNapi::CreateCameraObj(env, cameraObjList[i]);
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
    MEDIA_INFO_LOG("CameraManagerCommonCompleteCallback is called");
    auto context = static_cast<CameraManagerContext*>(data);

    CAMERA_NAPI_CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    MEDIA_INFO_LOG("modeForAsync = %{public}d", context->modeForAsync);
    napi_get_undefined(env, &jsContext->error);
    if (context->modeForAsync == CREATE_DEFERRED_PREVIEW_OUTPUT_ASYNC_CALLBACK) {
        MEDIA_INFO_LOG("createDeferredPreviewOutput");
        jsContext->data = PreviewOutputNapi::CreateDeferredPreviewOutput(env, context->profile);
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
    MEDIA_DEBUG_LOG("ParseSize is called");
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
    MEDIA_DEBUG_LOG("ParseProfile is called");
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
    MEDIA_DEBUG_LOG("ParseVideoProfile is called");
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

napi_value CameraManagerNapi::CreatePreviewOutputInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreatePreviewOutputInstance is called");
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
    MEDIA_INFO_LOG("ParseProfile "
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
    if (!CameraNapiUtils::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi CreateDeferredPreviewOutputInstance is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    if (!CameraNapiUtils::CheckInvalidArgument(env, argc, ARGS_ONE, argv, CREATE_DEFERRED_PREVIEW_OUTPUT)) {
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
    MEDIA_INFO_LOG("ParseProfile "
                   "size.width = %{public}d, size.height = %{public}d, format = %{public}d",
                   profile.size_.width, profile.size_.height, profile.format_);
    result = PreviewOutputNapi::CreateDeferredPreviewOutput(env, profile);
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
                MEDIA_INFO_LOG("ParseVideoProfile "
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
    MEDIA_DEBUG_LOG("ParseMetadataObjectTypes is called");
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
    } else {
        MEDIA_ERR_LOG("GetSupportedCameras call Failed!");
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
    status = napi_unwrap(env, argv[PARAM0], reinterpret_cast<void**>(&cameraDeviceNapi));
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
    MEDIA_DEBUG_LOG("IsCameraMuted : %{public}d", isMuted);
    napi_get_boolean(env, isMuted, &result);
    return result;
}

napi_value CameraManagerNapi::IsCameraMuteSupported(napi_env env, napi_callback_info info)
{
    if (!CameraNapiUtils::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsCameraMuteSupported is called!");
        return nullptr;
    }
    MEDIA_INFO_LOG("IsCameraMuteSupported is called");
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameters maximum");

    bool isMuteSupported = CameraManager::GetInstance()->IsCameraMuteSupported();
    MEDIA_DEBUG_LOG("isMuteSupported: %{public}d", isMuteSupported);
    napi_get_boolean(env, isMuteSupported, &result);
    return result;
}

napi_value CameraManagerNapi::MuteCamera(napi_env env, napi_callback_info info)
{
    if (!CameraNapiUtils::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi MuteCamera is called!");
        return nullptr;
    }
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
        status = napi_unwrap(env, argv[PARAM0], reinterpret_cast<void**>(&cameraDeviceNapi));
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
        MEDIA_DEBUG_LOG("cameraInfo is null, the cameraObjList size is %{public}zu",
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
    } else {
        MEDIA_ERR_LOG("cameraInfo is null");
    }
    return result;
}

napi_value CameraManagerNapi::RegisterCallback(napi_env env, napi_value jsThis,
    const string &eventType, napi_value callback, bool isOnce)
{
    const int32_t refCount = 1;
    napi_value undefinedResult = nullptr;
    napi_status status;
    napi_get_undefined(env, &undefinedResult);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    napi_ref callbackRef;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&cameraManagerNapi));
    NAPI_ASSERT(env, status == napi_ok && cameraManagerNapi != nullptr,
        "Failed to retrieve cameraManager napi instance.");
    NAPI_ASSERT(env, cameraManagerNapi->cameraManager_ != nullptr, "cameraManager instance is null.");
    napi_create_reference(env, callback, refCount, &callbackRef);
    if ((eventType.compare("cameraStatus")==0)) {
        if (cameraManagerNapi->cameraManagerCallback_ == nullptr) {
            shared_ptr<CameraManagerCallbackNapi> cameraManagerCallback =
                    make_shared<CameraManagerCallbackNapi>(env);
            cameraManagerNapi->cameraManagerCallback_ = cameraManagerCallback;
            cameraManagerNapi->cameraManager_->SetCallback(cameraManagerCallback);
        }
        cameraManagerNapi->cameraManagerCallback_->SaveCallbackReference(eventType, callback, isOnce);
    } else if ((eventType.compare("cameraMute")==0)) {
        if (!CameraNapiUtils::CheckSystemApp(env)) {
            MEDIA_ERR_LOG("SystemApi On cameraMute is called!");
            return undefinedResult;
        }
        if (cameraManagerNapi->cameraMuteListener_ == nullptr) {
            shared_ptr<CameraMuteListenerNapi> cameraMuteListener =
                    make_shared<CameraMuteListenerNapi>(env);
            cameraManagerNapi->cameraMuteListener_ = cameraMuteListener;
            cameraManagerNapi->cameraManager_->RegisterCameraMuteListener(cameraMuteListener);
        }
        cameraManagerNapi->cameraMuteListener_->SaveCallbackReference(eventType, callback, isOnce);
    } else if ((eventType.compare("torchStatusChange") == 0)) {
        if (cameraManagerNapi->torchListener_ == nullptr) {
            shared_ptr<TorchListenerNapi> torchListener =
                    make_shared<TorchListenerNapi>(env);
            cameraManagerNapi->torchListener_ = torchListener;
            cameraManagerNapi->cameraManager_->RegisterTorchListener(torchListener);
        }
        cameraManagerNapi->torchListener_->SaveCallbackReference(eventType, callback, isOnce);
    } else {
        MEDIA_ERR_LOG("Incorrect callback event type provided for camera manager!");
        if (callbackRef != nullptr) {
            napi_delete_reference(env, callbackRef);
        }
    }
    return undefinedResult;
}

napi_value CameraManagerNapi::UnregisterCallback(napi_env env, napi_value jsThis,
    const std::string& eventType, napi_value callback)
{
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);
    CameraManagerNapi *cameraManagerNapi = nullptr;
    napi_status status = napi_unwrap(env, jsThis, reinterpret_cast<void**>(&cameraManagerNapi));
    NAPI_ASSERT(env, status == napi_ok && cameraManagerNapi != nullptr, "Failed to retrieve audio mgr napi instance.");
    NAPI_ASSERT(env, cameraManagerNapi->cameraManager_ != nullptr, "audio system mgr instance is null.");

    if (eventType.compare("cameraStatus") == 0) {
        if (cameraManagerNapi->cameraManagerCallback_ == nullptr) {
            MEDIA_ERR_LOG("cameraManagerCallback is null");
        } else {
            cameraManagerNapi->cameraManagerCallback_->RemoveCallbackRef(env, callback);
        }
    } else if (eventType.compare("cameraMute") == 0) {
        if (!CameraNapiUtils::CheckSystemApp(env)) {
            MEDIA_ERR_LOG("SystemApi On cameraMute is called!");
            return undefinedResult;
        }
        if (cameraManagerNapi->cameraMuteListener_ == nullptr) {
            MEDIA_ERR_LOG("cameraMuteListener is null");
        } else {
            cameraManagerNapi->cameraMuteListener_->RemoveCallbackRef(env, callback);
        }
    } else if (eventType.compare("torchStatusChange") == 0) {
        if (cameraManagerNapi->torchListener_ == nullptr) {
            MEDIA_ERR_LOG("torchListener_ is null");
        } else {
            cameraManagerNapi->torchListener_->RemoveCallbackRef(env, callback);
        }
    } else {
        MEDIA_ERR_LOG("off no such supported!");
    }
    return undefinedResult;
}

napi_value CameraManagerNapi::On(napi_env env, napi_callback_info info)
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

napi_value CameraManagerNapi::Once(napi_env env, napi_callback_info info)
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

napi_value CameraManagerNapi::Off(napi_env env, napi_callback_info info)
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

napi_value CameraManagerNapi::IsPrelaunchSupported(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("IsPrelaunchSupported is called");
    if (!CameraNapiUtils::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi IsPrelaunchSupported is called!");
        return nullptr;
    }
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
    status = napi_unwrap(env, argv[PARAM0], reinterpret_cast<void**>(&cameraDeviceNapi));
    if (status == napi_ok && cameraDeviceNapi != nullptr) {
        sptr<CameraDevice> cameraInfo = cameraDeviceNapi->cameraDevice_;
        bool isPrelaunchSupported = CameraManager::GetInstance()->IsPrelaunchSupported(cameraInfo);
        MEDIA_DEBUG_LOG("isPrelaunchSupported: %{public}d", isPrelaunchSupported);
        napi_get_boolean(env, isPrelaunchSupported, &result);
    } else {
        MEDIA_ERR_LOG("Could not able to read cameraDevice argument!");
        if (!CameraNapiUtils::CheckError(env, INVALID_ARGUMENT)) {
            MEDIA_DEBUG_LOG("Could not able to read cameraDevice argument throw error");
        }
    }
    return result;
}

napi_value CameraManagerNapi::PrelaunchCamera(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("PrelaunchCamera is called");
    if (!CameraNapiUtils::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi PrelaunchCamera is called!");
        return nullptr;
    }
    napi_value result = nullptr;
    int32_t retCode = CameraManager::GetInstance()->PrelaunchCamera();
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        return result;
    }
    MEDIA_INFO_LOG("PrelaunchCamera");
    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraManagerNapi::SetPrelaunchConfig(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("SetPrelaunchConfig is called");
    if (!CameraNapiUtils::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi SetPrelaunchConfig is called!");
        return nullptr;
    }
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc < ARGS_TWO, "requires 1 parameters maximum");
    napi_value res = nullptr;
    PrelaunchConfig prelaunchConfig;
    CameraDeviceNapi* cameraDeviceNapi = nullptr;
    if (napi_get_named_property(env, argv[PARAM0], "cameraDevice", &res) == napi_ok) {
        status = napi_unwrap(env, res, reinterpret_cast<void**>(&cameraDeviceNapi));
        prelaunchConfig.cameraDevice_ = cameraDeviceNapi->cameraDevice_;
        if (status != napi_ok || prelaunchConfig.cameraDevice_ == nullptr) {
            MEDIA_ERR_LOG("napi_unwrap( ) failure!");
            return result;
        }
    } else {
        if (!CameraNapiUtils::CheckError(env, INVALID_ARGUMENT)) {
            return result;
        }
    }
    std::string cameraId = prelaunchConfig.GetCameraDevice()->GetID();
    MEDIA_INFO_LOG("SetPrelaunchConfig cameraId = %{public}s", cameraId.c_str());
    int32_t retCode = CameraManager::GetInstance()->SetPrelaunchConfig(cameraId);
    if (!CameraNapiUtils::CheckError(env, retCode)) {
        return result;
    }
    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraManagerNapi::IsTorchSupported(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("IsTorchSupported is called");
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
        bool isTorchSupported = CameraManager::GetInstance()->IsTorchSupported();
        MEDIA_DEBUG_LOG("IsTorchSupported : %{public}d", isTorchSupported);
        napi_get_boolean(env, isTorchSupported, &result);
    } else {
        MEDIA_ERR_LOG("IsTorchSupported call Failed!");
    }
    return result;
}

napi_value CameraManagerNapi::IsTorchModeSupported(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("IsTorchModeSupported is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status == napi_ok && cameraManagerNapi != nullptr) {
        int32_t mode;
        napi_get_value_int32(env, argv[PARAM0], &mode);
        MEDIA_INFO_LOG("CameraManagerNapi::IsTorchModeSupported mode = %{public}d", mode);
        TorchMode torchMode = (TorchMode)mode;
        bool isTorchModeSupported = CameraManager::GetInstance()->IsTorchModeSupported(torchMode);
        MEDIA_DEBUG_LOG("IsTorchModeSupported : %{public}d", isTorchModeSupported);
        napi_get_boolean(env, isTorchModeSupported, &result);
    } else {
        MEDIA_ERR_LOG("GetTorchMode call Failed!");
    }
    return result;
}

napi_value CameraManagerNapi::GetTorchMode(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("GetTorchMode is called");
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
        TorchMode torchMode = CameraManager::GetInstance()->GetTorchMode();
        MEDIA_DEBUG_LOG("GetTorchMode : %{public}d", torchMode);
        napi_create_int32(env, torchMode, &result);
    } else {
        MEDIA_ERR_LOG("GetTorchMode call Failed!");
    }
    return result;
}

napi_value CameraManagerNapi::SetTorchMode(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("SetTorchMode is called");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    CameraManagerNapi* cameraManagerNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&cameraManagerNapi));
    if (status == napi_ok && cameraManagerNapi != nullptr) {
        int32_t mode;
        napi_get_value_int32(env, argv[PARAM0], &mode);
        MEDIA_INFO_LOG("CameraManagerNapi::SetTorchMode mode = %{public}d", mode);
        TorchMode torchMode = (TorchMode)mode;
        int32_t retCode = CameraManager::GetInstance()->SetTorchMode(torchMode);
        if (!CameraNapiUtils::CheckError(env, retCode)) {
            MEDIA_DEBUG_LOG("SetTorchMode fail throw error");
        }
    } else {
        MEDIA_ERR_LOG("GetTorchMode call Failed!");
    }
    return result;
}
} // namespace CameraStandard
} // namespace OHOS
