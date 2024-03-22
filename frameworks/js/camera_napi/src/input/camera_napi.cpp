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

namespace OHOS {
namespace CameraStandard {
using namespace std;

thread_local napi_ref CameraNapi::sConstructor_ = nullptr;

thread_local napi_ref CameraNapi::exposureModeRef_ = nullptr;
thread_local napi_ref CameraNapi::focusModeRef_ = nullptr;
thread_local napi_ref CameraNapi::flashModeRef_ = nullptr;
thread_local napi_ref CameraNapi::cameraFormatRef_ = nullptr;
thread_local napi_ref CameraNapi::cameraStatusRef_ = nullptr;
thread_local napi_ref CameraNapi::connectionTypeRef_ = nullptr;
thread_local napi_ref CameraNapi::cameraPositionRef_ = nullptr;
thread_local napi_ref CameraNapi::cameraTypeRef_ = nullptr;
thread_local napi_ref CameraNapi::imageRotationRef_ = nullptr;
thread_local napi_ref CameraNapi::errorCameraRef_ = nullptr;
thread_local napi_ref CameraNapi::errorCameraInputRef_ = nullptr;
thread_local napi_ref CameraNapi::errorCaptureSessionRef_ = nullptr;
thread_local napi_ref CameraNapi::errorPreviewOutputRef_ = nullptr;
thread_local napi_ref CameraNapi::errorPhotoOutputRef_ = nullptr;
thread_local napi_ref CameraNapi::errorVideoOutputRef_ = nullptr;
thread_local napi_ref CameraNapi::errorMetadataOutputRef_ = nullptr;
thread_local napi_ref CameraNapi::metadataObjectTypeRef_ = nullptr;
thread_local napi_ref CameraNapi::exposureStateRef_ = nullptr;
thread_local napi_ref CameraNapi::focusStateRef_ = nullptr;
thread_local napi_ref CameraNapi::qualityLevelRef_ = nullptr;
thread_local napi_ref CameraNapi::videoStabilizationModeRef_ = nullptr;
thread_local napi_ref CameraNapi::hostNameTypeRef_ = nullptr;
thread_local napi_ref CameraNapi::sceneModeRef_ = nullptr;
thread_local napi_ref CameraNapi::filterTypeRef_ = nullptr;
thread_local napi_ref CameraNapi::beautyTypeRef_ = nullptr;
thread_local napi_ref CameraNapi::portraitEffectRef_ = nullptr;
thread_local napi_ref CameraNapi::torchModeRef_ = nullptr;
thread_local napi_ref CameraNapi::deferredDeliveryImageTypeRef_ = nullptr;
thread_local napi_ref CameraNapi::SmoothZoomModeRef_ = nullptr;
thread_local napi_ref CameraNapi::colorEffectTypeRef_ = nullptr;
thread_local napi_ref CameraNapi::restoreParamTypeRef_ = nullptr;

CameraNapi::CameraNapi() : env_(nullptr), wrapper_(nullptr)
{
}

CameraNapi::~CameraNapi()
{
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

// Constructor callback
napi_value CameraNapi::CameraNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CameraNapi> obj = std::make_unique<CameraNapi>();
        if (obj != nullptr) {
            obj->env_ = env;
            status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                               CameraNapi::CameraNapiDestructor, nullptr, nullptr);
            if (status == napi_ok) {
                obj.release();
                return thisVar;
            } else {
                MEDIA_ERR_LOG("CameraNapiConstructor Failure wrapping js to native napi");
            }
        }
    }
    MEDIA_ERR_LOG("CameraNapiConstructor call Failed!");
    return result;
}

void CameraNapi::CameraNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CameraNapiDestructor is called");
    CameraNapi* camera = reinterpret_cast<CameraNapi*>(nativeObject);
    if (camera != nullptr) {
        delete camera;
    }
}

napi_value CameraNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;
    napi_property_descriptor camera_properties[] = {
        DECLARE_NAPI_FUNCTION("getCameraManagerTest", CreateCameraManagerInstance)
    };

    napi_property_descriptor camera_static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("getCameraManager", CreateCameraManagerInstance),
        DECLARE_NAPI_STATIC_FUNCTION("getModeManager", CreateModeManagerInstance),
        DECLARE_NAPI_PROPERTY("FlashMode",
            CreateObjectWithMap(env, "FlashMode", mapFlashMode, flashModeRef_)),
        DECLARE_NAPI_PROPERTY("ExposureMode",
            CreateObjectWithMap(env, "ExposureMode", mapExposureMode, exposureModeRef_)),
        DECLARE_NAPI_PROPERTY("ExposureState",
            CreateObjectWithMap(env, "ExposureState", mapExposureState, exposureStateRef_)),
        DECLARE_NAPI_PROPERTY("FocusMode",
            CreateObjectWithMap(env, "FocusMode", mapFocusMode, focusModeRef_)),
        DECLARE_NAPI_PROPERTY("FocusState",
            CreateObjectWithMap(env, "FocusState", mapFocusState, focusStateRef_)),
        DECLARE_NAPI_PROPERTY("CameraPosition",
            CreateObjectWithMap(env, "CameraPosition", mapCameraPosition, cameraPositionRef_)),
        DECLARE_NAPI_PROPERTY("CameraType",
            CreateObjectWithMap(env, "CameraType", mapCameraType, cameraTypeRef_)),
        DECLARE_NAPI_PROPERTY("ConnectionType",
            CreateObjectWithMap(env, "ConnectionType", mapConnectionType, connectionTypeRef_)),
        DECLARE_NAPI_PROPERTY("CameraFormat",
            CreateObjectWithMap(env, "CameraFormat", mapCameraFormat, cameraFormatRef_)),
        DECLARE_NAPI_PROPERTY("CameraStatus",
            CreateObjectWithMap(env, "CameraStatus", mapCameraStatus, cameraStatusRef_)),
        DECLARE_NAPI_PROPERTY("ImageRotation",
            CreateObjectWithMap(env, "ImageRotation", mapImageRotation, imageRotationRef_)),
        DECLARE_NAPI_PROPERTY("QualityLevel",
            CreateObjectWithMap(env, "QualityLevel", mapQualityLevel, qualityLevelRef_)),
        DECLARE_NAPI_PROPERTY("VideoStabilizationMode",
            CreateObjectWithMap(env, "VideoStabilizationMode",
                                mapVideoStabilizationMode, videoStabilizationModeRef_)),
        DECLARE_NAPI_PROPERTY("MetadataObjectType",
            CreateObjectWithMap(env, "MetadataObjectType", mapMetadataObjectType, metadataObjectTypeRef_)),
        DECLARE_NAPI_PROPERTY("HostNameType",
            CreateObjectWithMap(env, "HostNameType", mapHostNameType, hostNameTypeRef_)),
        DECLARE_NAPI_PROPERTY("CameraMode",
            CreateObjectWithMap(env, "SceneMode", mapSceneMode, sceneModeRef_)),
        DECLARE_NAPI_PROPERTY("SceneMode",
            CreateObjectWithMap(env, "SceneMode", mapSceneMode, sceneModeRef_)),
        DECLARE_NAPI_PROPERTY("FilterType",
            CreateObjectWithMap(env, "FilterType", mapFilterType, filterTypeRef_)),
        DECLARE_NAPI_PROPERTY("BeautyType",
            CreateObjectWithMap(env, "BeautyType", mapBeautyType, beautyTypeRef_)),
        DECLARE_NAPI_PROPERTY("PortraitEffect",
            CreateObjectWithMap(env, "PortraitEffect", mapPortraitEffect, portraitEffectRef_)),
        DECLARE_NAPI_PROPERTY("TorchMode",
            CreateObjectWithMap(env, "TorchMode", mapTorchMode, torchModeRef_)),
        DECLARE_NAPI_PROPERTY("CameraErrorCode",
            CreateObjectWithMap(env, "CameraErrorCode", mapCameraErrorCode, errorCameraRef_)),
        DECLARE_NAPI_PROPERTY("CameraInputErrorCode",
            CreateObjectWithMap(env, "CameraInputErrorCode", mapCameraInputErrorCode, errorCameraInputRef_)),
        DECLARE_NAPI_PROPERTY("CaptureSessionErrorCode",
            CreateObjectWithMap(env, "CaptureSessionErrorCode", mapCaptureSessionErrorCode, errorCaptureSessionRef_)),
        DECLARE_NAPI_PROPERTY("PreviewOutputErrorCode",
            CreateObjectWithMap(env, "PreviewOutputErrorCode", mapPreviewOutputErrorCode, errorPreviewOutputRef_)),
        DECLARE_NAPI_PROPERTY("PhotoOutputErrorCode",
            CreateObjectWithMap(env, "PhotoOutputErrorCode", mapPhotoOutputErrorCode, errorPhotoOutputRef_)),
        DECLARE_NAPI_PROPERTY("VideoOutputErrorCode",
            CreateObjectWithMap(env, "VideoOutputErrorCode", mapVideoOutputErrorCode, errorVideoOutputRef_)),
        DECLARE_NAPI_PROPERTY("MetadataOutputErrorCode",
            CreateObjectWithMap(env, "MetadataOutputErrorCode", mapMetadataOutputErrorCode, errorMetadataOutputRef_)),
        DECLARE_NAPI_PROPERTY("DeferredDeliveryImageType",
            CreateObjectWithMap(env, "DeferredDeliveryImageType",
                                mapDeferredDeliveryImageType, deferredDeliveryImageTypeRef_)),
        DECLARE_NAPI_PROPERTY("SmoothZoomMode",
            CreateObjectWithMap(env, "SmoothZoomMode", mapSmoothZoomMode, SmoothZoomModeRef_)),
        DECLARE_NAPI_PROPERTY("ColorEffectType",
            CreateObjectWithMap(env, "ColorEffectType", mapColorEffectType, colorEffectTypeRef_)),
        DECLARE_NAPI_PROPERTY("RestoreParamType",
            CreateObjectWithMap(env, "RestoreParamType", mapRestoreParamType, restoreParamTypeRef_)),
    };

    status = napi_define_class(env, CAMERA_LIB_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH, CameraNapiConstructor,
                               nullptr, sizeof(camera_properties) / sizeof(camera_properties[PARAM0]),
                               camera_properties, &ctorObj);
    if (status == napi_ok) {
        if (napi_create_reference(env, ctorObj, refCount, &sConstructor_) == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_LIB_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok && napi_define_properties(env, exports,
                sizeof(camera_static_prop) / sizeof(camera_static_prop[PARAM0]), camera_static_prop) == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_status CameraNapi::AddNamedProperty(napi_env env, napi_value object,
                                         const std::string name, int32_t enumValue)
{
    napi_status status;
    napi_value enumNapiValue;

    status = napi_create_int32(env, enumValue, &enumNapiValue);
    if (status == napi_ok) {
        status = napi_set_named_property(env, object, name.c_str(), enumNapiValue);
    }

    return status;
}

napi_value CameraNapi::CreateCameraManagerInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreateCameraManagerInstance is called");
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    result = CameraManagerNapi::CreateCameraManager(env);
    return result;
}

napi_value CameraNapi::CreateModeManagerInstance(napi_env env, napi_callback_info info)
{
    MEDIA_INFO_LOG("CreateModeManagerInstance is called");
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    result = ModeManagerNapi::CreateModeManager(env);
    return result;
}

napi_value CameraNapi::CreateObjectWithMap(napi_env env,
                                           const std::string objectName,
                                           const std::unordered_map<std::string, int32_t>& inputMap,
                                           napi_ref& outputRef)
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
        status = napi_create_reference(env, result, 1, &outputRef);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("Create %{public}s call Failed!", objectName.c_str());
    napi_get_undefined(env, &result);

    return result;
}
} // namespace CameraStandard
} // namespace OHOS
