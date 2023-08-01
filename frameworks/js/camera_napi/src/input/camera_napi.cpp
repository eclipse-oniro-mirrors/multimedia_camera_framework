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

thread_local napi_ref CameraNapi::errorCameraInputRef_ = nullptr;
thread_local napi_ref CameraNapi::errorCaptureSessionRef_ = nullptr;
thread_local napi_ref CameraNapi::errorPreviewOutputRef_ = nullptr;
thread_local napi_ref CameraNapi::errorPhotoOutputRef_ = nullptr;
thread_local napi_ref CameraNapi::errorVideoOutputRef_ = nullptr;
thread_local napi_ref CameraNapi::errorMetaOutputRef_ = nullptr;
thread_local napi_ref CameraNapi::metadataObjectTypeRef_ = nullptr;
thread_local napi_ref CameraNapi::exposureStateRef_ = nullptr;
thread_local napi_ref CameraNapi::focusStateRef_ = nullptr;
thread_local napi_ref CameraNapi::qualityLevelRef_ = nullptr;
thread_local napi_ref CameraNapi::videoStabilizationModeRef_ = nullptr;

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

    return result;
}

void CameraNapi::CameraNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    CameraNapi* camera = reinterpret_cast<CameraNapi*>(nativeObject);
    if (camera != nullptr) {
        delete camera;
    }
}

napi_value CameraNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_INFO_LOG("CameraNapi::Init()");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;
    napi_property_descriptor camera_properties[] = {
        DECLARE_NAPI_FUNCTION("getCameraManagerTest", CreateCameraManagerInstance)
    };

    napi_property_descriptor camera_static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("getCameraManager", CreateCameraManagerInstance),
        DECLARE_NAPI_PROPERTY("FlashMode", CreateFlashModeObject(env)),
        DECLARE_NAPI_PROPERTY("ExposureMode", CreateExposureModeObject(env)),
        DECLARE_NAPI_PROPERTY("ExposureState", CreateExposureStateEnum(env)),
        DECLARE_NAPI_PROPERTY("FocusMode", CreateFocusModeObject(env)),
        DECLARE_NAPI_PROPERTY("FocusState", CreateFocusStateEnum(env)),
        DECLARE_NAPI_PROPERTY("CameraPosition", CreateCameraPositionEnum(env)),
        DECLARE_NAPI_PROPERTY("CameraType", CreateCameraTypeEnum(env)),
        DECLARE_NAPI_PROPERTY("ConnectionType", CreateConnectionTypeEnum(env)),
        DECLARE_NAPI_PROPERTY("CameraFormat", CreateCameraFormatObject(env)),
        DECLARE_NAPI_PROPERTY("CameraStatus", CreateCameraStatusObject(env)),
        DECLARE_NAPI_PROPERTY("ImageRotation", CreateImageRotationEnum(env)),
        DECLARE_NAPI_PROPERTY("QualityLevel", CreateQualityLevelEnum(env)),
        DECLARE_NAPI_PROPERTY("CameraErrorCode", CreateCameraErrorCode(env)),
        DECLARE_NAPI_PROPERTY("CameraInputErrorCode", CreateCameraInputErrorCode(env)),
        DECLARE_NAPI_PROPERTY("CaptureSessionErrorCode", CreateCaptureSessionErrorCode(env)),
        DECLARE_NAPI_PROPERTY("PreviewOutputErrorCode", CreatePreviewOutputErrorCode(env)),
        DECLARE_NAPI_PROPERTY("PhotoOutputErrorCode", CreatePhotoOutputErrorCode(env)),
        DECLARE_NAPI_PROPERTY("VideoOutputErrorCode", CreateVideoOutputErrorCode(env)),
        DECLARE_NAPI_PROPERTY("MetadataOutputErrorCode", CreateMetaOutputErrorCode(env)),
        DECLARE_NAPI_PROPERTY("VideoStabilizationMode", CreateVideoStabilizationModeObject(env)),
        DECLARE_NAPI_PROPERTY("MetadataObjectType", CreateMetadataObjectType(env)),
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
    MEDIA_INFO_LOG("CreateCameraManagerInstance called");
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    result = CameraManagerNapi::CreateCameraManager(env);
    return result;
}

napi_value CameraNapi::CreateFlashModeObject(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName;
        for (unsigned int i = 0; i < vecFlashMode.size(); i++) {
            propName = vecFlashMode[i];
            status = AddNamedProperty(env, result, propName, i);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add named prop for FlashMode!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &flashModeRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreateFlashModeObject is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraNapi::CreateExposureModeObject(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName;
        for (unsigned int i = 0; i < vecExposureMode.size(); i++) {
            propName = vecExposureMode[i];
            status = AddNamedProperty(env, result, propName, i);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add named prop for ExposureMode!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &exposureModeRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreateExposureModeObject is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraNapi::CreateExposureStateEnum(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName;
        for (auto itr = mapExposureState.begin(); itr != mapExposureState.end(); ++itr) {
            propName = itr->first;
            status = AddNamedProperty(env, result, propName, itr->second);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add FocusState prop!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &exposureStateRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreateExposureStateEnum is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraNapi::CreateFocusModeObject(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName;
        for (unsigned int i = 0; i < vecFocusMode.size(); i++) {
            propName = vecFocusMode[i];
            status = AddNamedProperty(env, result, propName, i);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add named prop for FocusMode!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &focusModeRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreateFocusModeObject is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraNapi::CreateFocusStateEnum(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName;
        for (auto itr = mapFocusState.begin(); itr != mapFocusState.end(); ++itr) {
            propName = itr->first;
            status = AddNamedProperty(env, result, propName, itr->second);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add FocusState prop!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &focusStateRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreateFocusStateEnum is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraNapi::CreateCameraPositionEnum(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName;
        for (unsigned int i = 0; i < vecCameraPositionMode.size(); i++) {
            propName = vecCameraPositionMode[i];
            status = AddNamedProperty(env, result, propName, i);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add named prop for CameraPosition!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &cameraPositionRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreateCameraPositionEnum is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraNapi::CreateCameraTypeEnum(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName;
        for (unsigned int i = 0; i < vecCameraTypeMode.size(); i++) {
            propName = vecCameraTypeMode[i];
            status = AddNamedProperty(env, result, propName, i);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add named prop for CameraType!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &cameraTypeRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreateCameraTypeEnum is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraNapi::CreateConnectionTypeEnum(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName;
        for (unsigned int i = 0; i < vecConnectionTypeMode.size(); i++) {
            propName =  vecConnectionTypeMode[i];
            status = AddNamedProperty(env, result, propName, i);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add named prop for CameraPosition!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &connectionTypeRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreateConnectionTypeEnum is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraNapi::CreateCameraFormatObject(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName;
        for (unsigned int i = 0; i < vecCameraFormat.size(); i++) {
            propName = vecCameraFormat[i];
            int32_t value;
            if (propName.compare("CAMERA_FORMAT_JPEG") == 0) {
                value = CAM_FORMAT_JPEG;
            } else if (propName.compare("CAMERA_FORMAT_YUV_420_SP") == 0) {
                value = CAM_FORMAT_YUV_420_SP;
            } else {
                value = CAM_FORMAT_RGBA_8888;
            }
            status = AddNamedProperty(env, result, propName, value);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add named prop!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &cameraFormatRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreateCameraFormatObject is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraNapi::CreateCameraStatusObject(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName;
        for (unsigned int i = 0; i < vecCameraStatus.size(); i++) {
            propName = vecCameraStatus[i];
            status = AddNamedProperty(env, result, propName, i);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add named prop!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &cameraStatusRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreateCameraStatusObject is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraNapi::CreateImageRotationEnum(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName;
        for (auto itr = mapImageRotation.begin(); itr != mapImageRotation.end(); ++itr) {
            propName = itr->first;
            status = AddNamedProperty(env, result, propName, itr->second);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add ImageRotation prop!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &imageRotationRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreateImageRotationEnum is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraNapi::CreateQualityLevelEnum(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName;
        for (auto itr = mapQualityLevel.begin(); itr != mapQualityLevel.end(); ++itr) {
            propName = itr->first;
            status = AddNamedProperty(env, result, propName, itr->second);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add QualityLevel prop!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &qualityLevelRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreateQualityLevelEnum is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraNapi::CreateCameraInputErrorCode(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName = "ERROR_UNKNOWN";
        for (auto itr = mapCameraInputErrorCode.begin(); itr != mapCameraInputErrorCode.end(); ++itr) {
            propName = itr->first;
            status = CameraNapi::AddNamedProperty(env, result, propName, itr->second);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add QualityLevel prop!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &errorCameraInputRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreateCameraInputErrorCode is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraNapi::CreateCameraErrorCode(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName = "ERROR_UNKNOWN";
        for (auto itr = mapCameraErrorCode.begin(); itr != mapCameraErrorCode.end(); ++itr) {
            propName = itr->first;
            status = CameraNapi::AddNamedProperty(env, result, propName, itr->second);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add QualityLevel prop!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &errorCameraInputRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreateCameraErrorCode is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraNapi::CreateCaptureSessionErrorCode(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName = "ERROR_UNKNOWN";
        for (auto itr = mapCaptureSessionErrorCode.begin(); itr != mapCaptureSessionErrorCode.end(); ++itr) {
            propName = itr->first;
            status = CameraNapi::AddNamedProperty(env, result, propName, itr->second);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add CaptureSessionErrorCode prop!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &errorCaptureSessionRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreateCaptureSessionErrorCode is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraNapi::CreatePreviewOutputErrorCode(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName = "ERROR_UNKNOWN";
        for (auto itr = mapPreviewOutputErrorCode.begin(); itr != mapPreviewOutputErrorCode.end(); ++itr) {
            propName = itr->first;
            status = CameraNapi::AddNamedProperty(env, result, propName, itr->second);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add PreviewOutputErrorCode prop!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &errorPreviewOutputRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreatePreviewOutputErrorCode is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraNapi::CreatePhotoOutputErrorCode(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName = "ERROR_UNKNOWN";
        for (auto itr = mapPhotoOutputErrorCode.begin(); itr != mapPhotoOutputErrorCode.end(); ++itr) {
            propName = itr->first;
            status = CameraNapi::AddNamedProperty(env, result, propName, itr->second);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add PhotoOutputErrorCode prop!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &errorPhotoOutputRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreatePhotoOutputErrorCode is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraNapi::CreateVideoOutputErrorCode(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName = "ERROR_UNKNOWN";
        for (auto itr = mapVideoOutputErrorCode.begin(); itr != mapVideoOutputErrorCode.end(); ++itr) {
            propName = itr->first;
            status = CameraNapi::AddNamedProperty(env, result, propName, itr->second);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add VideoOutputErrorCode prop!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &errorVideoOutputRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreateCameraInputErrorCode is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraNapi::CreateMetadataObjectType(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName = "FACE_DETECTION";
        for (auto itr = mapMetadataObjectType.begin(); itr != mapMetadataObjectType.end(); ++itr) {
            propName = itr->first;
            status = CameraNapi::AddNamedProperty(env, result, propName, itr->second);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add MetadataObjectType prop!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &metadataObjectTypeRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreateMetadataObjectType is Failed!");
    napi_get_undefined(env, &result);
    return result;
}

napi_value CameraNapi::CreateMetaOutputErrorCode(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName = "ERROR_UNKNOWN";
        for (auto itr = mapMetaOutputErrorCode.begin(); itr != mapMetaOutputErrorCode.end(); ++itr) {
            propName = itr->first;
            status = CameraNapi::AddNamedProperty(env, result, propName, itr->second);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add MetaOutputErrorCode prop!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &errorMetaOutputRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreateMetaOutputErrorCode is Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraNapi::CreateVideoStabilizationModeObject(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName;
        for (unsigned int i = 0; i < vecVideoStabilizationMode.size(); i++) {
            propName = vecVideoStabilizationMode[i];
            status = AddNamedProperty(env, result, propName, i);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add named prop for VideoStabilizationMode!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &videoStabilizationModeRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreateVideoStabilizationModeObject is Failed!");
    napi_get_undefined(env, &result);

    return result;
}
} // namespace CameraStandard
} // namespace OHOS
