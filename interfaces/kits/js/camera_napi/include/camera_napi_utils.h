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

#ifndef CAMERA_NAPI_UTILS_H_
#define CAMERA_NAPI_UTILS_H_

#include <vector>
#include "camera_error_code.h"
#include "camera_device_ability_items.h"
#include "input/camera_input.h"
#include "camera_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "output/photo_output.h"
#include "input/camera_manager.h"

#define CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar)                 \
    do {                                                                        \
        void* data;                                                             \
        napi_get_cb_info(env, info, &(argc), argv, &(thisVar), &data);          \
    } while (0)

#define CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar)                       \
    do {                                                                                        \
        void* data;                                                                             \
        status = napi_get_cb_info(env, info, nullptr, nullptr, &(thisVar), &data);              \
    } while (0)

#define CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, arg, count, cbRef)         \
    do {                                                                \
        napi_valuetype valueType = napi_undefined;                      \
        napi_typeof(env, arg, &valueType);                              \
        if (valueType == napi_function) {                               \
            napi_create_reference(env, arg, count, &(cbRef));           \
        } else {                                                        \
            NAPI_ASSERT(env, false, "type mismatch");                   \
        }                                                               \
    } while (0);

#define CAMERA_NAPI_ASSERT_NULLPTR_CHECK(env, result)       \
    do {                                                    \
        if ((result) == nullptr) {                          \
            napi_get_undefined(env, &(result));             \
            return result;                                  \
        }                                                   \
    } while (0);

#define CAMERA_NAPI_CREATE_PROMISE(env, callbackRef, deferred, result)      \
    do {                                                                    \
        if ((callbackRef) == nullptr) {                                     \
            napi_create_promise(env, &(deferred), &(result));               \
        }                                                                   \
    } while (0);

#define CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, resourceName)                       \
    do {                                                                                    \
        napi_create_string_utf8(env, resourceName, NAPI_AUTO_LENGTH, &(resource));          \
    } while (0);

#define CAMERA_NAPI_CHECK_NULL_PTR_RETURN_UNDEFINED(env, ptr, ret, message)     \
    do {                                                            \
        if ((ptr) == nullptr) {                                     \
            HiLog::Error(LABEL, message);                           \
            napi_get_undefined(env, &(ret));                        \
            return ret;                                             \
        }                                                           \
    } while (0)

#define CAMERA_NAPI_CHECK_NULL_PTR_RETURN_VOID(ptr, message)   \
    do {                                           \
        if ((ptr) == nullptr) {                    \
            HiLog::Error(LABEL, message);          \
            return;                                \
        }                                          \
    } while (0)

#define CAMERA_NAPI_ASSERT_EQUAL(condition, errMsg)     \
    do {                                    \
        if (!(condition)) {                 \
            HiLog::Error(LABEL, errMsg);    \
            return;                         \
        }                                   \
    } while (0)

#define CAMERA_NAPI_CHECK_AND_BREAK_LOG(cond, fmt, ...)            \
    do {                                               \
        if (!(cond)) {                                 \
            MEDIA_ERR_LOG(fmt, ##__VA_ARGS__);         \
            break;                                     \
        }                                              \
    } while (0)

#define CAMERA_NAPI_CHECK_AND_RETURN_LOG(cond, fmt, ...)           \
    do {                                               \
        if (!(cond)) {                                 \
            MEDIA_ERR_LOG(fmt, ##__VA_ARGS__);         \
            return;                                    \
        }                                              \
    } while (0)

namespace OHOS {
namespace CameraStandard {
/* Constants for array index */
const int32_t PARAM0 = 0;
const int32_t PARAM1 = 1;
const int32_t PARAM2 = 2;

/* Constants for array size */
const int32_t ARGS_ZERO = 0;
const int32_t ARGS_ONE = 1;
const int32_t ARGS_TWO = 2;
const int32_t ARGS_THREE = 3;
const int32_t SIZE = 100;

struct AsyncContext {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;
    bool status;
    int32_t taskId;
    int32_t errorCode;
    std::string errorMsg;
    std::string funcName;
    bool isInvalidArgument;
};

struct JSAsyncContextOutput {
    napi_value error;
    napi_value data;
    bool status;
    bool bRetBool;
    std::string funcName;
};

enum JSQualityLevel {
    QUALITY_LEVEL_HIGH = 0,
    QUALITY_LEVEL_MEDIUM,
    QUALITY_LEVEL_LOW
};

enum JSImageRotation {
    ROTATION_0 = 0,
    ROTATION_90 = 90,
    ROTATION_180 = 180,
    ROTATION_270 = 270
};

enum JSCameraStatus {
    JS_CAMERA_STATUS_APPEAR = 0,
    JS_CAMERA_STATUS_DISAPPEAR = 1,
    JS_CAMERA_STATUS_AVAILABLE = 2,
    JS_CAMERA_STATUS_UNAVAILABLE = 3
};

enum CameraTaskId {
    CAMERA_MANAGER_TASKID = 0x01000000,
    CAMERA_INPUT_TASKID = 0x02000000,
    CAMERA_PHOTO_OUTPUT_TASKID = 0x03000000,
    CAMERA_PREVIEW_OUTPUT_TASKID = 0x04000000,
    CAMERA_VIDEO_OUTPUT_TASKID = 0x05000000,
    CAMERA_SESSION_TASKID = 0x06000000
};

enum JSMetadataObjectType {
    FACE = 0
};

enum NapiCheckInvalidArgumentModes {
    CREATE_CAMERA_INPUT_INSTANCE,
    CREATE_PREVIEW_OUTPUT_INSTANCE,
    CREATE_PHOTO_OUTPUT_INSTANCE,
    CREATE_VIDEO_OUTPUT_INSTANCE,
    CREATE_METADATA_OUTPUT_INSTANCE,
    ADD_INPUT,
    REMOVE_INPUT,
    ADD_OUTPUT,
    REMOVE_OUTPUT,
    PHOTO_OUT_CAPTURE,
};

/* Util class used by napi asynchronous methods for making call to js callback function */
class CameraNapiUtils {
public:
    static int32_t MapExposureModeEnumFromJs(int32_t jsExposureMode, camera_exposure_mode_enum_t &nativeExposureMode)
    {
        MEDIA_INFO_LOG("js exposure mode = %{public}d", jsExposureMode);
        switch (jsExposureMode) {
            case EXPOSURE_MODE_LOCKED:
                nativeExposureMode = OHOS_CAMERA_EXPOSURE_MODE_LOCKED;
                break;
            case EXPOSURE_MODE_AUTO:
                nativeExposureMode = OHOS_CAMERA_EXPOSURE_MODE_AUTO;
                break;
            case EXPOSURE_MODE_CONTINUOUS_AUTO:
                nativeExposureMode = OHOS_CAMERA_EXPOSURE_MODE_CONTINUOUS_AUTO;
                break;
            default:
                MEDIA_ERR_LOG("Invalid exposure mode value received from application");
                return -1;
        }

        return 0;
    }

    static void MapExposureModeEnum(camera_exposure_mode_enum_t nativeExposureMode, int32_t &jsExposureMode)
    {
        MEDIA_INFO_LOG("native exposure mode = %{public}d", static_cast<int32_t>(nativeExposureMode));
        switch (nativeExposureMode) {
            case OHOS_CAMERA_EXPOSURE_MODE_LOCKED:
                jsExposureMode = EXPOSURE_MODE_LOCKED;
                break;
            case OHOS_CAMERA_EXPOSURE_MODE_AUTO:
                jsExposureMode = EXPOSURE_MODE_AUTO;
                break;
            case OHOS_CAMERA_EXPOSURE_MODE_CONTINUOUS_AUTO:
                jsExposureMode = EXPOSURE_MODE_CONTINUOUS_AUTO;
                break;
            default:
                MEDIA_ERR_LOG("Received native exposure mode is not supported with JS");
                jsExposureMode = -1;
        }
    }

    static void MapFocusStateEnum(FocusCallback::FocusState nativeFocusState, int32_t &jsFocusState)
    {
        MEDIA_INFO_LOG("native focus state = %{public}d", static_cast<int32_t>(nativeFocusState));
        switch (nativeFocusState) {
            case FocusCallback::SCAN:
                jsFocusState = FOCUS_STATE_SCAN;
                break;
            case FocusCallback::FOCUSED:
                jsFocusState = FOCUS_STATE_FOCUSED;
                break;
            case FocusCallback::UNFOCUSED:
            default:
                jsFocusState = FOCUS_STATE_UNFOCUSED;
        }
    }

    static void MapExposureStateEnum(ExposureCallback::ExposureState nativeExposureState, int32_t &jsExposureState)
    {
        MEDIA_INFO_LOG("native exposure state = %{public}d", static_cast<int32_t>(nativeExposureState));
        switch (nativeExposureState) {
            case ExposureCallback::SCAN:
                jsExposureState = EXPOSURE_STATE_SCAN;
                break;
            case ExposureCallback::CONVERGED:
            default:
                jsExposureState = EXPOSURE_STATE_CONVERGED;
        }
    }

    static void MapCameraPositionEnum(camera_position_enum_t nativeCamPos, int32_t &jsCameraPosition)
    {
        MEDIA_INFO_LOG("native cam pos = %{public}d", static_cast<int32_t>(nativeCamPos));
        switch (nativeCamPos) {
            case OHOS_CAMERA_POSITION_FRONT:
                jsCameraPosition = CAMERA_POSITION_FRONT;
                break;
            case OHOS_CAMERA_POSITION_BACK:
                jsCameraPosition = CAMERA_POSITION_BACK;
                break;
            case OHOS_CAMERA_POSITION_OTHER:
            default:
                jsCameraPosition = CAMERA_POSITION_UNSPECIFIED;
        }
    }

    static int32_t MapCameraPositionEnumFromJs(int32_t jsCameraPosition, camera_position_enum_t &nativeCamPos)
    {
        MEDIA_INFO_LOG("js cam pos = %{public}d", jsCameraPosition);
        switch (jsCameraPosition) {
            case CAMERA_POSITION_FRONT:
                nativeCamPos = OHOS_CAMERA_POSITION_FRONT;
                break;
            case CAMERA_POSITION_BACK:
                nativeCamPos = OHOS_CAMERA_POSITION_BACK;
                break;
            case CAMERA_POSITION_UNSPECIFIED:
                nativeCamPos = OHOS_CAMERA_POSITION_OTHER;
                break;
            default:
                MEDIA_ERR_LOG("Invalid camera position value received from application");
                return -1;
        }

        return 0;
    }

    static void MapCameraFormatEnum(camera_format_t nativeCamFormat, int32_t &jsCameraFormat)
    {
        MEDIA_INFO_LOG("native cam format = %{public}d", static_cast<int32_t>(nativeCamFormat));
        switch (nativeCamFormat) {
            case OHOS_CAMERA_FORMAT_YCRCB_420_SP:
                jsCameraFormat = CAMERA_FORMAT_YUV_420_SP;
                break;
            case OHOS_CAMERA_FORMAT_JPEG:
                jsCameraFormat = CAMERA_FORMAT_JPEG;
                break;
            case OHOS_CAMERA_FORMAT_RGBA_8888:
            case OHOS_CAMERA_FORMAT_YCBCR_420_888:
            default:
                jsCameraFormat = -1;
                MEDIA_ERR_LOG("The native camera format is not supported with JS");
        }
    }

    static void MapMetadataObjSupportedTypesEnum(MetadataObjectType nativeMetadataObjType, int32_t &jsMetadataObjType)
    {
        MEDIA_INFO_LOG("native metadata Object Type = %{public}d", static_cast<int32_t>(nativeMetadataObjType));
        switch (nativeMetadataObjType) {
            case MetadataObjectType::FACE:
                jsMetadataObjType = JSMetadataObjectType::FACE;
                break;
            default:
                jsMetadataObjType = -1;
                MEDIA_ERR_LOG("Native Metadata object type not supported with JS");
        }
    }

    static void MapMetadataObjSupportedTypesEnumFromJS(int32_t jsMetadataObjType,
        MetadataObjectType &nativeMetadataObjType, bool &isValid)
    {
        MEDIA_INFO_LOG("JS metadata Object Type = %{public}d", jsMetadataObjType);
        switch (jsMetadataObjType) {
            case JSMetadataObjectType::FACE:
                nativeMetadataObjType = MetadataObjectType::FACE;
                break;
            default:
                isValid = false;
                MEDIA_ERR_LOG("JS Metadata object type not supported with native");
        }
    }

    static int32_t MapCameraFormatEnumFromJs(int32_t jsCameraFormat, camera_format_t &nativeCamFormat)
    {
        MEDIA_INFO_LOG("js cam format = %{public}d", jsCameraFormat);
        switch (jsCameraFormat) {
            case CAMERA_FORMAT_YUV_420_SP:
                nativeCamFormat = OHOS_CAMERA_FORMAT_YCRCB_420_SP;
                break;
            case CAMERA_FORMAT_JPEG:
                nativeCamFormat = OHOS_CAMERA_FORMAT_JPEG;
                break;
            default:
                MEDIA_ERR_LOG("Invalid or unsupported camera format value received from application");
                return -1;
        }

        return 0;
    }

    static void MapCameraTypeEnum(camera_type_enum_t nativeCamType, int32_t &jsCameraType)
    {
        MEDIA_INFO_LOG("native cam type = %{public}d", static_cast<int32_t>(nativeCamType));
        switch (nativeCamType) {
            case OHOS_CAMERA_TYPE_WIDE_ANGLE:
                jsCameraType = CAMERA_TYPE_WIDE_ANGLE;
                break;
            case OHOS_CAMERA_TYPE_ULTRA_WIDE:
                jsCameraType = CAMERA_TYPE_ULTRA_WIDE;
                break;
            case OHOS_CAMERA_TYPE_TELTPHOTO:
                jsCameraType = CAMERA_TYPE_TELEPHOTO;
                break;
            case OHOS_CAMERA_TYPE_TRUE_DEAPTH:
                jsCameraType = CAMERA_TYPE_TRUE_DEPTH;
                break;
            case OHOS_CAMERA_TYPE_LOGICAL:
                MEDIA_ERR_LOG("Logical camera type is treated as unspecified");
                jsCameraType = CAMERA_TYPE_DEFAULT;
                break;
            case OHOS_CAMERA_TYPE_UNSPECIFIED:
            default:
                jsCameraType = CAMERA_TYPE_DEFAULT;
        }
    }

    static int32_t MapCameraTypeEnumFromJs(int32_t jsCameraType, camera_type_enum_t &nativeCamType)
    {
        MEDIA_INFO_LOG("js cam type = %{public}d", jsCameraType);
        switch (jsCameraType) {
            case CAMERA_TYPE_WIDE_ANGLE:
                nativeCamType = OHOS_CAMERA_TYPE_WIDE_ANGLE;
                break;
            case CAMERA_TYPE_ULTRA_WIDE:
                nativeCamType = OHOS_CAMERA_TYPE_ULTRA_WIDE;
                break;
            case CAMERA_TYPE_TELEPHOTO:
                nativeCamType = OHOS_CAMERA_TYPE_TELTPHOTO;
                break;
            case CAMERA_TYPE_TRUE_DEPTH:
                nativeCamType = OHOS_CAMERA_TYPE_TRUE_DEAPTH;
                break;
            case CAMERA_TYPE_DEFAULT:
                nativeCamType = OHOS_CAMERA_TYPE_UNSPECIFIED;
                break;
            default:
                MEDIA_ERR_LOG("Invalid camera type value received from application");
                return -1;
        }

        return 0;
    }

    static void MapCameraConnectionTypeEnum(camera_connection_type_t nativeCamConnType, int32_t &jsCameraConnType)
    {
        MEDIA_INFO_LOG("native cam connection type = %{public}d", static_cast<int32_t>(nativeCamConnType));
        switch (nativeCamConnType) {
            case OHOS_CAMERA_CONNECTION_TYPE_REMOTE:
                jsCameraConnType = CAMERA_CONNECTION_REMOTE;
                break;
            case OHOS_CAMERA_CONNECTION_TYPE_USB_PLUGIN:
                jsCameraConnType = CAMERA_CONNECTION_USB_PLUGIN;
                break;
            case OHOS_CAMERA_CONNECTION_TYPE_BUILTIN:
            default:
                jsCameraConnType = CAMERA_CONNECTION_BUILT_IN;
        }
    }

    static int32_t MapQualityLevelFromJs(int32_t jsQuality, PhotoCaptureSetting::QualityLevel &nativeQuality)
    {
        MEDIA_INFO_LOG("js quality level = %{public}d", jsQuality);
        switch (jsQuality) {
            case QUALITY_LEVEL_HIGH:
                nativeQuality = PhotoCaptureSetting::QUALITY_LEVEL_HIGH;
                break;
            case QUALITY_LEVEL_MEDIUM:
                nativeQuality = PhotoCaptureSetting::QUALITY_LEVEL_MEDIUM;
                break;
            case QUALITY_LEVEL_LOW:
                nativeQuality = PhotoCaptureSetting::QUALITY_LEVEL_LOW;
                break;
            default:
                MEDIA_ERR_LOG("Invalid quality value received from application");
                return -1;
        }

        return 0;
    }

    static int32_t MapImageRotationFromJs(int32_t jsRotation, PhotoCaptureSetting::RotationConfig &nativeRotation)
    {
        MEDIA_INFO_LOG("js rotation = %{public}d", jsRotation);
        switch (jsRotation) {
            case ROTATION_0:
                nativeRotation = PhotoCaptureSetting::Rotation_0;
                break;
            case ROTATION_90:
                nativeRotation = PhotoCaptureSetting::Rotation_90;
                break;
            case ROTATION_180:
                nativeRotation = PhotoCaptureSetting::Rotation_180;
                break;
            case ROTATION_270:
                nativeRotation = PhotoCaptureSetting::Rotation_270;
                break;
            default:
                MEDIA_ERR_LOG("Invalid rotation value received from application");
                return -1;
        }

        return 0;
    }

    static void MapCameraStatusEnum(CameraStatus deviceStatus, int32_t &jsCameraStatus)
    {
        MEDIA_INFO_LOG("native camera status = %{public}d", static_cast<int32_t>(deviceStatus));
        switch (deviceStatus) {
            case CAMERA_DEVICE_STATUS_UNAVAILABLE:
                jsCameraStatus = JS_CAMERA_STATUS_UNAVAILABLE;
                break;
            case CAMERA_DEVICE_STATUS_AVAILABLE:
                jsCameraStatus = JS_CAMERA_STATUS_AVAILABLE;
                break;
            default:
                MEDIA_ERR_LOG("Received native camera status is not supported with JS");
                jsCameraStatus = -1;
        }
    }

    static void VideoStabilizationModeEnum(
        CameraVideoStabilizationMode nativeVideoStabilizationMode, int32_t &jsVideoStabilizationMode)
    {
        MEDIA_INFO_LOG(
            "native video stabilization mode = %{public}d", static_cast<int32_t>(nativeVideoStabilizationMode));
        switch (nativeVideoStabilizationMode) {
            case OHOS_CAMERA_VIDEO_STABILIZATION_OFF:
                jsVideoStabilizationMode = OFF;
                break;
            case OHOS_CAMERA_VIDEO_STABILIZATION_LOW:
                jsVideoStabilizationMode = LOW;
                break;
            case OHOS_CAMERA_VIDEO_STABILIZATION_MIDDLE:
                jsVideoStabilizationMode = MIDDLE;
                break;
            case OHOS_CAMERA_VIDEO_STABILIZATION_HIGH:
                jsVideoStabilizationMode = HIGH;
                break;
            case OHOS_CAMERA_VIDEO_STABILIZATION_AUTO:
                jsVideoStabilizationMode = AUTO;
                break;
            default:
                MEDIA_ERR_LOG("Received native video stabilization mode is not supported with JS");
                jsVideoStabilizationMode = -1;
        }
    }

    static void CreateNapiErrorObject(napi_env env, int32_t errorCode, const char* errString,
        std::unique_ptr<JSAsyncContextOutput> &jsContext)
    {
        napi_get_undefined(env, &jsContext->data);
        napi_value napiErrorCode = nullptr;
        napi_value napiErrorMsg = nullptr;

        std::string errorCodeStr = std::to_string(errorCode);
        napi_create_string_utf8(env, errorCodeStr.c_str(), NAPI_AUTO_LENGTH, &napiErrorCode);
        napi_create_string_utf8(env, errString, NAPI_AUTO_LENGTH, &napiErrorMsg);

        napi_create_object(env, &jsContext->error);
        napi_set_named_property(env, jsContext->error, "code", napiErrorCode);
        napi_set_named_property(env, jsContext->error, "message", napiErrorMsg);

        jsContext->status = false;
    }

    static void InvokeJSAsyncMethod(napi_env env, napi_deferred deferred,
        napi_ref callbackRef, napi_async_work work, const JSAsyncContextOutput &asyncContext)
    {
        napi_value retVal;
        napi_value callback = nullptr;
        std::string funcName = asyncContext.funcName;
        MEDIA_INFO_LOG("%{public}s, context->InvokeJSAsyncMethod start", funcName.c_str());
        /* Deferred is used when JS Callback method expects a promise value */
        if (deferred) {
            if (asyncContext.status) {
                napi_resolve_deferred(env, deferred, asyncContext.data);
                MEDIA_INFO_LOG("%{public}s, InvokeJSAsyncMethod napi_resolve_deferred", funcName.c_str());
            } else {
                napi_reject_deferred(env, deferred, asyncContext.error);
                MEDIA_ERR_LOG("%{public}s, InvokeJSAsyncMethod napi_reject_deferred", funcName.c_str());
            }
            MEDIA_INFO_LOG("%{public}s, InvokeJSAsyncMethod end deferred", funcName.c_str());
        } else {
            MEDIA_INFO_LOG("%{public}s, InvokeJSAsyncMethod callback", funcName.c_str());
            napi_value result[ARGS_TWO];
            result[PARAM0] = asyncContext.error;
            result[PARAM1] = asyncContext.data;
            napi_get_reference_value(env, callbackRef, &callback);
            MEDIA_INFO_LOG("%{public}s, InvokeJSAsyncMethod napi_call_function start", funcName.c_str());
            napi_call_function(env, nullptr, callback, ARGS_TWO, result, &retVal);
            MEDIA_INFO_LOG("%{public}s, InvokeJSAsyncMethod napi_call_function end", funcName.c_str());
            napi_delete_reference(env, callbackRef);
        }
        napi_delete_async_work(env, work);
        MEDIA_INFO_LOG("%{public}s, InvokeJSAsyncMethod inner end", funcName.c_str());
    }

    static int32_t IncreamentAndGet(uint32_t &num)
    {
        int32_t temp = num & 0x00ffffff;
        if (temp >= 0xffff) {
            num = num & 0xff000000;
        }
        num++;
        return num;
    }

    static bool CheckInvalidArgument(napi_env env, size_t argc, int32_t length,
                                     napi_value *argv, NapiCheckInvalidArgumentModes mode)
    {
        bool isPass = true;
        napi_valuetype valueTypeArray[length];
        for (int32_t i = 0; i < length; i++) {
            napi_typeof(env, argv[i], &valueTypeArray[i]);
        }
        switch (mode) {
            case CREATE_CAMERA_INPUT_INSTANCE:
                if (argc == ARGS_ONE) {
                    isPass = valueTypeArray[0] == napi_object;
                } else if (argc == ARGS_TWO) {
                    isPass = (valueTypeArray[0] == napi_number) && (valueTypeArray[1] == napi_number);
                } else {
                    isPass = false;
                }
                break;

            case CREATE_PREVIEW_OUTPUT_INSTANCE:
                isPass = (argc == ARGS_TWO) &&
                         (valueTypeArray[0] == napi_object) && (valueTypeArray[1] == napi_string);
                break;

            case CREATE_PHOTO_OUTPUT_INSTANCE:
                isPass = (argc == ARGS_TWO) &&
                         (valueTypeArray[0] == napi_object) && (valueTypeArray[1] == napi_string);
                break;

            case CREATE_VIDEO_OUTPUT_INSTANCE:
                isPass = (argc == ARGS_TWO) &&
                         (valueTypeArray[0] == napi_object) && (valueTypeArray[1] == napi_string);
                break;

            case CREATE_METADATA_OUTPUT_INSTANCE:
                isPass = argc == ARGS_ONE;
                if (argc == ARGS_ONE) {
                    napi_is_array(env, argv[0], &isPass);
                } else {
                    isPass = false;
                }
                break;

            case ADD_INPUT:
                isPass = (argc == ARGS_ONE) && (valueTypeArray[0] == napi_object);
                break;

            case REMOVE_INPUT:
                isPass = (argc == ARGS_ONE) && (valueTypeArray[0] == napi_object);
                break;

            case ADD_OUTPUT:
                isPass = (argc == ARGS_ONE) && (valueTypeArray[0] == napi_object);
                break;

            case REMOVE_OUTPUT:
                isPass = (argc == ARGS_ONE) && (valueTypeArray[0] == napi_object);
                break;

            case PHOTO_OUT_CAPTURE:
                if (argc == ARGS_ZERO) {
                    isPass = true;
                } else if (argc == ARGS_ONE) {
                    isPass = (valueTypeArray[0] == napi_object) || (valueTypeArray[0] == napi_function) ||
                        (valueTypeArray[0] == napi_undefined);
                } else if (argc == ARGS_TWO) {
                    isPass = (valueTypeArray[0] == napi_object) && (valueTypeArray[1] == napi_function);
                } else {
                    isPass = false;
                }
                break;
            default:
                break;
        }
        if (!isPass) {
            std::string errorCode = std::to_string(CameraErrorCode::INVALID_ARGUMENT);
            napi_throw_type_error(env, errorCode.c_str(), "");
        }
        return isPass;
    }

    static bool CheckError(napi_env env, int32_t retCode)
    {
        if ((retCode != 0)) {
            std::string errorCode = std::to_string(retCode);
            napi_throw_error(env, errorCode.c_str(), "");
            return false;
        }
        return true;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_NAPI_UTILS_H_ */
