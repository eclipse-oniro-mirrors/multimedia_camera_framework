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
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

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

enum CameraSteps {
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
    static int32_t MapExposureModeEnumFromJs(int32_t jsExposureMode, camera_exposure_mode_enum_t &nativeExposureMode);

    static void MapExposureModeEnum(camera_exposure_mode_enum_t nativeExposureMode, int32_t &jsExposureMode);

    static void MapFocusStateEnum(FocusCallback::FocusState nativeFocusState, int32_t &jsFocusState);

    static void MapExposureStateEnum(ExposureCallback::ExposureState nativeExposureState, int32_t &jsExposureState);

    static void MapCameraPositionEnum(camera_position_enum_t nativeCamPos, int32_t &jsCameraPosition);

    static int32_t MapCameraPositionEnumFromJs(int32_t jsCameraPosition, camera_position_enum_t &nativeCamPos);

    static void MapCameraFormatEnum(camera_format_t nativeCamFormat, int32_t &jsCameraFormat);

    static void MapMetadataObjSupportedTypesEnum(MetadataObjectType nativeMetadataObjType, int32_t &jsMetadataObjType);

    static void MapMetadataObjSupportedTypesEnumFromJS(int32_t jsMetadataObjType,
        MetadataObjectType &nativeMetadataObjType, bool &isValid);

    static int32_t MapCameraFormatEnumFromJs(int32_t jsCameraFormat, camera_format_t &nativeCamFormat);

    static void MapCameraTypeEnum(camera_type_enum_t nativeCamType, int32_t &jsCameraType);

    static int32_t MapCameraTypeEnumFromJs(int32_t jsCameraType, camera_type_enum_t &nativeCamType);

    static void MapCameraConnectionTypeEnum(camera_connection_type_t nativeCamConnType, int32_t &jsCameraConnType);

    static int32_t MapQualityLevelFromJs(int32_t jsQuality, PhotoCaptureSetting::QualityLevel &nativeQuality);

    static int32_t MapImageRotationFromJs(int32_t jsRotation, PhotoCaptureSetting::RotationConfig &nativeRotation);

    static void MapCameraStatusEnum(CameraStatus deviceStatus, int32_t &jsCameraStatus);

    static void VideoStabilizationModeEnum(
        CameraVideoStabilizationMode nativeVideoStabilizationMode, int32_t &jsVideoStabilizationMode);

    static void CreateNapiErrorObject(napi_env env, int32_t errorCode, const char* errString,
        std::unique_ptr<JSAsyncContextOutput> &jsContext);

    static void InvokeJSAsyncMethod(napi_env env, napi_deferred deferred,
        napi_ref callbackRef, napi_async_work work, const JSAsyncContextOutput &asyncContext);

    static int32_t IncreamentAndGet(uint32_t &num);

    static bool CheckInvalidArgument(napi_env env, size_t argc, int32_t length,
                                     napi_value *argv, CameraSteps step);

    static bool CheckError(napi_env env, int32_t retCode);

    static double FloatToDouble(float val);

    static bool CheckSystemApp(napi_env env);
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_NAPI_UTILS_H_ */
