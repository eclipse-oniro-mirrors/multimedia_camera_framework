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

#include <cinttypes>
#include <securec.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fstream>
#include <iostream>
#include <sstream>
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

struct AutoRef {
    AutoRef(napi_env env, napi_ref cb, bool isOnce) : isOnce_(isOnce), env_(env), cb_(cb)
    {
    }
    ~AutoRef()
    {
        if (env_ != nullptr && cb_ != nullptr) {
            (void)napi_delete_reference(env_, cb_);
        }
    }
    bool isOnce_ = false;
    napi_env env_;
    napi_ref cb_;
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
    CAMERA_SESSION_TASKID = 0x06000000,
    MODE_MANAGER_TASKID = 0x07000000,
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
    ADD_DEFERRED_SURFACE,
    CREATE_DEFERRED_PREVIEW_OUTPUT
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

    static void MapMetadataObjSupportedTypesEnum(MetadataObjectType nativeMetadataObjType, int32_t &jsMetadataObjType);

    static void MapMetadataObjSupportedTypesEnumFromJS(int32_t jsMetadataObjType,
        MetadataObjectType &nativeMetadataObjType, bool &isValid);

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

    static std::string GetStringArgument(napi_env env, napi_value value);

    static void ThrowError(napi_env env, int32_t code);

    static bool IsSameCallback(napi_env env, napi_value callback, napi_ref refCallback);

    static napi_status CallPromiseFun(
        napi_env env, napi_value promiseValue, void* data, napi_callback thenCallback, napi_callback catchCallback);

    static std::vector<napi_property_descriptor> GetPropertyDescriptor(
        std::vector<std::vector<napi_property_descriptor>> descriptors);
};

template <typename T>
class EnumHelper {
public:
    EnumHelper(const std::map<T, std::string>&& origin, const T defaultValue)
    {
        _mapEnum2String = std::move(origin);
        _mapString2Enum = GenString2EnumMap(_mapEnum2String);
        _defaultValue = defaultValue;
    }

    T ToEnum(const std::string& str)
    {
        auto item = _mapString2Enum.find(str);
        if (item != _mapString2Enum.end()) {
            return item->second;
        }
        return _defaultValue;
    }
private:
    std::map<T, std::string> _mapEnum2String;
    std::map<std::string, T> _mapString2Enum;
    T _defaultValue;

    static std::map<std::string, T> GenString2EnumMap(std::map<T, std::string> enum2StringMap)
    {
        std::map<std::string, T> result;
        for (const auto& item : enum2StringMap) {
            result.emplace(std::make_pair(item.second, item.first));
        }
        return result;
    };
};

template <class T>
class ListenerTemplate {
public:
    static napi_value On(napi_env env, napi_callback_info info)
    {
        MEDIA_INFO_LOG("On is called");
        CAMERA_SYNC_TRACE;
        napi_value undefinedResult = nullptr;
        size_t argCount = ARGS_TWO;
        napi_value argv[ARGS_TWO] = {nullptr, nullptr};
        napi_value thisVar = nullptr;

        napi_get_undefined(env, &undefinedResult);

        CAMERA_NAPI_GET_JS_ARGS(env, info, argCount, argv, thisVar);
        NAPI_ASSERT(env, argCount == ARGS_TWO, "requires 2 parameters");

        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string
            || napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function) {
            return undefinedResult;
        }
        std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[PARAM0]);
        MEDIA_INFO_LOG("On eventType: %{public}s", eventType.c_str());
        return T::RegisterCallback(env, thisVar, eventType, argv[PARAM1], false);
    }

    static napi_value Once(napi_env env, napi_callback_info info)
    {
        MEDIA_INFO_LOG("Once is called");
        CAMERA_SYNC_TRACE;
        napi_value undefinedResult = nullptr;
        size_t argCount = ARGS_TWO;
        napi_value argv[ARGS_TWO] = {nullptr, nullptr};
        napi_value thisVar = nullptr;

        napi_get_undefined(env, &undefinedResult);

        CAMERA_NAPI_GET_JS_ARGS(env, info, argCount, argv, thisVar);
        NAPI_ASSERT(env, argCount == ARGS_TWO, "requires 2 parameters");

        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string
            || napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function) {
            return undefinedResult;
        }
        std::string eventType = CameraNapiUtils::GetStringArgument(env, argv[PARAM0]);
        MEDIA_INFO_LOG("Once eventType: %{public}s", eventType.c_str());
        return T::RegisterCallback(env, thisVar, eventType, argv[PARAM1], true);
    }

    static napi_value Off(napi_env env, napi_callback_info info)
    {
        MEDIA_INFO_LOG("Off is called");
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
        return T::UnregisterCallback(env, thisVar, eventType, argv[PARAM1]);
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_NAPI_UTILS_H_ */
