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

#include <stdbool.h>

#include "camera_error_code.h"
#include "camera_napi_const.h"
#include "js_native_api_types.h"
#include "napi/native_node_api.h"

#define CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar)        \
    do {                                                               \
        void* data;                                                    \
        napi_get_cb_info(env, info, &(argc), argv, &(thisVar), &data); \
    } while (0)

#define CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar)          \
    do {                                                                           \
        void* data;                                                                \
        status = napi_get_cb_info(env, info, nullptr, nullptr, &(thisVar), &data); \
    } while (0)

#define CAMERA_NAPI_GET_JS_ASYNC_CB_REF(env, arg, count, cbRef) \
    do {                                                        \
        napi_valuetype valueType = napi_undefined;              \
        napi_typeof(env, arg, &valueType);                      \
        if (valueType == napi_function) {                       \
            napi_create_reference(env, arg, count, &(cbRef));   \
        } else {                                                \
            NAPI_ASSERT(env, false, "type mismatch");           \
        }                                                       \
    } while (0)

#define CAMERA_NAPI_ASSERT_NULLPTR_CHECK(env, result) \
    do {                                              \
        if ((result) == nullptr) {                    \
            napi_get_undefined(env, &(result));       \
            return result;                            \
        }                                             \
    } while (0)

#define CAMERA_NAPI_CREATE_PROMISE(env, callbackRef, deferred, result) \
    do {                                                               \
        if ((callbackRef) == nullptr) {                                \
            napi_create_promise(env, &(deferred), &(result));          \
        }                                                              \
    } while (0)

#define CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, resourceName)              \
    do {                                                                           \
        napi_create_string_utf8(env, resourceName, NAPI_AUTO_LENGTH, &(resource)); \
    } while (0)

#define CAMERA_NAPI_CHECK_NULL_PTR_RETURN_UNDEFINED(env, ptr, ret, message, ...) \
    do {                                                                         \
        if ((ptr) == nullptr) {                                                  \
            MEDIA_ERR_LOG(message, ##__VA_ARGS__);                               \
            napi_get_undefined(env, &(ret));                                     \
            return ret;                                                          \
        }                                                                        \
    } while (0)

#define CAMERA_NAPI_CHECK_NULL_PTR_RETURN_VOID(ptr, message, ...) \
    do {                                                          \
        if ((ptr) == nullptr) {                                   \
            MEDIA_ERR_LOG(message, ##__VA_ARGS__);                \
            return;                                               \
        }                                                         \
    } while (0)

#define CAMERA_NAPI_ASSERT_EQUAL(condition, errMsg, ...) \
    do {                                                 \
        if (!(condition)) {                              \
            MEDIA_ERR_LOG(errMsg, ##__VA_ARGS__);        \
            return;                                      \
        }                                                \
    } while (0)

#define CAMERA_NAPI_CHECK_AND_BREAK_LOG(cond, fmt, ...) \
    do {                                                \
        if (!(cond)) {                                  \
            MEDIA_ERR_LOG(fmt, ##__VA_ARGS__);          \
            break;                                      \
        }                                               \
    } while (0)

#define CAMERA_NAPI_CHECK_AND_RETURN_LOG(cond, fmt, ...) \
    do {                                                 \
        if (!(cond)) {                                   \
            MEDIA_ERR_LOG(fmt, ##__VA_ARGS__);           \
            return;                                      \
        }                                                \
    } while (0)

namespace OHOS {
namespace CameraStandard {
/* Util class used by napi asynchronous methods for making call to js callback function */
class CameraNapiUtils {
public:
    static void CreateNapiErrorObject(
        napi_env env, int32_t errorCode, const char* errString, std::unique_ptr<JSAsyncContextOutput>& jsContext);

    static void InvokeJSAsyncMethod(napi_env env, napi_deferred deferred, napi_ref callbackRef, napi_async_work work,
        const JSAsyncContextOutput& asyncContext);

    static int32_t IncreamentAndGet(uint32_t& num);

    static void IsEnableSecureCamera(bool isEnable);

    static bool GetEnableSecureCamera();

    static bool CheckInvalidArgument(napi_env env, size_t argc, int32_t length,
                                     napi_value *argv, CameraSteps step);

    static bool CheckError(napi_env env, int32_t retCode);

    static double FloatToDouble(float val);

    static std::string GetStringArgument(napi_env env, napi_value value);

    static bool IsSameCallback(napi_env env, napi_value callback, napi_ref refCallback);

    static napi_status CallPromiseFun(
        napi_env env, napi_value promiseValue, void* data, napi_callback thenCallback, napi_callback catchCallback);

    static std::vector<napi_property_descriptor> GetPropertyDescriptor(
        std::vector<std::vector<napi_property_descriptor>> descriptors);

    static napi_status CreateObjectWithPropName(
        napi_env env, napi_value* result, size_t property_count, const char** keys);

    static napi_status CreateObjectWithPropNameAndValues(napi_env env, napi_value* result, size_t property_count,
        const char** keys, const std::vector<std::string> values);

    inline static napi_value GetUndefinedValue(napi_env env)
    {
        napi_value result = nullptr;
        napi_get_undefined(env, &result);
        return result;
    }

    inline static void ThrowError(napi_env env, int32_t code, const char* message)
    {
        std::string errorCode = std::to_string(code);
        napi_throw_error(env, errorCode.c_str(), message);
    }

    static void CreateFrameRateJSArray(napi_env env, std::vector<int32_t> frameRateRange, napi_value &result);
 
    static napi_value CreateSupportFrameRatesJSArray(
        napi_env env, std::vector<std::vector<int32_t>> supportedFrameRatesRange);

private:
    explicit CameraNapiUtils() {};

    static bool mEnableSecure;
}; // namespace CameraNapiUtils
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_NAPI_UTILS_H_ */
