/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "camera_napi_utils.h"

#include "camera_error_code.h"
#include "camera_log.h"
#include "js_native_api_types.h"
#include "napi/native_api.h"

namespace OHOS {
namespace CameraStandard {
bool CameraNapiUtils::mEnableSecure = false;
void CameraNapiUtils::CreateNapiErrorObject(napi_env env, int32_t errorCode, const char* errString,
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

void CameraNapiUtils::InvokeJSAsyncMethod(napi_env env, napi_deferred deferred,
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

int32_t CameraNapiUtils::IncreamentAndGet(uint32_t &num)
{
    int32_t temp = num & 0x00ffffff;
    if (temp >= 0xffff) {
        num = num & 0xff000000;
    }
    num++;
    return num;
}

bool CameraNapiUtils::GetEnableSecureCamera()
{
    return mEnableSecure;
}

void CameraNapiUtils::IsEnableSecureCamera(bool isEnable)
{
    mEnableSecure = isEnable;
}

bool CameraNapiUtils::CheckInvalidArgument(napi_env env, size_t argc, int32_t length,
    napi_value *argv, CameraSteps step)
{
    bool isPass = true;
    napi_valuetype valueTypeArray[length];
    for (int32_t i = 0; i < length; i++) {
        napi_typeof(env, argv[i], &valueTypeArray[i]);
    }
    switch (step) {
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
            isPass = (argc >= ARGS_ONE) && (valueTypeArray[0] == napi_object);
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

        case ADD_DEFERRED_SURFACE:
            if (argc == ARGS_ONE) {
                isPass = valueTypeArray[0] == napi_string;
            } else if (argc == ARGS_TWO) {
                isPass = (valueTypeArray[0] == napi_string) && (valueTypeArray[1] == napi_function);
            } else {
                isPass = false;
            }
            break;

        case CREATE_DEFERRED_PREVIEW_OUTPUT:
            if (argc == ARGS_ONE) {
                isPass = valueTypeArray[0] == napi_object;
            }  else {
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

bool CameraNapiUtils::CheckError(napi_env env, int32_t retCode)
{
    if ((retCode != 0)) {
        std::string errorCode = std::to_string(retCode);
        napi_throw_error(env, errorCode.c_str(), "");
        return false;
    }
    return true;
}

double CameraNapiUtils::FloatToDouble(float val)
{
    const double precision = 1000000.0;
    val *= precision;
    double result = static_cast<double>(val / precision);
    return result;
}

std::string CameraNapiUtils::GetStringArgument(napi_env env, napi_value value)
{
    std::string strValue = "";
    size_t bufLength = 0;
    napi_status status = napi_get_value_string_utf8(env, value, nullptr, 0, &bufLength);
    if (status == napi_ok && bufLength > 0 && bufLength < PATH_MAX) {
        char *buffer = static_cast<char *>(malloc((bufLength + 1) * sizeof(char)));
        CHECK_AND_RETURN_RET_LOG(buffer != nullptr, strValue, "no memory");
        status = napi_get_value_string_utf8(env, value, buffer, bufLength + 1, &bufLength);
        if (status == napi_ok) {
            MEDIA_DEBUG_LOG("argument = %{public}s", buffer);
            strValue = buffer;
        }
        free(buffer);
        buffer = nullptr;
    }
    return strValue;
}

bool CameraNapiUtils::IsSameCallback(napi_env env, napi_value callback, napi_ref refCallback)
{
    bool isEquals = false;
    napi_value copyValue = nullptr;

    napi_get_reference_value(env, refCallback, &copyValue);
    if (napi_strict_equals(env, copyValue, callback, &isEquals) != napi_ok) {
        MEDIA_ERR_LOG("get napi_strict_equals failed");
        return false;
    }

    return isEquals;
}

napi_status CameraNapiUtils::CallPromiseFun(
    napi_env env, napi_value promiseValue, void* data, napi_callback thenCallback, napi_callback catchCallback)
{
    MEDIA_DEBUG_LOG("CallPromiseFun Start");
    bool isPromise = false;
    napi_is_promise(env, promiseValue, &isPromise);
    if (!isPromise) {
        MEDIA_ERR_LOG("CallPromiseFun promiseValue is not promise");
        return napi_invalid_arg;
    }
    // Create promiseThen
    napi_value promiseThen = nullptr;
    napi_get_named_property(env, promiseValue, "then", &promiseThen);
    if (promiseThen == nullptr) {
        MEDIA_ERR_LOG("CallPromiseFun get promiseThen failed");
        return napi_invalid_arg;
    }
    napi_value thenValue;
    napi_status ret = napi_create_function(env, "thenCallback", NAPI_AUTO_LENGTH, thenCallback, data, &thenValue);
    if (ret != napi_ok) {
        MEDIA_ERR_LOG("CallPromiseFun thenCallback got exception");
        return ret;
    }
    napi_value catchValue;
    ret = napi_create_function(env, "catchCallback", NAPI_AUTO_LENGTH, catchCallback, data, &catchValue);
    if (ret != napi_ok) {
        MEDIA_ERR_LOG("CallPromiseFun  catchCallback got exception");
        return ret;
    }
    napi_value thenReturnValue;
    constexpr uint32_t THEN_ARGC = 2;
    napi_value thenArgv[THEN_ARGC] = { thenValue, catchValue };
    ret = napi_call_function(env, promiseValue, promiseThen, THEN_ARGC, thenArgv, &thenReturnValue);
    if (ret != napi_ok) {
        MEDIA_ERR_LOG("CallPromiseFun PromiseThen got exception");
        return ret;
    }
    MEDIA_DEBUG_LOG("CallPromiseFun End");
    return napi_ok;
}

std::vector<napi_property_descriptor> CameraNapiUtils::GetPropertyDescriptor(
    std::vector<std::vector<napi_property_descriptor>> descriptors)
{
    MEDIA_DEBUG_LOG("GetPropertyDescriptor Start %zu", descriptors.size());
    std::vector<napi_property_descriptor> properties = {};
    std::for_each(descriptors.begin(), descriptors.end(),
                  [&properties](const std::vector<napi_property_descriptor> descriptor) {
                      properties.insert(properties.end(), descriptor.begin(), descriptor.end());
                  });
    return properties;
};

napi_status CameraNapiUtils::CreateObjectWithPropName(
    napi_env env, napi_value* result, size_t property_count, const char** keys)
{
    napi_value values[property_count];
    for (size_t i = 0; i < property_count; i++) {
        napi_get_undefined(env, &values[i]);
    }
    return napi_create_object_with_named_properties(env, result, property_count, keys, values);
}

napi_status CameraNapiUtils::CreateObjectWithPropNameAndValues(
    napi_env env, napi_value* result, size_t property_count, const char** keys, const std::vector<std::string> values)
{
    napi_value napiValues[property_count];
    for (size_t i = 0; i < property_count; i++) {
        napi_create_string_utf8(env, values[i].data(), values[i].size(), &napiValues[i]);
    }
    return napi_create_object_with_named_properties(env, result, property_count, keys, napiValues);
}

void CameraNapiUtils::CreateFrameRateJSArray(napi_env env, std::vector<int32_t> frameRateRange, napi_value &result)
{
    MEDIA_DEBUG_LOG("CreateFrameRateJSArray called");
    if (frameRateRange.empty()) {
        MEDIA_ERR_LOG("frameRateRange is empty");
    }
 
    napi_status status = napi_create_object(env, &result);
    if (status == napi_ok) {
        napi_value minRate;
        status = napi_create_int32(env, frameRateRange[0], &minRate);
        napi_value maxRate;
        status = napi_create_int32(env, frameRateRange[1], &maxRate);
        if (status != napi_ok || napi_set_named_property(env, result, "min", minRate) != napi_ok ||
            napi_set_named_property(env, result, "max", maxRate) != napi_ok) {
            MEDIA_ERR_LOG("Failed to create frameRateArray with napi wrapper object.");
        }
    }
}
 
napi_value CameraNapiUtils::CreateSupportFrameRatesJSArray(
    napi_env env, std::vector<std::vector<int32_t>> supportedFrameRatesRange)
{
    MEDIA_DEBUG_LOG("CreateFrameRateJSArray called");
    napi_value supportedFrameRateArray = nullptr;
    if (supportedFrameRatesRange.empty()) {
        MEDIA_ERR_LOG("frameRateRange is empty");
    }
 
    napi_status status = napi_create_array(env, &supportedFrameRateArray);
    if (status == napi_ok) {
        for (size_t i = 0; i < supportedFrameRatesRange.size(); i++) {
            napi_value supportedFrameRateItem;
            CreateFrameRateJSArray(env, supportedFrameRatesRange[i], supportedFrameRateItem);
            if (napi_set_element(env, supportedFrameRateArray, i, supportedFrameRateItem) != napi_ok) {
                MEDIA_ERR_LOG("Failed to create supportedFrameRateArray with napi wrapper object.");
                return nullptr;
            }
        }
    }
    return supportedFrameRateArray;
}
} // namespace CameraStandard
} // namespace OHOS
