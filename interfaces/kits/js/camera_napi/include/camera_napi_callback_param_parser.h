/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef CAMERA_NAPI_CALLBACK_PARAM_PARSER_H
#define CAMERA_NAPI_CALLBACK_PARAM_PARSER_H

#include <cstddef>
#include <cstdint>

#include "camera_error_code.h"
#include "camera_napi_const.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace CameraStandard {

class CameraNapiCallbackParamParser {
public:
    template<typename T>
    explicit CameraNapiCallbackParamParser(napi_env env, napi_callback_info info, T*& nativeObjPointer) : env_(env)
    {
        static const size_t CALLBACK_ARGS_MIN = 1;
        napi_value thisVar;
        size_t paramSize = ARGS_MAX_SIZE;
        std::vector<napi_value> paramValue(paramSize, nullptr);
        napiError = napi_get_cb_info(env_, info, &paramSize, paramValue.data(), &thisVar, nullptr);
        if (napiError != napi_ok) {
            return;
        }
        UnwrapThisVarToAddr(thisVar, nativeObjPointer);
        if (napiError != napi_ok) {
            return;
        }
        if (paramSize > ARGS_MAX_SIZE || paramSize < CALLBACK_ARGS_MIN) {
            napiError = napi_status::napi_invalid_arg;
            return;
        }

        napi_valuetype valueNapiType = napi_undefined;
        napi_typeof(env_, paramValue[ARGS_ZERO], &valueNapiType);
        if (valueNapiType != napi_string) {
            napiError = napi_status::napi_invalid_arg;
            return;
        }
        if (paramSize > 1) {
            napi_typeof(env_, paramValue[paramSize - 1], &valueNapiType);
            if (valueNapiType != napi_function) {
                napiError = napi_status::napi_invalid_arg;
                return;
            }
            callbackFunction_ = paramValue[paramSize - 1];
            if (paramSize > CALLBACK_ARGS_MIN + 1) {
                callbackFunctionParameters_ =
                    std::vector<napi_value>(paramValue.begin() + 1, paramValue.begin() + paramSize - 1);
            }
        }
        size_t stringSize = 0;
        napiError = napi_get_value_string_utf8(env_, paramValue[ARGS_ZERO], nullptr, 0, &stringSize);
        if (napiError != napi_ok) {
            return;
        }
        callbackName_.resize(stringSize);
        napiError =
            napi_get_value_string_utf8(env_, paramValue[ARGS_ZERO], callbackName_.data(), stringSize + 1, &stringSize);
    }

    bool AssertStatus(CameraErrorCode errorCode, const char* message);

    inline const std::string& GetCallbackName()
    {
        return callbackName_;
    }

    inline const std::vector<napi_value>& GetCallbackArgs()
    {
        return callbackFunctionParameters_;
    }

    inline napi_value GetCallbackFunction()
    {
        return callbackFunction_;
    }

private:
    template<typename T>
    void UnwrapThisVarToAddr(napi_value thisVar, T*& dataPointAddr)
    {
        if (napiError != napi_ok) {
            return;
        }
        if (thisVar == nullptr) {
            napiError = napi_invalid_arg;
            return;
        }
        napiError = napi_unwrap(env_, thisVar, reinterpret_cast<void**>(&dataPointAddr));
        if (napiError == napi_ok && dataPointAddr == nullptr) {
            napiError = napi_invalid_arg;
        }
    }

    napi_env env_ = nullptr;

    napi_status napiError = napi_status::napi_invalid_arg;

    std::string callbackName_ = "";
    napi_value callbackFunction_ = nullptr;
    std::vector<napi_value> callbackFunctionParameters_ {};
};
} // namespace CameraStandard
} // namespace OHOS
#endif