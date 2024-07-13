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

#ifndef CAMERA_NAPI_POST_PROCESS_UTILS_H
#define CAMERA_NAPI_POST_PROCESS_UTILS_H

#include <stdint.h>
#include "camera_log.h"
#include "camera_napi_utils.h"
#include "napi/native_common.h"
#include "napi/native_api.h"

namespace OHOS {
namespace CameraStandard {
template<typename T>
class CameraAbilityProcessor {
public:
    template <typename U>
    static napi_value HandleQuery(napi_env env, napi_callback_info info, napi_value thisVar, U queryFunction)
    {
        napi_status status;
        napi_value result = nullptr;
        napi_get_undefined(env, &result);
        T* napiObj = nullptr;
        status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&napiObj));
        if (status == napi_ok && napiObj != nullptr && napiObj->GetNativeObj() != nullptr) {
            auto queryResult = queryFunction(napiObj->GetNativeObj());
            if constexpr(std::is_same_v<decltype(queryResult), bool>) {
                napi_get_boolean(env, queryResult, &result);
            } else if constexpr(std::is_same_v<decltype(queryResult), std::vector<int32_t>>
                            || std::is_enum_v<typename decltype(queryResult)::value_type>) {
                status = napi_create_array(env, &result);
                if (status != napi_ok) {
                    MEDIA_ERR_LOG("napi_create_array call Failed!");
                    return result;
                }
                for (size_t i = 0; i < queryResult.size(); i++) {
                    int32_t value = queryResult[i];
                    napi_value element;
                    napi_create_int32(env, value, &element);
                    napi_set_element(env, result, i, element);
                }
            } else if constexpr(std::is_same_v<decltype(queryResult), std::vector<float>>) {
                status = napi_create_array(env, &result);
                if (status != napi_ok) {
                    MEDIA_ERR_LOG("napi_create_array call Failed!");
                    return result;
                }
                for (size_t i = 0; i < queryResult.size(); i++) {
                    float value = queryResult[i];
                    napi_value element;
                    napi_create_double(env, CameraNapiUtils::FloatToDouble(value), &element);
                    napi_set_element(env, result, i, element);
                }
            } else {
                MEDIA_ERR_LOG("Unhandled type in HandleQuery");
            }
        } else {
            MEDIA_ERR_LOG("Query function call Failed!");
        }
        return result;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_NAPI_POST_PROCESS_UTILS_H */
