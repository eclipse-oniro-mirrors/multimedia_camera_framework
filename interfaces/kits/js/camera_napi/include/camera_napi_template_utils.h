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

#ifndef CAMERA_NAPI_TEMPLATE_UTILS_H
#define CAMERA_NAPI_TEMPLATE_UTILS_H

#include <map>

#include "camera_log.h"
#include "camera_napi_utils.h"

namespace OHOS {
namespace CameraStandard {
template<typename T>
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

template<class T>
class ListenerTemplate {
public:
    static napi_value On(napi_env env, napi_callback_info info)
    {
        MEDIA_INFO_LOG("On is called");
        CAMERA_SYNC_TRACE;
        napi_value undefinedResult = nullptr;
        size_t argCount = ARGS_TWO;
        napi_value argv[ARGS_TWO] = { nullptr, nullptr };
        napi_value thisVar = nullptr;

        napi_get_undefined(env, &undefinedResult);

        CAMERA_NAPI_GET_JS_ARGS(env, info, argCount, argv, thisVar);
        NAPI_ASSERT(env, argCount == ARGS_TWO, "requires 2 parameters");

        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string ||
            napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function) {
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
        napi_value argv[ARGS_TWO] = { nullptr, nullptr };
        napi_value thisVar = nullptr;

        napi_get_undefined(env, &undefinedResult);

        CAMERA_NAPI_GET_JS_ARGS(env, info, argCount, argv, thisVar);
        NAPI_ASSERT(env, argCount == ARGS_TWO, "requires 2 parameters");

        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string ||
            napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function) {
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
        napi_value argv[ARGS_TWO] = { nullptr, nullptr };
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
#endif /* CAMERA_NAPI_TEMPLATE_UTILS_H */