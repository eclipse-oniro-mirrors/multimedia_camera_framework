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

#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_napi_const.h"
#include "camera_napi_event_emitter.h"
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

    const std::string& GetKeyString(T enumValue)
    {
        const static std::string EMPTY_STRING = "";
        auto item = _mapEnum2String.find(enumValue);
        if (item == _mapEnum2String.end()) {
            return EMPTY_STRING;
        }
        return item->second;
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

template<typename T, typename = std::enable_if_t<std::is_base_of_v<CameraNapiEventEmitter<T>, T>>>
class ListenerTemplate {
public:
    static napi_value On(napi_env env, napi_callback_info info)
    {
        MEDIA_INFO_LOG("On is called");
        CAMERA_SYNC_TRACE;

        T* targetInstance = nullptr;
        CameraNapiCallbackParamParser jsCallbackParamParser(env, info, targetInstance);
        if (!jsCallbackParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
            MEDIA_ERR_LOG("On get invalid argument");
            return nullptr;
        }
        MEDIA_INFO_LOG("On eventType: %{public}s", jsCallbackParamParser.GetCallbackName().c_str());

        return targetInstance->RegisterCallback(env, jsCallbackParamParser, false);
    }

    static napi_value Once(napi_env env, napi_callback_info info)
    {
        MEDIA_INFO_LOG("Once is called");
        CAMERA_SYNC_TRACE;
        T* targetInstance = nullptr;
        CameraNapiCallbackParamParser jsCallbackParamParser(env, info, targetInstance);
        if (!jsCallbackParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
            MEDIA_ERR_LOG("On get invalid argument");
            return nullptr;
        }

        MEDIA_INFO_LOG("Once eventType: %{public}s", jsCallbackParamParser.GetCallbackName().c_str());
        return targetInstance->RegisterCallback(env, jsCallbackParamParser, true);
    }

    static napi_value Off(napi_env env, napi_callback_info info)
    {
        MEDIA_INFO_LOG("Off is called");
        CAMERA_SYNC_TRACE;
        T* targetInstance = nullptr;
        CameraNapiCallbackParamParser jsCallbackParamParser(env, info, targetInstance);
        if (!jsCallbackParamParser.AssertStatus(INVALID_ARGUMENT, "invalid argument")) {
            MEDIA_ERR_LOG("On get invalid argument");
            return nullptr;
        }
        MEDIA_INFO_LOG("Off eventType: %{public}s", jsCallbackParamParser.GetCallbackName().c_str());
        return targetInstance->UnregisterCallback(env, jsCallbackParamParser);
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_NAPI_TEMPLATE_UTILS_H */