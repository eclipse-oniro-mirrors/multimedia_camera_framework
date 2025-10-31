/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef FRAMEWORKS_TAIHE_INCLUDE_CAMERA_TEMPLATE_UTILS_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_CAMERA_TEMPLATE_UTILS_TAIHE_H

#include "taihe/runtime.hpp"
#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "camera_log.h"
#include "camera_utils_taihe.h"
#include "camera_event_emitter_taihe.h"

namespace Ani::Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;
using namespace OHOS;
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

    static std::map<std::string, T> GenString2EnumMap(const std::map<T, std::string>& enum2StringMap)
    {
        std::map<std::string, T> result;
        for (const auto& item : enum2StringMap) {
            result.emplace(std::make_pair(item.second, item.first));
        }
        return result;
    };
};

template<typename T, typename = std::enable_if_t<std::is_base_of_v<CameraAniEventEmitter<T>, T>>>
class ListenerTemplate {
public:
    static void On(T *obj, callback_view<void(uintptr_t)> callback, std::string callbackName)
    {
        MEDIA_DEBUG_LOG("On is called");
        CHECK_RETURN(obj == nullptr);
        std::shared_ptr<taihe::callback<void(uintptr_t)>> taiheCallback =
            std::make_shared<taihe::callback<void(uintptr_t)>>(callback);
        std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
        return obj->RegisterCallback(cacheCallback, callbackName, false);
    }

    template<typename E>
    static void On(T *obj, callback_view<void(uintptr_t, E)> callback, std::string callbackName)
    {
        MEDIA_DEBUG_LOG("On is called");
        CHECK_RETURN(obj == nullptr);
        std::shared_ptr<taihe::callback<void(uintptr_t, E)>> taiheCallback =
            std::make_shared<taihe::callback<void(uintptr_t, E)>>(callback);
        std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
        return obj->RegisterCallback(cacheCallback, callbackName, false);
    }

    template<typename E>
    static void On(T *obj, callback_view<void(E)> callback, std::string callbackName)
    {
        MEDIA_DEBUG_LOG("On is called");
        CHECK_RETURN(obj == nullptr);
        std::shared_ptr<taihe::callback<void(E)>> taiheCallback =
            std::make_shared<taihe::callback<void(E)>>(callback);
        std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
        return obj->RegisterCallback(cacheCallback, callbackName, false);
    }

    static void Off(T *obj, optional_view<callback<void(uintptr_t)>> callback, std::string callbackName)
    {
        MEDIA_DEBUG_LOG("Off eventType: %{public}s", callbackName.c_str());
        CHECK_RETURN(obj == nullptr);
        std::shared_ptr<uintptr_t> cacheCallback = nullptr;
        if (callback.has_value()) {
            std::shared_ptr<taihe::callback<void(uintptr_t)>> taiheCallback =
                std::make_shared<taihe::callback<void(uintptr_t)>>(callback.value());
            cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
        }
        return obj->UnregisterCallback(cacheCallback, callbackName);
    }

    template<typename E>
    static void Off(T *obj, optional_view<callback<void(uintptr_t, E)>> callback, std::string callbackName)
    {
        MEDIA_DEBUG_LOG("Off eventType: %{public}s", callbackName.c_str());
        CHECK_RETURN(obj == nullptr);
        std::shared_ptr<uintptr_t> cacheCallback = nullptr;
        if (callback.has_value()) {
            std::shared_ptr<taihe::callback<void(uintptr_t, E)>> taiheCallback =
                std::make_shared<taihe::callback<void(uintptr_t, E)>>(callback.value());
            cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
        }
        return obj->UnregisterCallback(cacheCallback, callbackName);
    }

    template<typename E>
    static void Off(T *obj, optional_view<callback<void(E)>> callback, std::string callbackName)
    {
        MEDIA_DEBUG_LOG("Off eventType: %{public}s", callbackName.c_str());
        CHECK_RETURN(obj == nullptr);
        std::shared_ptr<uintptr_t> cacheCallback = nullptr;
        if (callback.has_value()) {
            std::shared_ptr<taihe::callback<void(E)>> taiheCallback =
                std::make_shared<taihe::callback<void(E)>>(callback.value());
            cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
        }
        return obj->UnregisterCallback(cacheCallback, callbackName);
    }
};
} // namespace Ani::Camera

#endif // FRAMEWORKS_TAIHE_INCLUDE_CAMERA_TEMPLATE_UTILS_TAIHE_H