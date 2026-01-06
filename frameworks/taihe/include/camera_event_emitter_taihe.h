/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_CAMERA_EVENT_EMITTER_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_CAMERA_EVENT_EMITTER_TAIHE_H

#include <cstdint>

#include "camera_utils_taihe.h"

namespace Ani {
namespace Camera {
template<typename T>
class CameraAniEventEmitter {
public:
    typedef void (T::*RegisterFunc)(const std::string& eventName, std::shared_ptr<uintptr_t>, bool);
    typedef void (T::*UnregisterFunc)(const std::string& eventName, std::shared_ptr<uintptr_t>);
    typedef std::unordered_map<std::string, std::pair<RegisterFunc, UnregisterFunc>> EmitterFunctions;
    explicit CameraAniEventEmitter() = default;
    virtual ~CameraAniEventEmitter() = default;

    virtual const EmitterFunctions& GetEmitterFunctions() = 0;

    virtual void RegisterCallback(std::shared_ptr<uintptr_t> func, const std::string& callbackName, bool isOnce) final
    {
        MEDIA_DEBUG_LOG("CameraAniEventEmitter::RegisterCallback:%{public}s", callbackName.c_str());
        auto emitterFunctions = GetEmitterFunctions();
        auto it = emitterFunctions.find(callbackName);
        if (it != emitterFunctions.end()) {
            ((T*)this->*((RegisterFunc)it->second.first))(callbackName, func, isOnce);
        } else {
            MEDIA_ERR_LOG("Failed to Register Callback: Invalid event type");
            CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT,
                "Failed to Register Callback: Invalid event type");
            return;
        }
    }

    virtual void UnregisterCallback(std::shared_ptr<uintptr_t> func, const std::string& callbackName) final
    {
        MEDIA_DEBUG_LOG("CameraAniEventEmitter::UnregisterCallback functionName:%{public}s", callbackName.c_str());
        auto emitterFunctions = GetEmitterFunctions();
        auto it = emitterFunctions.find(callbackName);
        if (it != emitterFunctions.end()) {
            ((T*)this->*((UnregisterFunc)it->second.second))(callbackName, func);
        } else {
            MEDIA_ERR_LOG("Failed to Unregister Callback: Invalid event type");
            CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT,
                "Failed to Unregister Callback: Invalid event type");
            return;
        }
    }
};
} // namespace Camera
} // namespace Ani
#endif /* FRAMEWORKS_TAIHE_INCLUDE_CAMERA_EVENT_EMITTER_TAIHE_H */