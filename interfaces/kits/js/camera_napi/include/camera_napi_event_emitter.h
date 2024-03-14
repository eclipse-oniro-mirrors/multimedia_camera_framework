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

#ifndef CAMERA_NAPI_EVENT_EMITTER_H
#define CAMERA_NAPI_EVENT_EMITTER_H

#include <stdint.h>

#include "camera_log.h"
#include "camera_napi_callback_param_parser.h"
#include "camera_napi_utils.h"
namespace OHOS {
namespace CameraStandard {

template<typename T>
class CameraNapiEventEmitter {
public:
    typedef void (T::*RegisterFun)(napi_env, napi_value, const std::vector<napi_value>&, bool);
    typedef void (T::*UnregisterFun)(napi_env, napi_value, const std::vector<napi_value>&);
    typedef std::unordered_map<std::string, std::pair<RegisterFun, UnregisterFun>> EmitterFunctions;
    explicit CameraNapiEventEmitter() = default;
    virtual ~CameraNapiEventEmitter() = default;

    virtual const EmitterFunctions& GetEmitterFunctions() = 0;

    virtual napi_value RegisterCallback(napi_env env, CameraNapiCallbackParamParser& jsCbParser, bool isOnce) final
    {
        MEDIA_INFO_LOG("CameraNapiEventEmitter::RegisterCallback:%{public}s", jsCbParser.GetCallbackName().c_str());
        auto emitterFunctions = GetEmitterFunctions();
        auto it = emitterFunctions.find(jsCbParser.GetCallbackName());
        if (it != emitterFunctions.end()) {
            ((T*)this->*((RegisterFun)it->second.first))(
                env, jsCbParser.GetCallbackFunction(), jsCbParser.GetCallbackArgs(), isOnce);
        } else {
            MEDIA_ERR_LOG("Failed to Register Callback: Invalid event type");
            CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "Failed to Register Callback: Invalid event type");
            return nullptr;
        }
        return CameraNapiUtils::GetUndefinedValue(env);
    }

    virtual napi_value UnregisterCallback(napi_env env, CameraNapiCallbackParamParser& jsCbParser) final
    {
        MEDIA_INFO_LOG(
            "CameraNapiEventEmitter::UnregisterCallback functionName:%{public}s", jsCbParser.GetCallbackName().c_str());
        auto emitterFunctions = GetEmitterFunctions();
        auto it = emitterFunctions.find(jsCbParser.GetCallbackName());
        if (it != emitterFunctions.end()) {
            ((T*)this->*((UnregisterFun)it->second.second))(
                env, jsCbParser.GetCallbackFunction(), jsCbParser.GetCallbackArgs());
        } else {
            MEDIA_ERR_LOG("Failed to Unregister Callback: Invalid event type");
            CameraNapiUtils::ThrowError(env, INVALID_ARGUMENT, "Failed to Unregister Callback: Invalid event type");
            return nullptr;
        }
        return CameraNapiUtils::GetUndefinedValue(env);
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_NAPI_EVENT_EMITTER_H_ */
