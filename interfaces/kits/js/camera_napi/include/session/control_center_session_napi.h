/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef CONTROL_CENTER_SESSION_NAPI_H
#define CONTROL_CENTER_SESSION_NAPI_H

#include "camera_napi_utils.h"
#include "control_center_session.h"
#include "js_native_api_types.h"
#include "refbase.h"

namespace OHOS {
namespace CameraStandard {
 
static const char CONTROL_CENTER_SESSION_NAPI_CLASS_NAME[] = "ControlCenterSession";
 
class ControlCenterSessionNapi {
public:
    static void Init(napi_env env);
    static napi_value CreateControlCenterSession(napi_env env);
    ControlCenterSessionNapi();
    ~ControlCenterSessionNapi();
 
    static void ControlCenterSessionDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value ControlCenterSessionConstructor(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);

    static napi_value GetSupportedVirtualApertures(napi_env env, napi_callback_info info);
    static napi_value GetVirtualAperture(napi_env env, napi_callback_info info);
    static napi_value SetVirtualAperture(napi_env env, napi_callback_info info);

    static napi_value GetSupportedPhysicalApertures(napi_env env, napi_callback_info info);
    static napi_value GetPhysicalAperture(napi_env env, napi_callback_info info);
    static napi_value SetPhysicalAperture(napi_env env, napi_callback_info info);

    static napi_value GetSupportedBeautyTypes(napi_env env, napi_callback_info info);
    static napi_value GetSupportedBeautyRange(napi_env env, napi_callback_info info);
    static napi_value GetBeauty(napi_env env, napi_callback_info info);
    static napi_value SetBeauty(napi_env env, napi_callback_info info);
    static napi_value GetSupportedPortraitThemeTypes(napi_env env, napi_callback_info info);
    static napi_value IsPortraitThemeSupported(napi_env env, napi_callback_info info);
    static napi_value SetPortraitThemeType(napi_env env, napi_callback_info info);
private:
    napi_env env_;
    sptr<ControlCenterSession> controlCenterSession_;
    static thread_local napi_ref sConstructor_;
    static thread_local sptr<ControlCenterSession> sControlCenterSession_;
    static thread_local uint32_t controlCenterSessionTaskId;
};

struct ControlCenterSessionAsyncContext : public AsyncContext {
    ControlCenterSessionAsyncContext(std::string funcName, int32_t taskId) : AsyncContext(funcName, taskId) {};
    ControlCenterSessionNapi* objectInfo = nullptr;
    std::string errorMsg;
    napi_env env = nullptr;
};
 
} // namespace CameraStandard
} // namespace OHOS

#endif /* CONTROL_CENTER_SESSION_NAPI_H */