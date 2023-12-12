/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef CAMERA_PRE_LAUNCH_CONFIG_NAPI_H
#define CAMERA_PRE_LAUNCH_CONFIG_NAPI_H

#include "hilog/log.h"
#include "camera_napi_utils.h"
#include "input/camera_setting_param_napi.h"
#include "input/prelaunch_config.h"

namespace OHOS {
namespace CameraStandard {
static const char CAMERA_PRELAUNCH_CONFIG_NAPI_CLASS_NAME[] = "PrelauncherConfig";

class CameraPrelaunchConfigNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value GetPrelaunchCameraDevice(napi_env env, napi_callback_info info);
    static napi_value GetRestoreParamType(napi_env env, napi_callback_info info);
    static napi_value GetActiveTime(napi_env env, napi_callback_info info);
    static napi_value GetSettingParam(napi_env env, napi_callback_info info);
    CameraPrelaunchConfigNapi();
    ~CameraPrelaunchConfigNapi();
    PrelaunchConfig* prelaunchConfig_;
    static thread_local PrelaunchConfig* sPrelaunchConfig_;

private:
    static void CameraPrelaunchConfigNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value CameraPrelaunchConfigNapiConstructor(napi_env env, napi_callback_info info);
    napi_env env_;
    napi_ref wrapper_;

    static thread_local napi_ref sConstructor_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_PRE_LAUNCH_CONFIG_NAPI_H
