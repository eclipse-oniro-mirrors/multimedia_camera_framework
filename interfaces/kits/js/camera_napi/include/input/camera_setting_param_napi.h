/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
#ifndef CAMERA_SETTING_PARAM_NAPI_H
#define CAMERA_SETTING_PARAM_NAPI_H

#include "camera_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "hilog/log.h"
#include "camera_napi_utils.h"
#include "input/camera_input.h"
#include "input/prelaunch_config.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

namespace OHOS {
namespace CameraStandard {
static const char CAMERA_SETTINGPARAM_NAPI_CLASS_NAME[] = "SettingParam";

class CameraSettingParamNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateCameraSettingParam(napi_env env, SettingParam &cameraSettingParam);

    static napi_value GetCameraSmoothLevel(napi_env env, napi_callback_info info);
    static napi_value GetCameraFaceSlender(napi_env env, napi_callback_info info);
    static napi_value GetCameraSkinTone(napi_env env, napi_callback_info info);

    CameraSettingParamNapi();
    ~CameraSettingParamNapi();
    SettingParam* cameraSettingParam_;

private:
    static void CameraSettingParamNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value CameraSettingParamNapiConstructor(napi_env env, napi_callback_info info);

    napi_env env_;
    napi_ref wrapper_;

    static thread_local napi_ref sConstructor_;
    static thread_local SettingParam* sCameraSettingParam_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif
