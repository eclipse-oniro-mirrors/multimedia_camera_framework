/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef CAMERA_PROFILE_NAPI_H_
#define CAMERA_PROFILE_NAPI_H_

#include "camera_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "hilog/log.h"
#include "camera_napi_utils.h"
#include "input/camera_input.h"
#include "output/camera_output_capability.h"

#include "camera_size_napi.h"

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
static const char CAMERA_PROFILE_NAPI_CLASS_NAME[] = "ProfileNapi";
static const char CAMERA_VIDEO_PROFILE_NAPI_CLASS_NAME[] = "VideoProfileNapi";
class CameraProfileNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateCameraProfile(napi_env env, Profile &profile);
    static napi_value GetCameraProfileFormat(napi_env env, napi_callback_info info);
    static napi_value GetCameraProfileSize(napi_env env, napi_callback_info info);

    CameraProfileNapi();
    ~CameraProfileNapi();

    Profile* cameraProfile_;
    static thread_local Profile* sCameraProfile_;

private:
    static void CameraProfileNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value CameraProfileNapiConstructor(napi_env env, napi_callback_info info);

    napi_env env_;
    napi_ref wrapper_;

    static thread_local napi_ref sConstructor_;
};

class CameraVideoProfileNapi : public CameraProfileNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateCameraVideoProfile(napi_env env, VideoProfile &profile);
    static napi_value GetCameraProfileFormat(napi_env env, napi_callback_info info);
    static napi_value GetCameraProfileSize(napi_env env, napi_callback_info info);
    static napi_value GetFrameRateRange(napi_env env, napi_callback_info info);

    CameraVideoProfileNapi();
    ~CameraVideoProfileNapi();

    VideoProfile videoProfile_;
private:
    static void CameraVideoProfileNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value CameraVideoProfileNapiConstructor(napi_env env, napi_callback_info info);

    napi_env env_;
    napi_ref wrapper_;

    static thread_local VideoProfile sVideoProfile_;
    static thread_local napi_ref sVideoConstructor_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_PROFILE_NAPI_H_ */
