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

#ifndef CAMERA_OUTPUT_CAPABILITY_NAPI_H
#define CAMERA_OUTPUT_CAPABILITY_NAPI_H

#include "camera_device.h"
#include "capture_scene_const.h"
#include "napi/native_api.h"

namespace OHOS {
namespace CameraStandard {
static const char CAMERA_OUTPUT_CAPABILITY_NAPI_CLASS_NAME[] = "CameraOutputCapability";

class CameraOutputCapabilityNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateCameraOutputCapability(napi_env env, sptr<CameraDevice> camera);
    static napi_value CreateCameraOutputCapability(napi_env env, sptr<CameraDevice> camera, SceneMode mode);

    CameraOutputCapabilityNapi();
    ~CameraOutputCapabilityNapi();

    sptr<CameraOutputCapability> cameraOutputCapability_;
    static thread_local sptr<CameraOutputCapability> sCameraOutputCapability_;

private:
    static void CameraOutputCapabilityNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value CameraOutputCapabilityNapiConstructor(napi_env env, napi_callback_info info);

    static napi_value GetPreviewProfiles(napi_env env, napi_callback_info info);
    static napi_value GetPhotoProfiles(napi_env env, napi_callback_info info);
    static napi_value GetVideoProfiles(napi_env env, napi_callback_info info);
    static napi_value GetSupportedMetadataObjectTypes(napi_env env, napi_callback_info info);

    napi_env env_;
    napi_ref wrapper_;
    static thread_local napi_ref sCapabilityConstructor_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_OUTPUT_CAPABILITY_NAPI_H */