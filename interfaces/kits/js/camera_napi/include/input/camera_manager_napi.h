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

#ifndef CAMERA_MANAGER_NAPI_H_
#define CAMERA_MANAGER_NAPI_H_

#include "display_type.h"
#include "hilog/log.h"

#include "input/camera_manager.h"
#include "input/camera_device.h"
#include "output/capture_output.h"

#include "input/camera_input_napi.h"
#include "input/camera_info_napi.h"
#include "output/camera_output_capability.h"
#include "output/preview_output_napi.h"
#include "output/photo_output_napi.h"
#include "output/video_output_napi.h"
#include "session/camera_session_napi.h"
#include "camera_napi_utils.h"
#include "camera_manager_callback_napi.h"
#include "camera_mute_listener_napi.h"
#include "torch_listener_napi.h"

namespace OHOS {
namespace CameraStandard {
static const char CAMERA_MANAGER_NAPI_CLASS_NAME[] = "CameraManager";

enum CameraManagerAsyncCallbackModes {
    CREATE_DEFERRED_PREVIEW_OUTPUT_ASYNC_CALLBACK,
};

class CameraManagerNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateCameraManager(napi_env env);
    static napi_value GetSupportedCameras(napi_env env, napi_callback_info info);
    static napi_value GetSupportedModes(napi_env env, napi_callback_info info);
    static napi_value GetSupportedOutputCapability(napi_env env, napi_callback_info info);
    static napi_value IsCameraMuted(napi_env env, napi_callback_info info);
    static napi_value IsCameraMuteSupported(napi_env env, napi_callback_info info);
    static napi_value MuteCamera(napi_env env, napi_callback_info info);
    static napi_value PrelaunchCamera(napi_env env, napi_callback_info info);
    static napi_value PreSwitchCamera(napi_env env, napi_callback_info info);
    static napi_value SetPrelaunchConfig(napi_env env, napi_callback_info info);
    static napi_value IsPrelaunchSupported(napi_env env, napi_callback_info info);
    static napi_value CreateCameraInputInstance(napi_env env, napi_callback_info info);
    static napi_value CreateCameraSessionInstance(napi_env env, napi_callback_info info);
    static napi_value CreateSessionInstance(napi_env env, napi_callback_info info);
    static napi_value CreatePreviewOutputInstance(napi_env env, napi_callback_info info);
    static napi_value CreateDeferredPreviewOutputInstance(napi_env env, napi_callback_info info);
    static napi_value CreatePhotoOutputInstance(napi_env env, napi_callback_info info);
    static napi_value CreateVideoOutputInstance(napi_env env, napi_callback_info info);
    static napi_value CreateMetadataOutputInstance(napi_env env, napi_callback_info info);
    static napi_value IsTorchSupported(napi_env env, napi_callback_info info);
    static napi_value IsTorchModeSupported(napi_env env, napi_callback_info info);
    static napi_value GetTorchMode(napi_env env, napi_callback_info info);
    static napi_value SetTorchMode(napi_env env, napi_callback_info info);
    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);
    static napi_value Once(napi_env env, napi_callback_info info);
    CameraManagerNapi();
    ~CameraManagerNapi();

private:
    static void CameraManagerNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value CameraManagerNapiConstructor(napi_env env, napi_callback_info info);
    static napi_value RegisterCallback(napi_env env, napi_value jsThis,
        const std::string &eventType, napi_value callback, bool isOnce);
    static napi_value UnregisterCallback(napi_env env, napi_value jsThis,
        const std::string &eventType, napi_value callback);
    static thread_local napi_ref sConstructor_;

    napi_env env_;
    napi_ref wrapper_;
    sptr<CameraManager> cameraManager_;
    std::shared_ptr<CameraManagerCallbackNapi> cameraManagerCallback_;
    std::shared_ptr<CameraMuteListenerNapi> cameraMuteListener_;
    static thread_local uint32_t cameraManagerTaskId;
};

struct CameraManagerContext : public AsyncContext {
    std::string surfaceId;
    CameraManagerNapi* managerInstance;
    Profile profile;
    VideoProfile videoProfile;
    CameraManagerAsyncCallbackModes modeForAsync;
    std::string errString;
    ~CameraManagerContext()
    {
        managerInstance = nullptr;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_MANAGER_NAPI_H_ */
