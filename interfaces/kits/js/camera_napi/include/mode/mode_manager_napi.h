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

#ifndef MODE_MANAGER_NAPI_H_
#define MODE_MANAGER_NAPI_H_

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
#include "portrait_session_napi.h"
#include "photo_session_napi.h"
#include "night_session_napi.h"
#include "video_session_napi.h"
#include "secure_camera_session_napi.h"
#include "session/camera_session_napi.h"
#include "camera_napi_utils.h"

namespace OHOS {
namespace CameraStandard {
static const char MODE_MANAGER_NAPI_CLASS_NAME[] = "ModeManager";

enum ModeManagerAsyncCallbackModes {
    MODEMANAGER_CREATE_DEFERRED_PREVIEW_OUTPUT_ASYNC_CALLBACK,
};

class ModeManagerNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);

    static napi_value CreateModeManager(napi_env env);
    static napi_value GetSupportedOutputCapability(napi_env env, napi_callback_info info);
    static napi_value GetSupportedModes(napi_env env, napi_callback_info info);
    static napi_value CreateCameraSessionInstance(napi_env env, napi_callback_info info);

    static napi_value On(napi_env env, napi_callback_info info);

    ModeManagerNapi();
    ~ModeManagerNapi();

private:
    static void ModeManagerNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value ModeManagerNapiConstructor(napi_env env, napi_callback_info info);

    static thread_local napi_ref sConstructor_;

    napi_env env_;
    napi_ref wrapper_;
    sptr<CameraManager> modeManager_;

    static thread_local uint32_t modeManagerTaskId;
};

struct ModeManagerContext : public AsyncContext {
    std::string surfaceId;
    ModeManagerNapi* modeManagerInstance;
    ModeManagerAsyncCallbackModes modeForAsync;
    std::string errString;
    ~ModeManagerContext()
    {
        modeManagerInstance = nullptr;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* MODE_MANAGER_NAPI_H_ */
