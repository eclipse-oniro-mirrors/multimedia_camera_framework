/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "native_module_ohos_camera.h"

#include "input/camera_input_napi.h"
#include "input/camera_manager_napi.h"
#include "input/camera_napi.h"
#include "mode/aperture_video_session_napi.h"
#include "mode/fluorescence_photo_session_napi.h"
#include "mode/high_res_photo_session_napi.h"
#include "mode/light_painting_session_napi.h"
#include "mode/macro_photo_session_napi.h"
#include "mode/macro_video_session_napi.h"
#include "mode/mode_manager_napi.h"
#include "mode/night_session_napi.h"
#include "mode/panorama_session_napi.h"
#include "mode/photo_session_for_sys_napi.h"
#include "mode/photo_session_napi.h"
#include "mode/portrait_session_napi.h"
#include "mode/profession_session_napi.h"
#include "mode/quick_shot_photo_session_napi.h"
#include "mode/secure_camera_session_napi.h"
#include "mode/slow_motion_session_napi.h"
#include "mode/time_lapse_photo_session_napi.h"
#include "mode/video_session_for_sys_napi.h"
#include "mode/video_session_napi.h"
#include "output/deferred_photo_proxy_napi.h"
#include "output/depth_data_napi.h"
#include "output/depth_data_output_napi.h"
#include "output/photo_napi.h"
#include "output/photo_output_napi.h"
#include "output/preview_output_napi.h"
#include "output/video_output_napi.h"
#include "session/camera_session_napi.h"
#include "ability/camera_ability_napi.h"

namespace OHOS {
namespace CameraStandard {
/*
 * Function registering all props and functions of ohos.camera module
 */
static napi_value Export(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Export called()");
    CameraInputNapi::Init(env, exports);
    PreviewOutputNapi::Init(env, exports);
    PhotoOutputNapi::Init(env, exports);
    VideoOutputNapi::Init(env, exports);
    DepthDataOutputNapi::Init(env, exports);
    DepthDataNapi::Init(env, exports);
    CameraSessionNapi::Init(env, exports);
    CameraManagerNapi::Init(env, exports);
    CameraNapi::Init(env, exports);
    MetadataOutputNapi::Init(env, exports);
    HighResPhotoSessionNapi::Init(env, exports);
    PanoramaSessionNapi::Init(env, exports);
    PortraitSessionNapi::Init(env, exports);
    ProfessionSessionNapi::Init(env, exports);
    NightSessionNapi::Init(env, exports);
    PhotoSessionNapi::Init(env, exports);
    PhotoSessionForSysNapi::Init(env, exports);
    VideoSessionNapi::Init(env, exports);
    VideoSessionForSysNapi::Init(env, exports);
    CameraFunctionsNapi::Init(env, exports, FunctionsType::PHOTO_FUNCTIONS);
    CameraFunctionsNapi::Init(env, exports, FunctionsType::VIDEO_FUNCTIONS);
    CameraFunctionsNapi::Init(env, exports, FunctionsType::PORTRAIT_PHOTO_FUNCTIONS);
    CameraFunctionsNapi::Init(env, exports, FunctionsType::PHOTO_CONFLICT_FUNCTIONS);
    CameraFunctionsNapi::Init(env, exports, FunctionsType::VIDEO_CONFLICT_FUNCTIONS);
    CameraFunctionsNapi::Init(env, exports, FunctionsType::PORTRAIT_PHOTO_CONFLICT_FUNCTIONS);
    SlowMotionSessionNapi::Init(env, exports);
    MacroPhotoSessionNapi::Init(env, exports);
    MacroVideoSessionNapi::Init(env, exports);
    ModeManagerNapi::Init(env, exports);
    PhotoNapi::Init(env, exports);
    DeferredPhotoProxyNapi::Init(env, exports);
    SecureCameraSessionNapi::Init(env, exports);
    QuickShotPhotoSessionNapi::Init(env, exports);
    ApertureVideoSessionNapi::Init(env, exports);
    FluorescencePhotoSessionNapi::Init(env, exports);
    LightPaintingSessionNapi::Init(env, exports);
    TimeLapsePhotoSessionNapi::Init(env, exports);
    TryAEInfoNapi::Init(env, exports);
    MEDIA_DEBUG_LOG("Export is end");
    return exports;
}

/*
 * module define
 */
static napi_module g_module = { .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Export,
    .nm_modname = "multimedia.camera",
    .nm_priv = (reinterpret_cast<void*>(0)),
    .reserved = { 0 } };

/*
 * module register
 */
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    MEDIA_DEBUG_LOG("RegisterModule is called");
    napi_module_register(&g_module);
}
} // namespace CameraStandard
} // namespace OHOS
