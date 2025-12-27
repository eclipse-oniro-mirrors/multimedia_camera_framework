/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_CAMERA_CONST_ABILITY_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_CAMERA_CONST_ABILITY_TAIHE_H

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "taihe/runtime.hpp"
#include "capture_scene_const.h"
#include "camera_device.h"
#include "capture_session.h"
#include "istream_metadata.h"
#include "video_session.h"
#include "time_lapse_photo_session.h"
#include "slow_motion_session.h"
#include "camera_manager.h"


namespace Ani::Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;
using namespace OHOS;

constexpr char CLASS_NAME_BUSINESSERROR[] = "@ohos.base.BusinessError";
constexpr char CLASS_NAME_BOOLEAN[] = "std.core.Boolean";
constexpr char ENUM_NAME_COLORSPACE[] = "@ohos.graphics.colorSpaceManager.colorSpaceManager.ColorSpace";

const std::unordered_map<OHOS::CameraStandard::SceneMode, SceneMode> g_nativeToAniSupportedMode = {
    {OHOS::CameraStandard::SceneMode::CAPTURE, SceneMode::key_t::NORMAL_PHOTO},
    {OHOS::CameraStandard::SceneMode::VIDEO, SceneMode::key_t::NORMAL_VIDEO},
    {OHOS::CameraStandard::SceneMode::SECURE, SceneMode::key_t::SECURE_PHOTO},
};

const std::unordered_map<OHOS::CameraStandard::SceneMode, SceneMode> g_nativeToAniSupportedModeSys = {
    {OHOS::CameraStandard::SceneMode::CAPTURE, SceneMode::key_t::NORMAL_PHOTO},
    {OHOS::CameraStandard::SceneMode::VIDEO, SceneMode::key_t::NORMAL_VIDEO},
    {OHOS::CameraStandard::SceneMode::PORTRAIT, SceneMode::key_t::PORTRAIT_PHOTO},
    {OHOS::CameraStandard::SceneMode::NIGHT, SceneMode::key_t::NIGHT_PHOTO},
    {OHOS::CameraStandard::SceneMode::PROFESSIONAL_PHOTO, SceneMode::key_t::PROFESSIONAL_PHOTO},
    {OHOS::CameraStandard::SceneMode::PROFESSIONAL_VIDEO, SceneMode::key_t::PROFESSIONAL_VIDEO},
    {OHOS::CameraStandard::SceneMode::SLOW_MOTION, SceneMode::key_t::SLOW_MOTION_VIDEO},
    {OHOS::CameraStandard::SceneMode::CAPTURE_MACRO, SceneMode::key_t::MACRO_PHOTO},
    {OHOS::CameraStandard::SceneMode::VIDEO_MACRO, SceneMode::key_t::MACRO_VIDEO},
    {OHOS::CameraStandard::SceneMode::LIGHT_PAINTING, SceneMode::key_t::LIGHT_PAINTING_PHOTO},
    {OHOS::CameraStandard::SceneMode::HIGH_RES_PHOTO, SceneMode::key_t::HIGH_RESOLUTION_PHOTO},
    {OHOS::CameraStandard::SceneMode::SECURE, SceneMode::key_t::SECURE_PHOTO},
    {OHOS::CameraStandard::SceneMode::QUICK_SHOT_PHOTO, SceneMode::key_t::QUICK_SHOT_PHOTO},
    {OHOS::CameraStandard::SceneMode::APERTURE_VIDEO, SceneMode::key_t::APERTURE_VIDEO},
    {OHOS::CameraStandard::SceneMode::PANORAMA_PHOTO, SceneMode::key_t::PANORAMA_PHOTO},
    {OHOS::CameraStandard::SceneMode::TIMELAPSE_PHOTO, SceneMode::key_t::TIME_LAPSE_PHOTO},
    {OHOS::CameraStandard::SceneMode::FLUORESCENCE_PHOTO, SceneMode::key_t::FLUORESCENCE_PHOTO},
};

const std::unordered_map<int32_t, OHOS::CameraStandard::SceneMode> g_aniToNativeSupportedMode = {
    {1, OHOS::CameraStandard::SceneMode::CAPTURE},
    {2, OHOS::CameraStandard::SceneMode::VIDEO},
    {12, OHOS::CameraStandard::SceneMode::SECURE},
};

const std::unordered_map<int32_t, OHOS::CameraStandard::SceneMode> g_aniToNativeSupportedModeSys = {
    {1, OHOS::CameraStandard::SceneMode::CAPTURE},
    {2, OHOS::CameraStandard::SceneMode::VIDEO},
    {3, OHOS::CameraStandard::SceneMode::PORTRAIT},
    {4, OHOS::CameraStandard::SceneMode::NIGHT},
    {5, OHOS::CameraStandard::SceneMode::PROFESSIONAL_PHOTO},
    {6, OHOS::CameraStandard::SceneMode::PROFESSIONAL_VIDEO},
    {7, OHOS::CameraStandard::SceneMode::SLOW_MOTION},
    {8, OHOS::CameraStandard::SceneMode::CAPTURE_MACRO},
    {9, OHOS::CameraStandard::SceneMode::VIDEO_MACRO},
    {10, OHOS::CameraStandard::SceneMode::LIGHT_PAINTING},
    {11, OHOS::CameraStandard::SceneMode::HIGH_RES_PHOTO},
    {12, OHOS::CameraStandard::SceneMode::SECURE},
    {13, OHOS::CameraStandard::SceneMode::QUICK_SHOT_PHOTO},
    {14, OHOS::CameraStandard::SceneMode::APERTURE_VIDEO},
    {15, OHOS::CameraStandard::SceneMode::PANORAMA_PHOTO},
    {16, OHOS::CameraStandard::SceneMode::TIMELAPSE_PHOTO},
    {17, OHOS::CameraStandard::SceneMode::FLUORESCENCE_PHOTO},
};

const std::unordered_map<OHOS::CameraStandard::MacroStatusCallback::MacroStatus, bool> g_nativeToAniMacroStatus = {
    {OHOS::CameraStandard::MacroStatusCallback::MacroStatus::IDLE, false},
    {OHOS::CameraStandard::MacroStatusCallback::MacroStatus::ACTIVE, true},
    {OHOS::CameraStandard::MacroStatusCallback::MacroStatus::UNKNOWN, true},
};

const std::unordered_map<int32_t, OHOS::CameraStandard::PolicyType> g_jsToFwPolicyType = {
    {1, OHOS::CameraStandard::PolicyType::PRIVACY},
};
} // namespace Ani::Camera

#endif // FRAMEWORKS_TAIHE_INCLUDE_CAMERA_CONST_ABILITY_TAIHE_H
