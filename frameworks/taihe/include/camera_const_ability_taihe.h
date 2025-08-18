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

const std::unordered_map<OHOS::CameraStandard::CameraPosition, CameraPosition> g_nativeToAniCameraPosition = {
    {OHOS::CameraStandard::CameraPosition::CAMERA_POSITION_UNSPECIFIED,
        CameraPosition::key_t::CAMERA_POSITION_UNSPECIFIED},
    {OHOS::CameraStandard::CameraPosition::CAMERA_POSITION_BACK, CameraPosition::key_t::CAMERA_POSITION_BACK},
    {OHOS::CameraStandard::CameraPosition::CAMERA_POSITION_FRONT, CameraPosition::key_t::CAMERA_POSITION_FRONT},
    {OHOS::CameraStandard::CameraPosition::CAMERA_POSITION_FOLD_INNER,
        CameraPosition::key_t::CAMERA_POSITION_FOLD_INNER},
};

const std::unordered_map<OHOS::CameraStandard::CameraType, CameraType> g_nativeToAniCameraType = {
    {OHOS::CameraStandard::CameraType::CAMERA_TYPE_DEFAULT, CameraType::key_t::CAMERA_TYPE_DEFAULT},
    {OHOS::CameraStandard::CameraType::CAMERA_TYPE_WIDE_ANGLE, CameraType::key_t::CAMERA_TYPE_WIDE_ANGLE},
    {OHOS::CameraStandard::CameraType::CAMERA_TYPE_ULTRA_WIDE, CameraType::key_t::CAMERA_TYPE_ULTRA_WIDE},
    {OHOS::CameraStandard::CameraType::CAMERA_TYPE_TELEPHOTO, CameraType::key_t::CAMERA_TYPE_TELEPHOTO},
    {OHOS::CameraStandard::CameraType::CAMERA_TYPE_TRUE_DEPTH, CameraType::key_t::CAMERA_TYPE_TRUE_DEPTH},
};

const std::unordered_map<OHOS::CameraStandard::SceneFeature, SceneFeatureType> g_nativeToAniSceneFeatureType = {
    {OHOS::CameraStandard::SceneFeature::FEATURE_ENUM_MIN, SceneFeatureType::key_t::MOON_CAPTURE_BOOST},
    {OHOS::CameraStandard::SceneFeature::FEATURE_MOON_CAPTURE_BOOST, SceneFeatureType::key_t::MOON_CAPTURE_BOOST},
    {OHOS::CameraStandard::SceneFeature::FEATURE_TRIPOD_DETECTION, SceneFeatureType::key_t::TRIPOD_DETECTION},
    {OHOS::CameraStandard::SceneFeature::FEATURE_LOW_LIGHT_BOOST, SceneFeatureType::key_t::LOW_LIGHT_BOOST},
};

const std::unordered_map<OHOS::CameraStandard::MacroStatusCallback::MacroStatus, bool> g_nativeToAniMacroStatus = {
    {OHOS::CameraStandard::MacroStatusCallback::MacroStatus::IDLE, false},
    {OHOS::CameraStandard::MacroStatusCallback::MacroStatus::ACTIVE, true},
    {OHOS::CameraStandard::MacroStatusCallback::MacroStatus::UNKNOWN, true},
};

const std::unordered_map<OHOS::CameraStandard::EffectSuggestionType, EffectSuggestionType>
    g_nativeToAniEffectSuggestionType = {
    {OHOS::CameraStandard::EffectSuggestionType::EFFECT_SUGGESTION_NONE,
        EffectSuggestionType::key_t::EFFECT_SUGGESTION_NONE},
    {OHOS::CameraStandard::EffectSuggestionType::EFFECT_SUGGESTION_PORTRAIT,
        EffectSuggestionType::key_t::EFFECT_SUGGESTION_PORTRAIT},
    {OHOS::CameraStandard::EffectSuggestionType::EFFECT_SUGGESTION_FOOD,
        EffectSuggestionType::key_t::EFFECT_SUGGESTION_FOOD},
    {OHOS::CameraStandard::EffectSuggestionType::EFFECT_SUGGESTION_SKY,
        EffectSuggestionType::key_t::EFFECT_SUGGESTION_SKY},
    {OHOS::CameraStandard::EffectSuggestionType::EFFECT_SUGGESTION_SUNRISE_SUNSET,
        EffectSuggestionType::key_t::EFFECT_SUGGESTION_SUNRISE_SUNSET},
};

const std::unordered_map<OHOS::CameraStandard::ConnectionType, ConnectionType> g_nativeToAniConnectionType = {
    {OHOS::CameraStandard::ConnectionType::CAMERA_CONNECTION_BUILT_IN,
        ConnectionType::key_t::CAMERA_CONNECTION_BUILT_IN},
    {OHOS::CameraStandard::ConnectionType::CAMERA_CONNECTION_USB_PLUGIN,
        ConnectionType::key_t::CAMERA_CONNECTION_USB_PLUGIN},
    {OHOS::CameraStandard::ConnectionType::CAMERA_CONNECTION_REMOTE, ConnectionType::key_t::CAMERA_CONNECTION_REMOTE},
};

const std::unordered_map<int32_t, LightStatus> g_nativeToAniLightStatus = {
    {0, LightStatus::key_t::NORMAL},
    {1, LightStatus::key_t::INSUFFICIENT},
};

const std::unordered_map<OHOS::CameraStandard::FocusTrackingMode, FocusTrackingMode> g_nativeToAniFocusTrackingMode = {
    {OHOS::CameraStandard::FocusTrackingMode::FOCUS_TRACKING_MODE_AUTO,
        FocusTrackingMode::key_t::AUTO},
};

const std::unordered_map<OHOS::CameraStandard::CameraFormat, CameraFormat> g_nativeToAniCameraFormat = {
    {OHOS::CameraStandard::CameraFormat::CAMERA_FORMAT_RGBA_8888, CameraFormat::key_t::CAMERA_FORMAT_RGBA_8888},
    {OHOS::CameraStandard::CameraFormat::CAMERA_FORMAT_DNG, CameraFormat::key_t::CAMERA_FORMAT_DNG},
    {OHOS::CameraStandard::CameraFormat::CAMERA_FORMAT_DNG_XDRAW, CameraFormat::key_t::CAMERA_FORMAT_DNG_XDRAW},
    {OHOS::CameraStandard::CameraFormat::CAMERA_FORMAT_YUV_420_SP, CameraFormat::key_t::CAMERA_FORMAT_YUV_420_SP},
    {OHOS::CameraStandard::CameraFormat::CAMERA_FORMAT_JPEG, CameraFormat::key_t::CAMERA_FORMAT_JPEG},
    {OHOS::CameraStandard::CameraFormat::CAMERA_FORMAT_YCBCR_P010, CameraFormat::key_t::CAMERA_FORMAT_YCBCR_P010},
    {OHOS::CameraStandard::CameraFormat::CAMERA_FORMAT_YCRCB_P010, CameraFormat::key_t::CAMERA_FORMAT_YCRCB_P010},
    {OHOS::CameraStandard::CameraFormat::CAMERA_FORMAT_HEIC, CameraFormat::key_t::CAMERA_FORMAT_HEIC},
    {OHOS::CameraStandard::CameraFormat::CAMERA_FORMAT_DEPTH_16, CameraFormat::key_t::CAMERA_FORMAT_DEPTH_16},
    {OHOS::CameraStandard::CameraFormat::CAMERA_FORMAT_DEPTH_32, CameraFormat::key_t::CAMERA_FORMAT_DEPTH_32},
};

const std::unordered_map<OHOS::CameraStandard::FocusCallback::FocusState, FocusState> g_nativeToAniFocusState = {
    {OHOS::CameraStandard::FocusCallback::FocusState::SCAN, FocusState::key_t::FOCUS_STATE_SCAN},
    {OHOS::CameraStandard::FocusCallback::FOCUSED, FocusState::key_t::FOCUS_STATE_FOCUSED},
    {OHOS::CameraStandard::FocusCallback::UNFOCUSED, FocusState::key_t::FOCUS_STATE_UNFOCUSED},
};

const std::unordered_map<int32_t, DepthDataQualityLevel> g_nativeToAniDepthDataQualityLevel = {
    {0, DepthDataQualityLevel::key_t::DEPTH_DATA_QUALITY_BAD},
    {1, DepthDataQualityLevel::key_t::DEPTH_DATA_QUALITY_FAIR},
    {2, DepthDataQualityLevel::key_t::DEPTH_DATA_QUALITY_GOOD},
};

const std::unordered_map<OHOS::CameraStandard::DepthDataAccuracy, DepthDataAccuracy> g_nativeToAniDepthDataAccuracy = {
    {OHOS::CameraStandard::DepthDataAccuracy::DEPTH_DATA_ACCURACY_RELATIVE,
        DepthDataAccuracy::key_t::DEPTH_DATA_ACCURACY_RELATIVE},
    {OHOS::CameraStandard::DepthDataAccuracy::DEPTH_DATA_ACCURACY_ABSOLUTE,
        DepthDataAccuracy::key_t::DEPTH_DATA_ACCURACY_ABSOLUTE},
};

const std::unordered_map<OHOS::CameraStandard::MetadataObjectType,
                         MetadataObjectType> g_nativeToAniMetadataObjectType = {
    {OHOS::CameraStandard::MetadataObjectType::BASE_FACE_DETECTION, MetadataObjectType::key_t::FACE_DETECTION},
    {OHOS::CameraStandard::MetadataObjectType::HUMAN_BODY, MetadataObjectType::key_t::HUMAN_BODY},
    {OHOS::CameraStandard::MetadataObjectType::CAT_FACE, MetadataObjectType::key_t::CAT_FACE},
    {OHOS::CameraStandard::MetadataObjectType::CAT_BODY, MetadataObjectType::key_t::CAT_BODY},
    {OHOS::CameraStandard::MetadataObjectType::DOG_FACE, MetadataObjectType::key_t::DOG_FACE},
    {OHOS::CameraStandard::MetadataObjectType::DOG_BODY, MetadataObjectType::key_t::DOG_BODY},
    {OHOS::CameraStandard::MetadataObjectType::SALIENT_DETECTION, MetadataObjectType::key_t::SALIENT_DETECTION},
    {OHOS::CameraStandard::MetadataObjectType::BAR_CODE_DETECTION, MetadataObjectType::key_t::BAR_CODE_DETECTION},
};

const std::unordered_map<OHOS::CameraStandard::TimeLapsePreviewType,
    ohos::multimedia::camera::TimeLapsePreviewType> g_nativeToAniTimeLapsePreviewType = {
    {OHOS::CameraStandard::TimeLapsePreviewType::DARK, ohos::multimedia::camera::TimeLapsePreviewType::key_t::DARK},
    {OHOS::CameraStandard::TimeLapsePreviewType::LIGHT, ohos::multimedia::camera::TimeLapsePreviewType::key_t::LIGHT},
};

const std::unordered_map<OHOS::CameraStandard::SlowMotionState, SlowMotionStatus> g_nativeToAniSlowMotionState = {
    {OHOS::CameraStandard::SlowMotionState::DISABLE, SlowMotionStatus::key_t::DISABLED},
    {OHOS::CameraStandard::SlowMotionState::READY, SlowMotionStatus::key_t::READY},
    {OHOS::CameraStandard::SlowMotionState::START, SlowMotionStatus::key_t::VIDEO_START},
    {OHOS::CameraStandard::SlowMotionState::RECORDING, SlowMotionStatus::key_t::VIDEO_DONE},
    {OHOS::CameraStandard::SlowMotionState::FINISH, SlowMotionStatus::key_t::FINISHED},
};

const std::unordered_map<int32_t, OHOS::CameraStandard::PolicyType> g_jsToFwPolicyType = {
    {1, OHOS::CameraStandard::PolicyType::PRIVACY},
};
} // namespace Ani::Camera

#endif // FRAMEWORKS_TAIHE_INCLUDE_CAMERA_CONST_ABILITY_TAIHE_H
