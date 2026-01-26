/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "ability/camera_ability_const.h"
#include "camera_util.h"
#include "camera/v1_5/types.h"
#include "capture_scene_const.h"
#include "display/graphic/common/v2_1/cm_color_space.h"
#include "istream_metadata.h"
#include "hstream_common.h"
namespace OHOS {
namespace CameraStandard {
using OHOS::HDI::Camera::V1_5::OperationMode;
using namespace OHOS::HDI::Display::Graphic::Common::V2_1;
using CM_ColorSpaceType_V2_1 = OHOS::HDI::Display::Graphic::Common::V2_1::CM_ColorSpaceType;

const std::unordered_map<camera_flash_mode_enum_t, FlashMode> g_metaFlashModeMap_ = {
    {OHOS_CAMERA_FLASH_MODE_CLOSE, FLASH_MODE_CLOSE},
    {OHOS_CAMERA_FLASH_MODE_OPEN, FLASH_MODE_OPEN},
    {OHOS_CAMERA_FLASH_MODE_AUTO, FLASH_MODE_AUTO},
    {OHOS_CAMERA_FLASH_MODE_ALWAYS_OPEN, FLASH_MODE_ALWAYS_OPEN}
};

const std::unordered_map<camera_exposure_mode_enum_t, ExposureMode> g_metaExposureModeMap_ = {
    {OHOS_CAMERA_EXPOSURE_MODE_LOCKED, EXPOSURE_MODE_LOCKED},
    {OHOS_CAMERA_EXPOSURE_MODE_AUTO, EXPOSURE_MODE_AUTO},
    {OHOS_CAMERA_EXPOSURE_MODE_CONTINUOUS_AUTO, EXPOSURE_MODE_CONTINUOUS_AUTO}
};

const std::unordered_map<camera_focus_mode_enum_t, FocusMode> g_metaFocusModeMap_ = {
    {OHOS_CAMERA_FOCUS_MODE_MANUAL, FOCUS_MODE_MANUAL},
    {OHOS_CAMERA_FOCUS_MODE_CONTINUOUS_AUTO, FOCUS_MODE_CONTINUOUS_AUTO},
    {OHOS_CAMERA_FOCUS_MODE_AUTO, FOCUS_MODE_AUTO},
    {OHOS_CAMERA_FOCUS_MODE_LOCKED, FOCUS_MODE_LOCKED}
};

const std::unordered_map<CameraQualityPrioritization, QualityPrioritization> g_metaQualityPrioritizationMap_ = {
    { OHOS_CAMERA_QUALITY_PRIORITIZATION_HIGH_QUALITY, HIGH_QUALITY },
    { OHOS_CAMERA_QUALITY_PRIORITIZATION_POWER_BALANCE, POWER_BALANCE }
};

const std::unordered_map<camera_beauty_type_t, BeautyType> g_metaBeautyTypeMap_ = {
    {OHOS_CAMERA_BEAUTY_TYPE_AUTO, AUTO_TYPE},
    {OHOS_CAMERA_BEAUTY_TYPE_SKIN_SMOOTH, SKIN_SMOOTH},
    {OHOS_CAMERA_BEAUTY_TYPE_FACE_SLENDER, FACE_SLENDER},
    {OHOS_CAMERA_BEAUTY_TYPE_SKIN_TONE, SKIN_TONE},
    {OHOS_CAMERA_BEAUTY_TYPE_SKIN_TONEBRIGHT, SKIN_TONEBRIGHT},
    {OHOS_CAMERA_BEAUTY_TYPE_EYE_BIGEYES, EYE_BIGEYES},
    {OHOS_CAMERA_BEAUTY_TYPE_HAIR_HAIRLINE, HAIR_HAIRLINE},
    {OHOS_CAMERA_BEAUTY_TYPE_FACE_MAKEUP, FACE_MAKEUP},
    {OHOS_CAMERA_BEAUTY_TYPE_HEAD_SHRINK, HEAD_SHRINK},
    {OHOS_CAMERA_BEAUTY_TYPE_NOSE_SLENDER, NOSE_SLENDER},
};

const std::unordered_map<camera_device_metadata_tag_t, BeautyType> g_metaBeautyAbilityMap_ = {
    {OHOS_ABILITY_BEAUTY_AUTO_VALUES, AUTO_TYPE},
    {OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES, SKIN_SMOOTH},
    {OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES, FACE_SLENDER},
    {OHOS_ABILITY_BEAUTY_SKIN_TONE_VALUES, SKIN_TONE},
    {OHOS_ABILITY_BEAUTY_SKIN_TONEBRIGHT_VALUES, SKIN_TONEBRIGHT},
    {OHOS_ABILITY_BEAUTY_EYE_BIGEYES_VALUES, EYE_BIGEYES},
    {OHOS_ABILITY_BEAUTY_HAIR_HAIRLINE_VALUES, HAIR_HAIRLINE},
    {OHOS_ABILITY_BEAUTY_FACE_MAKEUP_VALUES, FACE_MAKEUP},
    {OHOS_ABILITY_BEAUTY_HEAD_SHRINK_VALUES, HEAD_SHRINK},
    {OHOS_ABILITY_BEAUTY_NOSE_SLENDER_VALUES, NOSE_SLENDER},
};

const std::unordered_map<camera_xmage_color_type_t, ColorEffect> g_metaColorEffectMap_ = {
    {CAMERA_CUSTOM_COLOR_NORMAL, COLOR_EFFECT_NORMAL},
    {CAMERA_CUSTOM_COLOR_BRIGHT, COLOR_EFFECT_BRIGHT},
    {CAMERA_CUSTOM_COLOR_SOFT, COLOR_EFFECT_SOFT},
    {CAMERA_CUSTOM_COLOR_MONO, COLOR_EFFECT_BLACK_WHITE},
    {CAMERA_CUSTOM_COLOR_CLASSIC, COLOR_EFFECT_CLASSIC},
    {CAMERA_CUSTOM_COLOR_MODERN, COLOR_EFFECT_MODERN},
};

const std::unordered_map<CameraVideoStabilizationMode, VideoStabilizationMode> g_metaVideoStabModesMap_ = {
    {OHOS_CAMERA_VIDEO_STABILIZATION_OFF, OFF},
    {OHOS_CAMERA_VIDEO_STABILIZATION_LOW, LOW},
    {OHOS_CAMERA_VIDEO_STABILIZATION_MIDDLE, MIDDLE},
    {OHOS_CAMERA_VIDEO_STABILIZATION_HIGH, HIGH},
    {OHOS_CAMERA_VIDEO_STABILIZATION_AUTO, AUTO}
};

const std::unordered_map<camera_portrait_effect_type_t, PortraitEffect> g_metaToFwPortraitEffect_ = {
    {OHOS_CAMERA_PORTRAIT_EFFECT_OFF, OFF_EFFECT},
    {OHOS_CAMERA_PORTRAIT_CIRCLES, CIRCLES},
    {OHOS_CAMERA_PORTRAIT_HEART, HEART},
    {OHOS_CAMERA_PORTRAIT_ROTATED, ROTATED},
    {OHOS_CAMERA_PORTRAIT_STUDIO, STUDIO},
    {OHOS_CAMERA_PORTRAIT_THEATER, THEATER},
};

const std::unordered_map<VideoStabilizationMode, CameraVideoStabilizationMode> g_fwkVideoStabModesMap_ = {
    {OFF, OHOS_CAMERA_VIDEO_STABILIZATION_OFF},
    {LOW, OHOS_CAMERA_VIDEO_STABILIZATION_LOW},
    {MIDDLE, OHOS_CAMERA_VIDEO_STABILIZATION_MIDDLE},
    {HIGH, OHOS_CAMERA_VIDEO_STABILIZATION_HIGH},
    {AUTO, OHOS_CAMERA_VIDEO_STABILIZATION_AUTO}
};

const std::unordered_map<ExposureMode, camera_exposure_mode_enum_t> g_fwkExposureModeMap_ = {
    {EXPOSURE_MODE_LOCKED, OHOS_CAMERA_EXPOSURE_MODE_LOCKED},
    {EXPOSURE_MODE_AUTO, OHOS_CAMERA_EXPOSURE_MODE_AUTO},
    {EXPOSURE_MODE_CONTINUOUS_AUTO, OHOS_CAMERA_EXPOSURE_MODE_CONTINUOUS_AUTO}
};

const std::map<CM_ColorSpaceType_V2_1, ColorSpace> g_metaColorSpaceMap_ = {
    {CM_ColorSpaceType_V2_1::CM_COLORSPACE_NONE, COLOR_SPACE_UNKNOWN},
    {CM_ColorSpaceType_V2_1::CM_P3_FULL, DISPLAY_P3},
    {CM_ColorSpaceType_V2_1::CM_SRGB_FULL, SRGB},
    {CM_ColorSpaceType_V2_1::CM_BT709_FULL, BT709},
    {CM_ColorSpaceType_V2_1::CM_BT2020_HLG_FULL, BT2020_HLG},
    {CM_ColorSpaceType_V2_1::CM_BT2020_PQ_FULL, BT2020_PQ},
    {CM_ColorSpaceType_V2_1::CM_P3_HLG_FULL, P3_HLG},
    {CM_ColorSpaceType_V2_1::CM_P3_PQ_FULL, P3_PQ},
    {CM_ColorSpaceType_V2_1::CM_P3_LIMIT, DISPLAY_P3_LIMIT},
    {CM_ColorSpaceType_V2_1::CM_SRGB_LIMIT, SRGB_LIMIT},
    {CM_ColorSpaceType_V2_1::CM_BT709_LIMIT, BT709_LIMIT},
    {CM_ColorSpaceType_V2_1::CM_BT2020_HLG_LIMIT, BT2020_HLG_LIMIT},
    {CM_ColorSpaceType_V2_1::CM_BT2020_PQ_LIMIT, BT2020_PQ_LIMIT},
    {CM_ColorSpaceType_V2_1::CM_P3_HLG_LIMIT, P3_HLG_LIMIT},
    {CM_ColorSpaceType_V2_1::CM_P3_PQ_LIMIT, P3_PQ_LIMIT},
    {CM_ColorSpaceType_V2_1::CM_BT2020_LOG_FULL, H_LOG},
};

const std::unordered_map<FocusMode, camera_focus_mode_enum_t> g_fwkFocusModeMap_ = {
    {FOCUS_MODE_MANUAL, OHOS_CAMERA_FOCUS_MODE_MANUAL},
    {FOCUS_MODE_CONTINUOUS_AUTO, OHOS_CAMERA_FOCUS_MODE_CONTINUOUS_AUTO},
    {FOCUS_MODE_AUTO, OHOS_CAMERA_FOCUS_MODE_AUTO},
    {FOCUS_MODE_LOCKED, OHOS_CAMERA_FOCUS_MODE_LOCKED}
};

const std::unordered_map<QualityPrioritization, CameraQualityPrioritization> g_fwkQualityPrioritizationMap_ = {
    { HIGH_QUALITY, OHOS_CAMERA_QUALITY_PRIORITIZATION_HIGH_QUALITY },
    { POWER_BALANCE, OHOS_CAMERA_QUALITY_PRIORITIZATION_POWER_BALANCE }
};

const std::unordered_map<ColorEffect, camera_xmage_color_type_t> g_fwkColorEffectMap_ = {
    {COLOR_EFFECT_NORMAL, CAMERA_CUSTOM_COLOR_NORMAL},
    {COLOR_EFFECT_BRIGHT, CAMERA_CUSTOM_COLOR_BRIGHT},
    {COLOR_EFFECT_SOFT, CAMERA_CUSTOM_COLOR_SOFT},
    {COLOR_EFFECT_BLACK_WHITE, CAMERA_CUSTOM_COLOR_MONO},
    {COLOR_EFFECT_CLASSIC, CAMERA_CUSTOM_COLOR_CLASSIC},
    {COLOR_EFFECT_MODERN, CAMERA_CUSTOM_COLOR_MODERN},
};

const std::unordered_map<FlashMode, camera_flash_mode_enum_t> g_fwkFlashModeMap_ = {
    {FLASH_MODE_CLOSE, OHOS_CAMERA_FLASH_MODE_CLOSE},
    {FLASH_MODE_OPEN, OHOS_CAMERA_FLASH_MODE_OPEN},
    {FLASH_MODE_AUTO, OHOS_CAMERA_FLASH_MODE_AUTO},
    {FLASH_MODE_ALWAYS_OPEN, OHOS_CAMERA_FLASH_MODE_ALWAYS_OPEN}
};

const std::unordered_map<BeautyType, camera_beauty_type_t> g_fwkBeautyTypeMap_ = {
    {AUTO_TYPE, OHOS_CAMERA_BEAUTY_TYPE_AUTO},
    {SKIN_SMOOTH, OHOS_CAMERA_BEAUTY_TYPE_SKIN_SMOOTH},
    {FACE_SLENDER, OHOS_CAMERA_BEAUTY_TYPE_FACE_SLENDER},
    {SKIN_TONE, OHOS_CAMERA_BEAUTY_TYPE_SKIN_TONE},
    {SKIN_TONEBRIGHT, OHOS_CAMERA_BEAUTY_TYPE_SKIN_TONEBRIGHT},
    {EYE_BIGEYES, OHOS_CAMERA_BEAUTY_TYPE_EYE_BIGEYES},
    {HAIR_HAIRLINE, OHOS_CAMERA_BEAUTY_TYPE_HAIR_HAIRLINE},
    {FACE_MAKEUP, OHOS_CAMERA_BEAUTY_TYPE_FACE_MAKEUP},
    {HEAD_SHRINK, OHOS_CAMERA_BEAUTY_TYPE_HEAD_SHRINK},
    {NOSE_SLENDER, OHOS_CAMERA_BEAUTY_TYPE_NOSE_SLENDER},
};

const std::unordered_map<BeautyType, camera_device_metadata_tag_t> g_fwkBeautyAbilityMap_ = {
    {AUTO_TYPE, OHOS_ABILITY_BEAUTY_AUTO_VALUES},
    {SKIN_SMOOTH, OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES},
    {FACE_SLENDER, OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES},
    {SKIN_TONE, OHOS_ABILITY_BEAUTY_SKIN_TONE_VALUES},
    {SKIN_TONEBRIGHT, OHOS_ABILITY_BEAUTY_SKIN_TONEBRIGHT_VALUES},
    {EYE_BIGEYES, OHOS_ABILITY_BEAUTY_EYE_BIGEYES_VALUES},
    {HAIR_HAIRLINE, OHOS_ABILITY_BEAUTY_HAIR_HAIRLINE_VALUES},
    {FACE_MAKEUP, OHOS_ABILITY_BEAUTY_FACE_MAKEUP_VALUES},
    {HEAD_SHRINK, OHOS_ABILITY_BEAUTY_HEAD_SHRINK_VALUES},
    {NOSE_SLENDER, OHOS_ABILITY_BEAUTY_NOSE_SLENDER_VALUES},
};

const std::unordered_map<PortraitThemeType, CameraPortraitThemeTypes> g_fwkPortraitThemeTypeMap_ = {
    {PortraitThemeType::NATURAL, OHOS_CAMERA_PORTRAIT_THEME_TYPE_NATURAL},
    {PortraitThemeType::DELICATE, OHOS_CAMERA_PORTRAIT_THEME_TYPE_DELICATE},
    {PortraitThemeType::STYLISH, OHOS_CAMERA_PORTRAIT_THEME_TYPE_STYLISH},
};

const std::unordered_map<CameraPortraitThemeTypes, PortraitThemeType> g_metaPortraitThemeTypeMap_ = {
    {OHOS_CAMERA_PORTRAIT_THEME_TYPE_NATURAL, PortraitThemeType::NATURAL},
    {OHOS_CAMERA_PORTRAIT_THEME_TYPE_DELICATE, PortraitThemeType::DELICATE},
    {OHOS_CAMERA_PORTRAIT_THEME_TYPE_STYLISH, PortraitThemeType::STYLISH},
};

const std::unordered_map<NightSubMode, CameraNightSubMode> g_fwkNightSubModeMap_ = {
    {NightSubMode::DEFAULT, OHOS_CAMERA_NIGHT_SUB_MODE_DEFAULT},
    {NightSubMode::SUPER_MOON, OHOS_CAMERA_NIGHT_SUB_MODE_SUPER_MOON},
    {NightSubMode::STARRY_SKY, OHOS_CAMERA_NIGHT_SUB_MODE_STARRY_SKY},
    {NightSubMode::STARRY_SKY_PORTRAIT, OHOS_CAMERA_NIGHT_SUB_MODE_STARRY_SKY_PORTRAIT},
};

const std::unordered_map<CameraNightSubMode, NightSubMode> g_metaNightSubModeMap_ = {
    {OHOS_CAMERA_NIGHT_SUB_MODE_DEFAULT, NightSubMode::DEFAULT},
    {OHOS_CAMERA_NIGHT_SUB_MODE_SUPER_MOON, NightSubMode::SUPER_MOON},
    {OHOS_CAMERA_NIGHT_SUB_MODE_STARRY_SKY, NightSubMode::STARRY_SKY},
    {OHOS_CAMERA_NIGHT_SUB_MODE_STARRY_SKY_PORTRAIT, NightSubMode::STARRY_SKY_PORTRAIT},
};

const std::vector<VideoRotation> g_fwkVideoRotationVector_ = {
    VideoRotation::ROTATION_0,
    VideoRotation::ROTATION_90,
    VideoRotation::ROTATION_180,
    VideoRotation::ROTATION_270
};

const std::unordered_map<OperationMode, SceneMode> g_metaToFwSupportedMode_ = {
    {OperationMode::NORMAL, NORMAL},
    {OperationMode::CAPTURE, CAPTURE},
    {OperationMode::VIDEO, VIDEO},
    {OperationMode::PORTRAIT, PORTRAIT},
    {OperationMode::NIGHT, NIGHT},
    {OperationMode::PROFESSIONAL_PHOTO, PROFESSIONAL_PHOTO},
    {OperationMode::PROFESSIONAL_VIDEO, PROFESSIONAL_VIDEO},
    {OperationMode::SLOW_MOTION, SLOW_MOTION},
    {OperationMode::SCAN_CODE, SCAN},
    {OperationMode::CAPTURE_MACRO, CAPTURE_MACRO},
    {OperationMode::VIDEO_MACRO, VIDEO_MACRO},
    {OperationMode::HIGH_FRAME_RATE, HIGH_FRAME_RATE},
    {OperationMode::HIGH_RESOLUTION_PHOTO, HIGH_RES_PHOTO},
    {OperationMode::SECURE, SECURE},
    {OperationMode::QUICK_SHOT_PHOTO, QUICK_SHOT_PHOTO},
    {OperationMode::APERTURE_VIDEO, APERTURE_VIDEO},
    {OperationMode::PANORAMA_PHOTO, PANORAMA_PHOTO},
    {OperationMode::LIGHT_PAINTING, LIGHT_PAINTING},
    {OperationMode::TIMELAPSE_PHOTO, TIMELAPSE_PHOTO},
    {OperationMode::FLUORESCENCE_PHOTO, FLUORESCENCE_PHOTO},
    {OperationMode::STITCHING_PHOTO, STITCHING_PHOTO},
    {OperationMode::CINEMATIC_VIDEO, CINEMATIC_VIDEO},
};

const std::unordered_map<SceneMode, OperationMode> g_fwToMetaSupportedMode_ = {
    {NORMAL, OperationMode::NORMAL},
    {CAPTURE,  OperationMode::CAPTURE},
    {VIDEO,  OperationMode::VIDEO},
    {PORTRAIT,  OperationMode::PORTRAIT},
    {NIGHT,  OperationMode::NIGHT},
    {PROFESSIONAL_PHOTO,  OperationMode::PROFESSIONAL_PHOTO},
    {PROFESSIONAL_VIDEO,  OperationMode::PROFESSIONAL_VIDEO},
    {SLOW_MOTION,  OperationMode::SLOW_MOTION},
    {SCAN, OperationMode::SCAN_CODE},
    {CAPTURE_MACRO, OperationMode::CAPTURE_MACRO},
    {VIDEO_MACRO, OperationMode::VIDEO_MACRO},
    {HIGH_FRAME_RATE, OperationMode::HIGH_FRAME_RATE},
    {HIGH_RES_PHOTO, OperationMode::HIGH_RESOLUTION_PHOTO},
    {SECURE, OperationMode::SECURE},
    {QUICK_SHOT_PHOTO, OperationMode::QUICK_SHOT_PHOTO},
    {APERTURE_VIDEO, OperationMode::APERTURE_VIDEO},
    {PANORAMA_PHOTO, OperationMode::PANORAMA_PHOTO},
    {LIGHT_PAINTING, OperationMode::LIGHT_PAINTING},
    {TIMELAPSE_PHOTO, OperationMode::TIMELAPSE_PHOTO},
    {FLUORESCENCE_PHOTO, OperationMode::FLUORESCENCE_PHOTO},
    {STITCHING_PHOTO, OperationMode::STITCHING_PHOTO},
#ifdef CAMERA_FRAMEWORK_FEATURE_MEDIA_STREAM
    {CINEMATIC_VIDEO, OperationMode::CINEMATIC_VIDEO},
#endif
};

const std::unordered_map<StatisticsDetectType, MetadataObjectType> g_metaToFwCameraMetaDetect_ = {
    {StatisticsDetectType::OHOS_CAMERA_HUMAN_FACE_DETECT, MetadataObjectType::FACE},
    {StatisticsDetectType::OHOS_CAMERA_HUMAN_BODY_DETECT, MetadataObjectType::HUMAN_BODY},
    {StatisticsDetectType::OHOS_CAMERA_CAT_FACE_DETECT, MetadataObjectType::CAT_FACE},
    {StatisticsDetectType::OHOS_CAMERA_CAT_BODY_DETECT, MetadataObjectType::CAT_BODY},
    {StatisticsDetectType::OHOS_CAMERA_DOG_FACE_DETECT, MetadataObjectType::DOG_FACE},
    {StatisticsDetectType::OHOS_CAMERA_DOG_BODY_DETECT, MetadataObjectType::DOG_BODY},
    {StatisticsDetectType::OHOS_CAMERA_SALIENT_DETECT, MetadataObjectType::SALIENT_DETECTION},
    {StatisticsDetectType::OHOS_CAMERA_BAR_CODE_DETECT, MetadataObjectType::BAR_CODE_DETECTION},
    {StatisticsDetectType::OHOS_CAMERA_BASE_FACE_DETECT, MetadataObjectType::BASE_FACE_DETECTION},
    {StatisticsDetectType::OHOS_CAMERA_HUMAN_HEAD_DETECT, MetadataObjectType::HUMAN_HEAD}
};

const std::unordered_map<camera_focus_range_type_t, FocusRangeType> g_metaFocusRangeTypeMap_ = {
    {OHOS_CAMERA_FOCUS_RANGE_AUTO, FocusRangeType::FOCUS_RANGE_TYPE_AUTO},
    {OHOS_CAMERA_FOCUS_RANGE_NEAR, FocusRangeType::FOCUS_RANGE_TYPE_NEAR}
};

const std::unordered_map<FocusRangeType, camera_focus_range_type_t> g_fwkocusRangeTypeMap_ = {
    {FocusRangeType::FOCUS_RANGE_TYPE_AUTO, OHOS_CAMERA_FOCUS_RANGE_AUTO},
    {FocusRangeType::FOCUS_RANGE_TYPE_NEAR, OHOS_CAMERA_FOCUS_RANGE_NEAR}
};

const std::unordered_map<camera_focus_driven_type_t, FocusDrivenType> g_metaFocusDrivenTypeMap_ = {
    {OHOS_CAMERA_FOCUS_DRIVEN_AUTO, FocusDrivenType::FOCUS_DRIVEN_TYPE_AUTO},
    {OHOS_CAMERA_FOCUS_DRIVEN_FACE, FocusDrivenType::FOCUS_DRIVEN_TYPE_FACE}
};

const std::unordered_map<FocusDrivenType, camera_focus_driven_type_t> g_fwkFocusDrivenTypeMap_ = {
    {FocusDrivenType::FOCUS_DRIVEN_TYPE_AUTO, OHOS_CAMERA_FOCUS_DRIVEN_AUTO},
    {FocusDrivenType::FOCUS_DRIVEN_TYPE_FACE, OHOS_CAMERA_FOCUS_DRIVEN_FACE}
};

const std::unordered_map<camera_color_reservation_type_t, ColorReservationType>
    g_metaColorReservationTypeMap_ = {
    {OHOS_CAMERA_COLOR_RESERVATION_NONE, ColorReservationType::COLOR_RESERVATION_TYPE_NONE},
    {OHOS_CAMERA_COLOR_RESERVATION_PORTRAIT, ColorReservationType::COLOR_RESERVATION_TYPE_PORTRAIT}
};

const std::unordered_map<ColorReservationType, camera_color_reservation_type_t>
    g_fwkColorReservationTypeMap_ = {
    {ColorReservationType::COLOR_RESERVATION_TYPE_NONE, OHOS_CAMERA_COLOR_RESERVATION_NONE},
    {ColorReservationType::COLOR_RESERVATION_TYPE_PORTRAIT, OHOS_CAMERA_COLOR_RESERVATION_PORTRAIT}
};

const std::unordered_map<camera_imaging_mode_enum_t, ImagingMode> g_metaImagingModesMap_ = {
    {OHOS_CAMERA_IMAGING_MODE_AUTO, IMAGING_MODE_AUTO},
    {OHOS_CAMERA_IMAGING_MODE_RGB, IMAGING_MODE_RGB},
    {OHOS_CAMERA_IMAGING_MODE_IR, IMAGING_MODE_IR}
};

const std::unordered_map<ImagingMode, camera_imaging_mode_enum_t> g_fwkImagingModesMap_ = {
    {IMAGING_MODE_AUTO, OHOS_CAMERA_IMAGING_MODE_AUTO},
    {IMAGING_MODE_RGB, OHOS_CAMERA_IMAGING_MODE_RGB},
    {IMAGING_MODE_IR, OHOS_CAMERA_IMAGING_MODE_IR}
};
} // namespace CameraStandard
} // namespace OHOS
