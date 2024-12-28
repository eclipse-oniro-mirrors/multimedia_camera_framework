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

#ifndef CAMERA_ABILITY_CONST_H
#define CAMERA_ABILITY_CONST_H

#include <cstdint>
#include <map>
#include "camera_metadata_operator.h"
namespace OHOS {
namespace HDI {
namespace Display {
namespace Graphic {
namespace Common {
namespace V1_0 {
enum CM_ColorSpaceType : int32_t;
}}}}}}

namespace OHOS {
namespace CameraStandard {

using namespace OHOS::HDI::Display::Graphic::Common::V1_0;

enum FlashMode {
    FLASH_MODE_CLOSE = 0,
    FLASH_MODE_OPEN,
    FLASH_MODE_AUTO,
    FLASH_MODE_ALWAYS_OPEN,
};

enum ExposureMode {
    EXPOSURE_MODE_UNSUPPORTED = -1,
    EXPOSURE_MODE_LOCKED = 0,
    EXPOSURE_MODE_AUTO,
    EXPOSURE_MODE_CONTINUOUS_AUTO
};

enum FocusMode {
    FOCUS_MODE_MANUAL = 0,
    FOCUS_MODE_CONTINUOUS_AUTO,
    FOCUS_MODE_AUTO,
    FOCUS_MODE_LOCKED,
};

enum QualityPrioritization {
    HIGH_QUALITY = 0,
    POWER_BALANCE,
};

enum BeautyType {
    AUTO_TYPE = 0,
    SKIN_SMOOTH = 1,
    FACE_SLENDER = 2,
    SKIN_TONE = 3,
};

enum ColorEffect {
    COLOR_EFFECT_NORMAL = 0,
    COLOR_EFFECT_BRIGHT,
    COLOR_EFFECT_SOFT,
    COLOR_EFFECT_BLACK_WHITE,
};

enum PortraitEffect {
    OFF_EFFECT = 0,
    CIRCLES = 1,
    HEART = 2,
    ROTATED = 3,
    STUDIO = 4,
    THEATER = 5,
};

enum VideoStabilizationMode {
    OFF = 0,
    LOW,
    MIDDLE,
    HIGH,
    AUTO
};

enum ColorSpace {
    COLOR_SPACE_UNKNOWN = 0,
    DISPLAY_P3 = 3, // CM_P3_FULL
    SRGB = 4, // CM_SRGB_FULL
    BT709 = 6, // CM_BT709_FULL
    BT2020_HLG = 9, // CM_BT2020_HLG_FULL
    BT2020_PQ = 10, // CM_BT2020_PQ_FULL
    P3_HLG = 11, // CM_P3_HLG_FULL
    P3_PQ = 12, // CM_P3_PQ_FULL
    DISPLAY_P3_LIMIT = 14, // CM_P3_LIMIT
    SRGB_LIMIT = 15, // CM_SRGB_LIMIT
    BT709_LIMIT = 16, // CM_BT709_LIMIT
    BT2020_HLG_LIMIT = 19, // CM_BT2020_HLG_LIMIT
    BT2020_PQ_LIMIT = 20, // CM_BT2020_PQ_LIMIT
    P3_HLG_LIMIT = 21, // CM_P3_HLG_LIMIT
    P3_PQ_LIMIT = 22 // CM_P3_PQ_LIMIT
};

enum class PortraitThemeType {
    NATURAL = 0,
    DELICATE,
    STYLISH
};

enum class VideoRotation {
    ROTATION_0 = 0,
    ROTATION_90 = 90,
    ROTATION_180 = 180,
    ROTATION_270 = 270
};

extern const std::unordered_map<camera_flash_mode_enum_t, FlashMode> g_metaFlashModeMap_;
extern const std::unordered_map<camera_exposure_mode_enum_t, ExposureMode> g_metaExposureModeMap_;
extern const std::unordered_map<camera_focus_mode_enum_t, FocusMode> g_metaFocusModeMap_;
extern const std::unordered_map<camera_beauty_type_t, BeautyType> g_metaBeautyTypeMap_;
extern const std::unordered_map<camera_device_metadata_tag_t, BeautyType> g_metaBeautyAbilityMap_;
extern const std::unordered_map<camera_xmage_color_type_t, ColorEffect> g_metaColorEffectMap_;
extern const std::unordered_map<CameraVideoStabilizationMode, VideoStabilizationMode> g_metaVideoStabModesMap_;
extern const std::unordered_map<camera_portrait_effect_type_t, PortraitEffect> g_metaToFwPortraitEffect_;
extern const std::unordered_map<VideoStabilizationMode, CameraVideoStabilizationMode> g_fwkVideoStabModesMap_;
extern const std::unordered_map<ExposureMode, camera_exposure_mode_enum_t> g_fwkExposureModeMap_;
extern const std::map<CM_ColorSpaceType, ColorSpace> g_metaColorSpaceMap_;
extern const std::unordered_map<FocusMode, camera_focus_mode_enum_t> g_fwkFocusModeMap_;
extern const std::unordered_map<ColorEffect, camera_xmage_color_type_t> g_fwkColorEffectMap_;
extern const std::unordered_map<FlashMode, camera_flash_mode_enum_t> g_fwkFlashModeMap_;
extern const std::unordered_map<BeautyType, camera_beauty_type_t> g_fwkBeautyTypeMap_;
extern const std::unordered_map<BeautyType, camera_device_metadata_tag_t> g_fwkBeautyAbilityMap_;
extern const std::unordered_map<PortraitThemeType, CameraPortraitThemeTypes> g_fwkPortraitThemeTypeMap_;
extern const std::unordered_map<CameraPortraitThemeTypes, PortraitThemeType> g_metaPortraitThemeTypeMap_;
extern const std::vector<VideoRotation> g_fwkVideoRotationVector_;
extern const std::unordered_map<CameraQualityPrioritization, QualityPrioritization> g_metaQualityPrioritizationMap_;
extern const std::unordered_map<QualityPrioritization, CameraQualityPrioritization> g_fwkQualityPrioritizationMap_;

template <typename S, typename T>
void g_transformValidData(
    const camera_metadata_item_t& item, const std::unordered_map<S, T>& map, std::vector<T>& validModes)
{
    for (uint32_t i = 0; i < item.count; i++) {
        auto it = map.find(static_cast<S>(item.data.u8[i]));
        if (it != map.end()) {
            validModes.emplace_back(it->second);
        }
    }
}
} // namespace CameraStandard
} // namespace OHOS
#endif