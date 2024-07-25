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

#include "ability/camera_ability_builder.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {

std::vector<sptr<CameraAbility>> CameraAbilityBuilder::GetAbility(int32_t modeName, common_metadata_header_t* metadata,
    const std::set<int32_t>& specIds, sptr<CaptureSession> session, bool isForApp)
{
    AvailableConfig availableConfig;
    CameraAbilityParseUtil::GetAvailableConfiguration(modeName, metadata, availableConfig);
    std::vector<sptr<CameraAbility>> abilities;
    MEDIA_INFO_LOG("enter CameraAbilityBuilder::GetAbility");
    for (const auto& configInfo : availableConfig.configInfos) {
        if (specIds.find(configInfo.specId) == specIds.end()) {
            continue;
        }
        sptr<CameraAbility> ability = new CameraAbility();
        if (ability == nullptr) {
            MEDIA_ERR_LOG("alloc CameraAbility error");
            continue;
        }
        for (const auto& tagId : configInfo.tagIds) {
            SetModeSpecTagField(ability, modeName, metadata, tagId, configInfo.specId);
        }
        if (isForApp) {
            SetOtherTag(ability, modeName, session);
        }
        ability->DumpCameraAbilityInfo();
        abilities.push_back(ability);
    }
    return abilities;
}

std::vector<sptr<CameraAbility>> CameraAbilityBuilder::GetConflictAbility(
    int32_t modeName, common_metadata_header_t* metadata)
{
    ConflictConfig conflictConfig;
    CameraAbilityParseUtil::GetConflictConfiguration(modeName, metadata, conflictConfig);
    std::vector<sptr<CameraAbility>> conflictAbilities;
    MEDIA_INFO_LOG("enter CameraAbilityBuilder::GetConflictAbility");
    for (const auto& configInfo : conflictConfig.configInfos) {
        sptr<CameraAbility> conflictAbility = new CameraAbility();
        if (conflictAbility == nullptr) {
            MEDIA_ERR_LOG("alloc CameraAbility error");
            continue;
        }
        for (const auto& tagInfo : configInfo.tagInfos) {
            SetModeSpecTagField(conflictAbility, modeName, metadata, tagInfo.first, tagInfo.second);
        }
        conflictAbility->DumpCameraAbilityInfo();
        conflictAbilities.push_back(conflictAbility);
    }
    return conflictAbilities;
}

std::vector<int32_t> CameraAbilityBuilder::GetData(
    int32_t modeName, common_metadata_header_t* metadata, uint32_t tagId, int32_t specId)
{
    if (cachedTagSet_.find(tagId) == cachedTagSet_.end()) {
        std::map<int32_t, std::vector<int32_t>> tagDataMap;
        CameraAbilityParseUtil::GetAbilityInfo(modeName, metadata, tagId, tagDataMap);
        cacheTagDataMap_[tagId] = tagDataMap;
        cachedTagSet_.insert(tagId);
    }

    auto itc = cacheTagDataMap_.find(tagId);
    if (itc == cacheTagDataMap_.end()) {
        return {};
    }
    auto& dataMap = itc->second;
    auto itd = dataMap.find(specId);
    if (itd == dataMap.end()) {
        return {};
    }
    return itd->second;
}

std::vector<FlashMode> CameraAbilityBuilder::GetValidFlashModes(const std::vector<int32_t>& data)
{
    std::vector<FlashMode> modes;
    modes.reserve(data.size());
    for (const auto& item : data) {
        auto it = g_metaFlashModeMap_.find(static_cast<camera_flash_mode_enum_t>(item));
        if (it != g_metaFlashModeMap_.end()) {
            modes.emplace_back(it->second);
        }
    }
    return modes;
}

std::vector<ExposureMode> CameraAbilityBuilder::GetValidExposureModes(const std::vector<int32_t>& data)
{
    std::vector<ExposureMode> modes;
    modes.reserve(data.size());
    for (const auto& item : data) {
        auto it = g_metaExposureModeMap_.find(static_cast<camera_exposure_mode_enum_t>(item));
        if (it != g_metaExposureModeMap_.end()) {
            modes.emplace_back(it->second);
        }
    }
    return modes;
}

std::vector<FocusMode> CameraAbilityBuilder::GetValidFocusModes(const std::vector<int32_t>& data)
{
    std::vector<FocusMode> modes;
    modes.reserve(data.size());
    for (const auto& item : data) {
        auto it = g_metaFocusModeMap_.find(static_cast<camera_focus_mode_enum_t>(item));
        if (it != g_metaFocusModeMap_.end()) {
            modes.emplace_back(it->second);
        }
    }
    return modes;
}

std::vector<float> CameraAbilityBuilder::GetValidExposureBiasRange(const std::vector<int32_t>& data)
{
    size_t validSize = 2;
    if (data.size() != validSize || data[0] > data[1]) {
        return {};
    }
    return { static_cast<float>(data[0]), static_cast<float>(data[1]) };
}

std::vector<float> CameraAbilityBuilder::GetValidZoomRatioRange(const std::vector<int32_t>& data)
{
    constexpr float factor = 100.0;
    size_t validSize = 2;
    if (data.size() != validSize) {
        return {};
    }
    float minZoom = data[0] / factor;
    float maxZoom = data[1] / factor;
    return { minZoom, maxZoom };
}

std::vector<BeautyType> CameraAbilityBuilder::GetValidBeautyTypes(const std::vector<int32_t>& data)
{
    std::vector<BeautyType> types;
    types.reserve(data.size());
    for (const auto& item : data) {
        auto it = g_metaBeautyTypeMap_.find(static_cast<camera_beauty_type_t>(item));
        if (it != g_metaBeautyTypeMap_.end()) {
            types.emplace_back(it->second);
        }
    }
    return types;
}

std::vector<int32_t> CameraAbilityBuilder::GetValidBeautyRange(BeautyType beautyType, const std::vector<int32_t>& data)
{
    std::vector<int32_t> range;
    if (beautyType == BeautyType::SKIN_TONE) {
        constexpr int32_t skinToneOff = -1;
        range.push_back(skinToneOff);
    }
    range.insert(range.end(), data.begin(), data.end());
    return range;
}

void CameraAbilityBuilder::ProcessBeautyAbilityTag(
    sptr<CameraAbility> ability, uint32_t tagId, const std::vector<int32_t>& data)
{
    BeautyType beautyType;
    auto it = g_metaBeautyAbilityMap_.find(static_cast<camera_device_metadata_tag_t>(tagId));
    if (it != g_metaBeautyAbilityMap_.end()) {
        beautyType = it->second;
        ability->supportedBeautyRangeMap_[beautyType] = GetValidBeautyRange(beautyType, data);
    }
}

std::vector<ColorEffect> CameraAbilityBuilder::GetValidColorEffects(const std::vector<int32_t>& data)
{
    std::vector<ColorEffect> colorEffects;
    colorEffects.reserve(data.size());
    for (const auto& item : data) {
        auto it = g_metaColorEffectMap_.find(static_cast<camera_xmage_color_type_t>(item));
        if (it != g_metaColorEffectMap_.end()) {
            colorEffects.emplace_back(it->second);
        }
    }
    return colorEffects;
}

std::vector<ColorSpace> CameraAbilityBuilder::GetValidColorSpaces(const std::vector<int32_t>& data)
{
    std::vector<ColorSpace> colorSpaces;
    colorSpaces.reserve(data.size());
    for (const auto& item : data) {
        auto it = g_metaColorSpaceMap_.find(static_cast<CM_ColorSpaceType>(item));
        if (it != g_metaColorSpaceMap_.end()) {
            colorSpaces.emplace_back(it->second);
        }
    }
    return colorSpaces;
}

bool CameraAbilityBuilder::IsSupportMacro(const std::vector<int32_t>& data)
{
    if (data.size() != 1) {
        return false;
    }
    return static_cast<camera_macro_supported_type_t>(data[0]) == OHOS_CAMERA_MACRO_SUPPORTED;
}

std::vector<VideoStabilizationMode> CameraAbilityBuilder::GetValidVideoStabilizationModes(
    const std::vector<int32_t>& data)
{
    std::vector<VideoStabilizationMode> modes;
    modes.reserve(data.size());
    for (const auto& item : data) {
        auto it = g_metaVideoStabModesMap_.find(static_cast<CameraVideoStabilizationMode>(item));
        if (it != g_metaVideoStabModesMap_.end()) {
            modes.emplace_back(it->second);
        }
    }
    return modes;
}

std::vector<PortraitEffect> CameraAbilityBuilder::GetValidPortraitEffects(const std::vector<int32_t>& data)
{
    std::vector<PortraitEffect> portraitEffects;
    portraitEffects.reserve(data.size());
    for (const auto& item : data) {
        auto it = g_metaToFwPortraitEffect_.find(static_cast<camera_portrait_effect_type_t>(item));
        if (it != g_metaToFwPortraitEffect_.end()) {
            portraitEffects.emplace_back(it->second);
        }
    }
    return portraitEffects;
}

void CameraAbilityBuilder::SetModeSpecTagField(
    sptr<CameraAbility> ability, int32_t modeName, common_metadata_header_t* metadata, uint32_t tagId, int32_t specId)
{
    std::vector<int32_t> data = GetData(modeName, metadata, tagId, specId);
    switch (tagId) {
        case OHOS_ABILITY_FLASH_MODES: {
            ability->supportedFlashModes_ = GetValidFlashModes(data);
            break;
        }
        case OHOS_ABILITY_EXPOSURE_MODES: {
            ability->supportedExposureModes_ = GetValidExposureModes(data);
            break;
        }
        case OHOS_ABILITY_AE_COMPENSATION_RANGE: {
            ability->exposureBiasRange_ = GetValidExposureBiasRange(data);
            break;
        }
        case OHOS_ABILITY_FOCUS_MODES: {
            ability->supportedFocusModes_ = GetValidFocusModes(data);
            break;
        }
        case OHOS_ABILITY_SCENE_ZOOM_CAP: {
            ability->zoomRatioRange_ = GetValidZoomRatioRange(data);
            break;
        }
        case OHOS_ABILITY_SUPPORTED_COLOR_MODES: {
            ability->supportedColorEffects_ = GetValidColorEffects(data);
            break;
        }
        case OHOS_ABILITY_AVAILABLE_COLOR_SPACES: {
            ability->supportedColorSpaces_ = GetValidColorSpaces(data);
            break;
        }
        case OHOS_ABILITY_SCENE_MACRO_CAP: {
            ability->isMacroSupported_ = IsSupportMacro(data);
            break;
        }
        case OHOS_ABILITY_VIDEO_STABILIZATION_MODES: {
            ability->supportedVideoStabilizationMode_ = GetValidVideoStabilizationModes(data);
            break;
        }
        default:
            break;
    }
}

void CameraAbilityBuilder::SetOtherTag(sptr<CameraAbility> ability, int32_t modeName, sptr<CaptureSession> session)
{
    ability->supportedFlashModes_ = session->GetSupportedFlashModes();
    ability->supportedExposureModes_ = session->GetSupportedExposureModes();
    ability->supportedFocusModes_ = session->GetSupportedFocusModes();
    ability->exposureBiasRange_ = session->GetExposureBiasRange();
    if (!ability->zoomRatioRange_.has_value()) {
        ability->zoomRatioRange_ = session->GetZoomRatioRange();
    }
    ability->supportedBeautyTypes_ = session->GetSupportedBeautyTypes();
    for (auto it : g_fwkBeautyTypeMap_) {
        ability->supportedBeautyRangeMap_[it.first] = session->GetSupportedBeautyRange(it.first);
    }
    ability->supportedColorEffects_ = session->GetSupportedColorEffects();
    ability->supportedColorSpaces_ = session->GetSupportedColorSpaces();
    switch (modeName) {
        case SceneMode::CAPTURE: {
            if (!ability->isMacroSupported_.has_value()) {
                ability->isMacroSupported_ = session->IsMacroSupported();
            }
            break;
        }
        case SceneMode::VIDEO: {
            if (!ability->isMacroSupported_.has_value()) {
                ability->isMacroSupported_ = session->IsMacroSupported();
            }
            ability->supportedVideoStabilizationMode_ = session->GetSupportedStabilizationMode();
            break;
        }
        case SceneMode::PORTRAIT: {
            ability->supportedPortraitEffects_ = session->GetSupportedPortraitEffects();
            session->GetSupportedVirtualApertures(ability->supportedVirtualApertures_);
            session->GetSupportedPhysicalApertures(ability->supportedPhysicalApertures_);
            break;
        }
        default:
            break;
    }
}
} // namespace CameraStandard
} // namespace OHOS
