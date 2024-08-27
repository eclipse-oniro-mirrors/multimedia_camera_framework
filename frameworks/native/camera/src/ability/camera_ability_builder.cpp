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

bool CameraAbilityBuilder::IsSupportMacro(const std::vector<int32_t>& data)
{
    if (data.size() != 1) {
        return false;
    }
    return static_cast<camera_macro_supported_type_t>(data[0]) == OHOS_CAMERA_MACRO_SUPPORTED;
}

void CameraAbilityBuilder::SetModeSpecTagField(
    sptr<CameraAbility> ability, int32_t modeName, common_metadata_header_t* metadata, uint32_t tagId, int32_t specId)
{
    std::vector<int32_t> data = GetData(modeName, metadata, tagId, specId);
    switch (tagId) {
        case OHOS_ABILITY_SCENE_ZOOM_CAP: {
            ability->zoomRatioRange_ = GetValidZoomRatioRange(data);
            break;
        }
        case OHOS_ABILITY_SCENE_MACRO_CAP: {
            ability->isMacroSupported_ = IsSupportMacro(data);
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
    ability->supportedBeautyTypes_ = session->GetSupportedBeautyTypes();
    for (auto it : g_fwkBeautyTypeMap_) {
        ability->supportedBeautyRangeMap_[it.first] = session->GetSupportedBeautyRange(it.first);
    }
    ability->supportedColorEffects_ = session->GetSupportedColorEffects();
    ability->supportedColorSpaces_ = session->GetSupportedColorSpaces();

    SceneFeature feature = SceneFeature::FEATURE_MOON_CAPTURE_BOOST;
    while (feature < SceneFeature::FEATURE_ENUM_MAX) {
        if (session->IsFeatureSupported(feature)) {
            ability->supportedSceneFeature_.emplace_back(feature);
        }
        feature = static_cast<SceneFeature>(static_cast<int32_t>(feature) + 1);
    }

    switch (modeName) {
        case SceneMode::CAPTURE: {
            break;
        }
        case SceneMode::VIDEO: {
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
