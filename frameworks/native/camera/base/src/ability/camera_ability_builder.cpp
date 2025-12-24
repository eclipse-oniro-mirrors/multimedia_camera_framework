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
#include "camera_util.h"
#include "camera_security_utils.h"

namespace OHOS {
namespace CameraStandard {

std::vector<sptr<CameraAbility>> CameraAbilityBuilder::GetAbility(int32_t modeName, common_metadata_header_t* metadata,
    const std::set<int32_t>& specIds, sptr<CaptureSession> session, bool isForApp)
{
    AvailableConfig availableConfig;
    sceneMode_ = static_cast<SceneMode>(modeName);
    CameraAbilityParseUtil::GetAvailableConfiguration(modeName, metadata, availableConfig);
    std::vector<sptr<CameraAbility>> abilities;
    MEDIA_DEBUG_LOG("enter CameraAbilityBuilder::GetAbility");
    for (const auto& configInfo : availableConfig.configInfos) {
        CHECK_CONTINUE(specIds.find(configInfo.specId) == specIds.end());
        sptr<CameraAbility> ability = new CameraAbility();
        CHECK_CONTINUE_ELOG(ability == nullptr, "alloc CameraAbility error");
        for (const auto& tagId : configInfo.tagIds) {
            SetModeSpecTagField(ability, modeName, metadata, tagId, configInfo.specId);
        }
        CHECK_EXECUTE(isForApp, SetOtherTag(ability, modeName, session));
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
        CHECK_CONTINUE_ELOG(conflictAbility == nullptr, "alloc CameraAbility error");
        for (const auto& tagInfo : configInfo.tagInfos) {
            SetModeSpecTagField(conflictAbility, modeName, metadata, tagInfo.first, tagInfo.second);
        }
        conflictAbility->DumpCameraAbilityInfo();
        conflictAbilities.push_back(conflictAbility);
    }
    return conflictAbilities;
}

const CameraAbilityBuilder::ExecuteFunctions& CameraAbilityBuilder::GetExecuteFunctions()
{
    static const ExecuteFunctions executeFunctions = {
        { OHOS_ABILITY_SCENE_ZOOM_CAP, &CameraAbilityBuilder::FillZoomRatioRange },
        { OHOS_ABILITY_SCENE_MACRO_CAP, &CameraAbilityBuilder::FillMacro},
        { OHOS_ABILITY_NIGHT_SUB_MODES, &CameraAbilityBuilder::FillNightSubModes},
        { OHOS_ABILITY_AVAILABLE_COLOR_SPACES, &CameraAbilityBuilder::FillColorSpaces},
        { OHOS_ABILITY_SCENE_SUPPORTED_COLOR_MODES, &CameraAbilityBuilder::FillColorEffects},
        { OHOS_ABILITY_CONSTELLATION_DRAWING, &CameraAbilityBuilder::FillConstellationDrawing},
        { OHOS_ABILITY_SCENE_FLASH_MODES, &CameraAbilityBuilder::FillFlashModes},
        { OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME, &CameraAbilityBuilder::FillNightModeExposureTime},
        { OHOS_ABILITY_SKETCH_ENABLE_RATIO, &CameraAbilityBuilder::FillSketchEnableRatio},
        { OHOS_ABILITY_SKETCH_REFERENCE_FOV_RATIO, &CameraAbilityBuilder::FillSketchReferenceFovRatio}};
    return executeFunctions;
}

MultiTypeArray CameraAbilityBuilder::GetData(
    int32_t modeName, common_metadata_header_t* metadata, uint32_t tagId, int32_t specId)
{
    if (cachedTagSet_.find(tagId) == cachedTagSet_.end()) {
        std::map<int32_t, MultiTypeArray> tagDataMap;
        CameraAbilityParseUtil::GetAbilityInfo(modeName, metadata, tagId, tagDataMap);
        cacheTagDataMap_[tagId] = tagDataMap;
        cachedTagSet_.insert(tagId);
    }

    auto itc = cacheTagDataMap_.find(tagId);
    CHECK_RETURN_RET(itc == cacheTagDataMap_.end(), {});
    auto& dataMap = itc->second;
    auto itd = dataMap.find(specId);
    return itd == dataMap.end() ? MultiTypeArray{} : itd->second;
}

std::vector<float> CameraAbilityBuilder::GetValidZoomRatioRange(const std::vector<int32_t>& data)
{
    constexpr float factor = 100.0;
    size_t validSize = 2;
    CHECK_RETURN_RET(data.size() != validSize, {});
    float minZoom = data[0] / factor;
    float maxZoom = data[1] / factor;
    return { minZoom, maxZoom };
}

bool CameraAbilityBuilder::CanAddColorSpace(ColorSpace colorSpace)
{
    return CameraSecurity::CheckSystemApp() ||
        !(colorSpace == ColorSpace::BT2020_HLG && sceneMode_ == SceneMode::CAPTURE);
}

std::vector<ColorSpace> CameraAbilityBuilder::GetValidColorSpaces(const std::vector<int32_t>& data)
{
    std::vector<ColorSpace> validColorSpaces;
    for (size_t i = 0; i < data.size(); i++) {
        auto it = g_metaColorSpaceMap_.find(static_cast<CM_ColorSpaceType>(data[i]));
        if (it != g_metaColorSpaceMap_.end() && CanAddColorSpace(it->second)) {
            validColorSpaces.emplace_back(it->second);
        }
    }
    return validColorSpaces;
}

bool CameraAbilityBuilder::IsSupportMacro(const std::vector<int32_t>& data)
{
    CHECK_RETURN_RET_ELOG(data.size() != 1, false, "IsSupportMacro, invalid data size");
    return static_cast<camera_macro_supported_type_t>(data[0]) == OHOS_CAMERA_MACRO_SUPPORTED;
}

void CameraAbilityBuilder::FillConstellationDrawing(MultiTypeArray &dataArray, sptr<CameraAbility> ability)
{
    auto data = dataArray.i32;
    ability->isConstellationDrawingSupported = (data.size() > 0 && data[0] == 1);
    CHECK_EXECUTE(ability->isConstellationDrawingSupported,
        ability->supportedSceneFeature_.emplace_back(SceneFeature::FEATURE_CONSTELLATION_DRAWING));
}

void CameraAbilityBuilder::FillNightModeExposureTime(MultiTypeArray &dataArray, sptr<CameraAbility> ability)
{
    auto data = dataArray.i32;
    ability->isManalExposureSupported_ = data.size() > 0;
    std::vector<uint32_t> uintVec;
    uintVec.reserve(data.size());
    std::transform(
        data.begin(), data.end(), std::back_inserter(uintVec), [](int32_t val) { return static_cast<uint32_t>(val); });
    ability->supportedManalExposureRange_ = uintVec;
}

void CameraAbilityBuilder::FillSketchEnableRatio(MultiTypeArray &dataArray, sptr<CameraAbility> ability)
{
    auto sketchData = dataArray.f;
    ability->isSketchSupported_ = sketchData.size() > 0;
    CHECK_EXECUTE(ability->isSketchSupported_, ability->canEnableSketchRatio_ = sketchData[0]);
}

void CameraAbilityBuilder::FillSketchReferenceFovRatio(MultiTypeArray &dataArray, sptr<CameraAbility> ability)
{
    auto sketchFovData = dataArray.f;
    ability->sketchFovRatio_ = sketchFovData;
}

void CameraAbilityBuilder::FillZoomRatioRange(MultiTypeArray &dataArray, sptr<CameraAbility> ability)
{
    ability->zoomRatioRange_ = GetValidZoomRatioRange(dataArray.i32);
}

void CameraAbilityBuilder::FillMacro(MultiTypeArray &dataArray, sptr<CameraAbility> ability)
{
    ability->isMacroSupported_ = IsSupportMacro(dataArray.i32);
}

void CameraAbilityBuilder::FillNightSubModes(MultiTypeArray &dataArray, sptr<CameraAbility> ability)
{
    g_transformValidData(dataArray.i32, g_metaNightSubModeMap_, ability->supportedNightSubModes_);
}

void CameraAbilityBuilder::FillColorSpaces(MultiTypeArray &dataArray, sptr<CameraAbility> ability)
{
    ability->supportedColorSpaces_ = GetValidColorSpaces(dataArray.i32);
}

void CameraAbilityBuilder::FillColorEffects(MultiTypeArray &dataArray, sptr<CameraAbility> ability)
{
    g_transformValidData(dataArray.i32, g_metaColorEffectMap_, ability->supportedColorEffects_);
}

void CameraAbilityBuilder::FillFlashModes(MultiTypeArray &dataArray, sptr<CameraAbility> ability)
{
    g_transformValidData(dataArray.i32, g_metaFlashModeMap_, ability->supportedFlashModes_);
}

void CameraAbilityBuilder::SetModeSpecTagField(
    sptr<CameraAbility> ability, int32_t modeName, common_metadata_header_t* metadata, uint32_t tagId, int32_t specId)
{
    MultiTypeArray dataArray = GetData(modeName, metadata, tagId, specId);
    auto executeFunctions = GetExecuteFunctions();
    auto it = executeFunctions.find(tagId);
    CHECK_RETURN_ELOG(it == executeFunctions.end(), "Tag: %{public}d cant find suitable function", tagId);
    (this->*((ExecuteFunc)it->second))(dataArray, ability);
}

void CameraAbilityBuilder::SetOtherTag(sptr<CameraAbility> ability, int32_t modeName, sptr<CaptureSession> session)
{
    CHECK_RETURN(session == nullptr);
    // LCOV_EXCL_START
    auto metadata = session->GetMetadata();
    CHECK_RETURN(metadata == nullptr);
    ability->isLcdFlashSupported_ = session->IsLcdFlashSupported();
    ability->supportedExposureModes_ = session->GetSupportedExposureModes();
    ability->supportedFocusModes_ = session->GetSupportedFocusModes();
    session->GetSupportedFocusRangeTypes(ability->supportedFocusRangeTypes_);
    session->GetSupportedFocusDrivenTypes(ability->supportedFocusDrivenTypes_);
    ability->exposureBiasRange_ = session->GetExposureBiasRange();
    ability->supportedBeautyTypes_ = session->GetSupportedBeautyTypes();
    for (auto it : g_fwkBeautyTypeMap_) {
        ability->supportedBeautyRangeMap_[it.first] = session->GetSupportedBeautyRange(it.first);
    }
    SceneFeature feature = SceneFeature::FEATURE_MOON_CAPTURE_BOOST;
    while (feature < SceneFeature::FEATURE_ENUM_MAX) {
        CHECK_EXECUTE(feature != SceneFeature::FEATURE_CONSTELLATION_DRAWING && session->IsFeatureSupported(feature),
            ability->supportedSceneFeature_.emplace_back(feature));
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
            session->GetSupportedPortraitThemeTypes(ability->supportedPortraitThemeTypes_);
            ability->isPortraitThemeSupported_ = session->IsPortraitThemeSupported();
            break;
        }
        case SceneMode::NIGHT: {
            ability->isImageStabilizationGuideSupported_ = session->IsImageStabilizationGuideSupported();
            ability->supportedNightSubModes_ = session->GetSupportedNightSubModeTypes();
            break;
        }
        default:
            break;
    }
    // LCOV_EXCL_STOP
}
} // namespace CameraStandard
} // namespace OHOS
