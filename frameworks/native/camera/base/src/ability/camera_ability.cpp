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
#include "ability/camera_ability.h"
#include "session/capture_session.h"
#include "camera_util.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {

constexpr size_t VALID_RANGE_SIZE = 2;

bool g_isValidZoomRaioRange(std::vector<float> range)
{
    return range.size() == VALID_RANGE_SIZE && range[0] <= range[1];
}

bool CameraAbility::HasFlash()
{
    bool onlyHasCloseMode = supportedFlashModes_.size() == 1 && supportedFlashModes_[0] == FLASH_MODE_CLOSE;
    return !supportedFlashModes_.empty() && !onlyHasCloseMode;
}

bool CameraAbility::IsFlashModeSupported(FlashMode flashMode)
{
    return std::find(
        supportedFlashModes_.begin(), supportedFlashModes_.end(), flashMode) != supportedFlashModes_.end();
}

std::vector<FlashMode> CameraAbility::GetSupportedFlashModes()
{
    return supportedFlashModes_;
}

bool CameraAbility::IsExposureModeSupported(ExposureMode exposureMode)
{
    return std::find(
        supportedExposureModes_.begin(), supportedExposureModes_.end(), exposureMode) != supportedExposureModes_.end();
}

std::vector<ExposureMode> CameraAbility::GetSupportedExposureModes()
{
    return supportedExposureModes_;
}

std::vector<float> CameraAbility::GetExposureBiasRange()
{
    return exposureBiasRange_;
}

std::vector<FocusMode> CameraAbility::GetSupportedFocusModes()
{
    return supportedFocusModes_;
}

bool CameraAbility::IsFocusModeSupported(FocusMode focusMode)
{
    return std::find(supportedFocusModes_.begin(), supportedFocusModes_.end(), focusMode) != supportedFocusModes_.end();
}

// LCOV_EXCL_START
bool CameraAbility::IsFocusRangeTypeSupported(FocusRangeType focusRangeType)
{
    return std::find(supportedFocusRangeTypes_.begin(), supportedFocusRangeTypes_.end(), focusRangeType) !=
        supportedFocusRangeTypes_.end();
}

bool CameraAbility::IsFocusDrivenTypeSupported(FocusDrivenType focusDrivenType)
{
    return std::find(supportedFocusDrivenTypes_.begin(), supportedFocusDrivenTypes_.end(), focusDrivenType) !=
        supportedFocusDrivenTypes_.end();
}
// LCOV_EXCL_STOP

std::vector<float> CameraAbility::GetZoomRatioRange()
{
    return zoomRatioRange_.value_or(std::vector<float>{1.0f, 1.0f});
}

std::vector<BeautyType> CameraAbility::GetSupportedBeautyTypes()
{
    return supportedBeautyTypes_;
}

std::vector<int32_t> CameraAbility::GetSupportedBeautyRange(BeautyType beautyType)
{
    auto it = supportedBeautyRangeMap_.find(beautyType);
    return it != supportedBeautyRangeMap_.end() ? it->second : std::vector<int32_t> {};
}

std::vector<ColorEffect> CameraAbility::GetSupportedColorEffects()
{
    return supportedColorEffects_;
}

std::vector<ColorSpace> CameraAbility::GetSupportedColorSpaces()
{
    return supportedColorSpaces_;
}

bool CameraAbility::IsMacroSupported()
{
    return isMacroSupported_.value_or(false);
}

// LCOV_EXCL_START
bool CameraAbility::IsDepthFusionSupported()
{
    return isDepthFusionSupported_.value_or(false);
}

std::vector<float> CameraAbility::GetDepthFusionThreshold()
{
    return getDepthFusionThreshold_.value_or(std::vector<float>{1.0f, 1.0f});
}
// LCOV_EXCL_STOP

std::vector<PortraitEffect> CameraAbility::GetSupportedPortraitEffects()
{
    return supportedPortraitEffects_;
}

std::vector<float> CameraAbility::GetSupportedVirtualApertures()
{
    return supportedVirtualApertures_;
}

std::vector<std::vector<float>> CameraAbility::GetSupportedPhysicalApertures()
{
    return supportedPhysicalApertures_;
}

std::vector<VideoStabilizationMode> CameraAbility::GetSupportedStabilizationMode()
{
    return supportedVideoStabilizationMode_;
}

bool CameraAbility::IsVideoStabilizationModeSupported(VideoStabilizationMode stabilizationMode)
{
    auto it = std::find(
        supportedVideoStabilizationMode_.begin(), supportedVideoStabilizationMode_.end(), stabilizationMode);
    return it != supportedVideoStabilizationMode_.end();
}

std::vector<uint32_t> CameraAbility::GetSupportedExposureRange()
{
    return supportedExposureRange_;
}

bool CameraAbility::IsFeatureSupported(SceneFeature sceneFeature)
{
    return std::find(
        supportedSceneFeature_.begin(), supportedSceneFeature_.end(), sceneFeature) != supportedSceneFeature_.end();
}

bool CameraAbility::IsLcdFlashSupported()
{
    return isLcdFlashSupported_;
}

bool CameraAbility::IsImageStabilizationGuideSupported()
{
    return isImageStabilizationGuideSupported_;
}

std::vector<NightSubMode> CameraAbility::GetSupportedNightSubModeTypes()
{
    return supportedNightSubModes_;
}

bool CameraAbility::IsConstellationDrawingSupported()
{
    return isConstellationDrawingSupported;
}

std::vector<uint32_t> CameraAbility::GetExposureRange()
{
    return supportedManalExposureRange_;
}

std::vector<PortraitThemeType> CameraAbility::GetSupportedPortraitThemeTypes()
{
    return supportedPortraitThemeTypes_;
}

bool CameraAbility::IsPortraitThemeSupported()
{
    return isPortraitThemeSupported_;
}

void CameraAbility::DumpCameraAbilityInfo()
{
    auto logFunc = [](const std::string& label, const auto& container) {
        std::string vecStr = Container2String(container.begin(), container.end());
        MEDIA_DEBUG_LOG("%{public}s: %{public}s", label.c_str(), vecStr.c_str());
    };

    logFunc("Supported Flash Modes", supportedFlashModes_);
    logFunc("Supported Exposure Modes", supportedExposureModes_);
    logFunc("Exposure Bias Range", exposureBiasRange_);
    logFunc("Supported Focus Modes", supportedFocusModes_);
    logFunc("Supported Color Effects", supportedColorEffects_);
    logFunc("Supported Color Spaces", supportedColorSpaces_);
    logFunc("Supported Portrait Effects", supportedPortraitEffects_);
    logFunc("Supported Video Stabilization Modes", supportedVideoStabilizationMode_);
    logFunc("Supported Beauty Types", supportedBeautyTypes_);
    logFunc("Supported Exposure Range", supportedExposureRange_);
    logFunc("Supported Scene Feature", supportedSceneFeature_);
    logFunc("sketchFovRatio data", sketchFovRatio_);
    logFunc("Supported night manal exposure range", supportedManalExposureRange_);
    logFunc("Zoom Ratio Range", zoomRatioRange_.value_or(std::vector<float>{}));
    logFunc("Depth Fusion Threshold", getDepthFusionThreshold_.value_or(std::vector<float>{}));
    logFunc("Supported Virtual Apertures", supportedVirtualApertures_);
    for (const auto& [type, range] : supportedBeautyRangeMap_) {
        std::string vecStr = Container2String(range.begin(), range.end());
        MEDIA_DEBUG_LOG("Beauty Types: %{public}d Supported Beauty Ranges: %{public}s", type, vecStr.c_str());
    }
    for (const auto& apertureList : supportedPhysicalApertures_) {
        logFunc("Supported Physical Apertures", apertureList);
    }
    MEDIA_DEBUG_LOG("Macro Supported: %{public}d", isMacroSupported_.value_or(false));
    MEDIA_DEBUG_LOG("Depth Fusion Supported: %{public}d", isDepthFusionSupported_.value_or(false));
    MEDIA_DEBUG_LOG("Sketch Supported: %{public}d", isSketchSupported_);
}

CameraAbilityContainer::~CameraAbilityContainer()
{
    conflictAbilities_.clear();
}

// LCOV_EXCL_START
void CameraAbilityContainer::OnAbilityChange()
{
    auto session = session_.promote();
    CHECK_RETURN(session == nullptr);
    MEDIA_DEBUG_LOG("CameraAbilityContainer OnAbilityChange");
    session->ExecuteAbilityChangeCallback();
}
// LCOV_EXCL_STOP

CameraAbilityContainer::CameraAbilityContainer(std::vector<sptr<CameraAbility>> abilities,
    std::vector<sptr<CameraAbility>> conflictAbilities, wptr<CaptureSession> session)
    : session_(session), conflictAbilities_(conflictAbilities)
{
    PrepareSpecMaximumValue(abilities);
}

void CameraAbilityContainer::PrepareSpecMaximumValue(std::vector<sptr<CameraAbility>>& abilities)
{
    std::optional<std::vector<float>> tempRange;

    for (const auto& ability : abilities) {
        CHECK_CONTINUE(!ability);

        if (!IsMacroSupportedInSpec_) {
            IsMacroSupportedInSpec_ = ability->IsMacroSupported();
        }

        auto range = ability->GetZoomRatioRange();
        CHECK_CONTINUE(!g_isValidZoomRaioRange(range));
        if (!tempRange.has_value()) {
            tempRange = range;
        } else {
            // LCOV_EXCL_START
            float min = std::min(tempRange.value()[0], range[0]);
            float max = std::max(tempRange.value()[1], range[1]);
            tempRange = std::vector<float>{min, max};
            // LCOV_EXCL_STOP
        }
        
        if (ability->GetSupportedNightSubModeTypes().size() > nightSubModesInSpec_.size()) {
            nightSubModesInSpec_ = ability->GetSupportedNightSubModeTypes();
        }

        if (ability->GetSupportedFlashModes().size() > supportedFlashModesInSpec_.size()) {
            supportedFlashModesInSpec_ = ability->GetSupportedFlashModes();
        }

        if (ability->GetSupportedColorEffects().size() > supportedColorEffectsInSpec_.size()) {
            supportedColorEffectsInSpec_ = ability->GetSupportedColorEffects();
        }

        if (ability->GetSupportedColorSpaces().size() > supportedColorSpacesInSpec_.size()) {
            supportedColorSpacesInSpec_ = ability->GetSupportedColorSpaces();
        }

        if (ability->GetExposureRange().size() > supportedManalExposureRangeInSpec_.size()) {
            supportedManalExposureRangeInSpec_ = ability->GetExposureRange();
        }

        if (!isConstellationDrawingSupportedInSpec_) {
            isConstellationDrawingSupportedInSpec_ = ability->IsConstellationDrawingSupported();
        }

        if (!hasFlashInSpec_) {
            hasFlashInSpec_ = ability->HasFlash();
        }
    }

    zoomRatioRangeInSpec_ = tempRange.value_or(std::vector<float>{1.0, 1.0});
    abilities.clear();
}

// LCOV_EXCL_START
void CameraAbilityContainer::FilterByZoomRatio(float zoomRatio)
{
    zoomRatioSet_ = zoomRatio;
    CHECK_RETURN(!lastIsMacroSupported_.has_value());
    bool oldValue = lastIsMacroSupported_.value();
    bool newValue = IsMacroSupported();
    MEDIA_INFO_LOG("CameraAbilityContainer macroValue %{public}d", static_cast<int32_t>(newValue));
    if (oldValue != newValue) {
        OnAbilityChange();
    }
}

void CameraAbilityContainer::FilterByMacro(bool enableMacro)
{
    enableMacroSet_ = enableMacro;
    CHECK_RETURN(!lastGetZoomRatioRange_.has_value());
    std::vector<float> oldValue = lastGetZoomRatioRange_.value();
    std::vector<float> newValue = GetZoomRatioRange();
    MEDIA_INFO_LOG("CameraAbilityContainer zoomValue %{public}f %{public}f", newValue[0], newValue[1]);
    if (oldValue[0] != newValue[0] || oldValue[1] != newValue[1]) {
        OnAbilityChange();
    }
}

void CameraAbilityContainer::FilterByNightSubMode(NightSubMode nightSubMode)
{
    nightSubModeSet_ = nightSubMode;
    for (const auto &ability : conflictAbilities_) {
        CHECK_CONTINUE(ability == nullptr);
        std::vector<NightSubMode> subModes = ability->GetSupportedNightSubModeTypes();
        if (subModes.size() == 1 && nightSubMode == subModes[0]) {
            nightSubModeAbility_ = ability;
        }
    }
    OnAbilityChange();
}

std::vector<float> CameraAbilityContainer::GetZoomRatioRange()
{
    if (nightSubModeSet_.has_value()) {
        return nightSubModeAbility_ ? nightSubModeAbility_->GetZoomRatioRange() : std::vector<float>{1.0f, 1.0f};
    }
    bool enableMacro = enableMacroSet_.value_or(false);
    if (!g_isValidZoomRaioRange(zoomRatioRangeInSpec_)) {
        MEDIA_ERR_LOG("zoomRatioRangeInSpec_ invalid data");
        return std::vector<float>{1.0f, 1.0f};
    }
    for (const auto& ability : conflictAbilities_) {
        CHECK_CONTINUE(ability == nullptr);
        std::vector<float> range = ability->GetZoomRatioRange();
        bool isValidRange = enableMacro == ability->IsMacroSupported() && g_isValidZoomRaioRange(range);
        if (isValidRange) {
            float min = std::max(zoomRatioRangeInSpec_[0], range[0]);
            float max = std::min(zoomRatioRangeInSpec_[1], range[1]);
            lastGetZoomRatioRange_ = {min, max};
            return {min, max};
        }
    }
    lastGetZoomRatioRange_ = zoomRatioRangeInSpec_;
    return zoomRatioRangeInSpec_;
}

bool CameraAbilityContainer::IsMacroSupported()
{
    float zoomRatio = zoomRatioSet_.value_or(1.0f);
    for (const auto& ability : conflictAbilities_) {
        CHECK_CONTINUE(ability == nullptr);
        std::vector<float> range = ability->GetZoomRatioRange();
        bool isValidRange = g_isValidZoomRaioRange(range) && ability->IsMacroSupported();
        if (isValidRange) {
            bool isSupport = IsMacroSupportedInSpec_ && (range[0] <= zoomRatio && zoomRatio <= range[1]);
            lastIsMacroSupported_ = isSupport;
            return isSupport;
        }
    }
    lastIsMacroSupported_ = IsMacroSupportedInSpec_;
    return IsMacroSupportedInSpec_;
}

std::vector<NightSubMode> CameraAbilityContainer::GetSupportedNightSubModeTypes()
{
    return nightSubModesInSpec_;
}

bool CameraAbilityContainer::IsConstellationDrawingSupported()
{
    CHECK_RETURN_RET(!nightSubModeSet_.has_value(), isConstellationDrawingSupportedInSpec_);
    return nightSubModeAbility_ ? nightSubModeAbility_->IsConstellationDrawingSupported() : false;
}

bool CameraAbilityContainer::HasFlash()
{
    CHECK_RETURN_RET(!nightSubModeSet_.has_value(), hasFlashInSpec_);
    return nightSubModeAbility_ ? nightSubModeAbility_->HasFlash() : false;
}

std::vector<FlashMode> CameraAbilityContainer::GetSupportedFlashModes()
{
    CHECK_RETURN_RET(!nightSubModeSet_.has_value(), supportedFlashModesInSpec_);
    return nightSubModeAbility_ ? nightSubModeAbility_->GetSupportedFlashModes() : std::vector<FlashMode>{};
}

std::vector<uint32_t> CameraAbilityContainer::GetExposureRange()
{
    CHECK_RETURN_RET(!nightSubModeSet_.has_value(), supportedManalExposureRangeInSpec_);
    return nightSubModeAbility_ ? nightSubModeAbility_->GetExposureRange() : std::vector<uint32_t>{};
}

std::vector<ColorEffect> CameraAbilityContainer::GetSupportedColorEffects()
{
    CHECK_RETURN_RET(!nightSubModeSet_.has_value(), supportedColorEffectsInSpec_);
    return nightSubModeAbility_ ? nightSubModeAbility_->GetSupportedColorEffects() : std::vector<ColorEffect>{};
}

std::vector<ColorSpace> CameraAbilityContainer::GetSupportedColorSpaces()
{
    CHECK_RETURN_RET(!nightSubModeSet_.has_value(), supportedColorSpacesInSpec_);
    return nightSubModeAbility_ ? nightSubModeAbility_->GetSupportedColorSpaces() : std::vector<ColorSpace>{};
}
// LCOV_EXCL_STOP
} // namespace CameraStandard
} // namespace OHOS