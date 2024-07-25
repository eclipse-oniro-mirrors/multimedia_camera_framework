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
    return !supportedFlashModes_.empty();
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
    if (it != supportedBeautyRangeMap_.end()) {
        return it->second;
    }
    return {};
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

    for (const auto& [type, range] : supportedBeautyRangeMap_) {
        std::string vecStr = Container2String(range.begin(), range.end());
        MEDIA_DEBUG_LOG("Beauty Types: %{public}d Supported Beauty Ranges: %{public}s", type, vecStr.c_str());
    }

    logFunc("Supported Virtual Apertures", supportedVirtualApertures_);

    for (const auto& apertureList : supportedPhysicalApertures_) {
        logFunc("Supported Physical Apertures", apertureList);
    }

    if (zoomRatioRange_.has_value()) {
        logFunc("Zoom Ratio Range", zoomRatioRange_.value());
    } else {
        MEDIA_DEBUG_LOG("Zoom Ratio Range: Not supported");
    }

    if (isMacroSupported_.has_value()) {
        MEDIA_DEBUG_LOG("Macro Supported: %{public}d", isMacroSupported_.value());
    } else {
        MEDIA_DEBUG_LOG("Macro Supported: Not supported");
    }
}

CameraAbilityContainer::~CameraAbilityContainer()
{
    conflictAbilities_.clear();
}

void CameraAbilityContainer::OnAbilityChange()
{
    auto session = session_.promote();
    if (session != nullptr) {
        MEDIA_DEBUG_LOG("CameraAbilityContainer OnAbilityChange");
        session->ExecuteAbilityChangeCallback();
    }
}

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
        if (!ability) {
            continue;
        }

        if (!IsMacroSupportedInSpec_) {
            IsMacroSupportedInSpec_ = ability->IsMacroSupported();
        }

        auto range = ability->GetZoomRatioRange();
        if (!g_isValidZoomRaioRange(range)) {
            continue;
        }
        if (!tempRange.has_value()) {
            tempRange = range;
        } else {
            float min = std::min(tempRange.value()[0], range[0]);
            float max = std::max(tempRange.value()[1], range[1]);
            tempRange = std::vector<float>{min, max};
        }
    }

    zoomRatioRangeInSpec_ = tempRange.value_or(std::vector<float>{1.0, 1.0});
    abilities.clear();
}

void CameraAbilityContainer::FilterByZoomRatio(float zoomRatio)
{
    zoomRatioSet_ = zoomRatio;
    if (lastIsMacroSupported_.has_value()) {
        bool oldValue = lastIsMacroSupported_.value();
        bool newValue = IsMacroSupported();
        MEDIA_INFO_LOG("CameraAbilityContainer macroValue %{public}d", static_cast<int32_t>(newValue));
        if (oldValue != newValue) {
            OnAbilityChange();
        }
    }
}

void CameraAbilityContainer::FilterByMacro(bool enableMacro)
{
    enableMacroSet_ = enableMacro;
    if (lastGetZoomRatioRange_.has_value()) {
        std::vector<float> oldValue = lastGetZoomRatioRange_.value();
        std::vector<float> newValue = GetZoomRatioRange();
        MEDIA_INFO_LOG("CameraAbilityContainer zoomValue %{public}f %{public}f", newValue[0], newValue[1]);
        if (oldValue[0] != newValue[0] || oldValue[1] != newValue[1]) {
            OnAbilityChange();
        }
    }
}

std::vector<float> CameraAbilityContainer::GetZoomRatioRange()
{
    bool enableMacro = enableMacroSet_.value_or(false);
    const auto& zoomSpec = zoomRatioRangeInSpec_;
    for (const auto& ability : conflictAbilities_) {
        if (ability == nullptr) {
            continue;
        }
        if (enableMacro == ability->IsMacroSupported()) {
            float min = std::max(zoomSpec[0], ability->GetZoomRatioRange()[0]);
            float max = std::min(zoomSpec[1], ability->GetZoomRatioRange()[1]);
            lastGetZoomRatioRange_ = {min, max};
            return {min, max};
        }
    }
    lastGetZoomRatioRange_ = zoomSpec;
    return zoomSpec;
}

bool CameraAbilityContainer::IsMacroSupported()
{
    float zoomRatio = zoomRatioSet_.value_or(1.0f);
    for (const auto& ability : conflictAbilities_) {
        if (ability == nullptr) {
            continue;
        }
        std::vector<float> range = ability->GetZoomRatioRange();
        if (g_isValidZoomRaioRange(range) && ability->IsMacroSupported()) {
            bool isSupport = IsMacroSupportedInSpec_ && (range[0] <= zoomRatio && zoomRatio <= range[1]);
            lastIsMacroSupported_ = isSupport;
            return isSupport;
        }
    }
    lastIsMacroSupported_ = IsMacroSupportedInSpec_;
    return IsMacroSupportedInSpec_;
}
} // namespace CameraStandard
} // namespace OHOS