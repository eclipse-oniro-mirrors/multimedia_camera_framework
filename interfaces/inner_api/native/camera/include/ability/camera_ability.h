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

#ifndef OHOS_CAMERA_CAMERA_ABILITY_H
#define OHOS_CAMERA_CAMERA_ABILITY_H

#include "refbase.h"
#include <map>
#include <vector>
#include <cstdint>
#include "ability/camera_ability_const.h"
#include "session/capture_scene_const.h"

namespace OHOS {
namespace CameraStandard {

class CameraAbility : public RefBase {
public:
    CameraAbility() = default;
    virtual ~CameraAbility() = default;
    void DumpCameraAbilityInfo();

    bool HasFlash();
    bool IsFlashModeSupported(FlashMode flashMode);
    std::vector<FlashMode> GetSupportedFlashModes();
    bool IsExposureModeSupported(ExposureMode exposureMode);
    std::vector<ExposureMode> GetSupportedExposureModes();
    std::vector<float> GetExposureBiasRange();
    std::vector<FocusMode> GetSupportedFocusModes();
    bool IsFocusModeSupported(FocusMode focusMode);
    bool IsFocusRangeTypeSupported(FocusRangeType focusRangeType);
    bool IsFocusDrivenTypeSupported(FocusDrivenType focusDrivenType);
    std::vector<float> GetZoomRatioRange();
    std::vector<BeautyType> GetSupportedBeautyTypes();
    std::vector<int32_t> GetSupportedBeautyRange(BeautyType type);
    std::vector<ColorEffect> GetSupportedColorEffects();
    std::vector<ColorSpace> GetSupportedColorSpaces();
    bool IsMacroSupported();
    bool IsDepthFusionSupported();
    std::vector<float> GetDepthFusionThreshold();
    std::vector<PortraitEffect> GetSupportedPortraitEffects();
    std::vector<float> GetSupportedVirtualApertures();
    std::vector<std::vector<float>> GetSupportedPhysicalApertures();
    std::vector<VideoStabilizationMode> GetSupportedStabilizationMode();
    bool IsVideoStabilizationModeSupported(VideoStabilizationMode stabilizationMode);
    std::vector<uint32_t> GetSupportedExposureRange();
    bool IsFeatureSupported(SceneFeature sceneFeature);
    bool IsLcdFlashSupported();
    bool IsImageStabilizationGuideSupported();
    std::vector<NightSubMode> GetSupportedNightSubModeTypes();
    bool IsConstellationDrawingSupported();
    std::vector<uint32_t> GetExposureRange();
    std::vector<PortraitThemeType> GetSupportedPortraitThemeTypes();
    bool IsPortraitThemeSupported();

    std::vector<FlashMode> supportedFlashModes_;
    std::vector<ExposureMode> supportedExposureModes_;
    std::vector<float> exposureBiasRange_;
    std::vector<FocusMode> supportedFocusModes_;
    std::vector<FocusRangeType> supportedFocusRangeTypes_ = {};
    std::vector<FocusDrivenType> supportedFocusDrivenTypes_ = {};
    std::vector<BeautyType> supportedBeautyTypes_;
    std::map<BeautyType, std::vector<int32_t>> supportedBeautyRangeMap_;
    std::vector<ColorEffect> supportedColorEffects_;
    std::vector<ColorSpace> supportedColorSpaces_;
    std::vector<PortraitEffect> supportedPortraitEffects_;
    std::vector<float> supportedVirtualApertures_;
    std::vector<std::vector<float>> supportedPhysicalApertures_;
    std::vector<VideoStabilizationMode> supportedVideoStabilizationMode_;
    std::vector<uint32_t> supportedExposureRange_;
    std::vector<SceneFeature> supportedSceneFeature_;
    bool isLcdFlashSupported_;
    bool isImageStabilizationGuideSupported_;
    std::vector<NightSubMode> supportedNightSubModes_;
    bool isConstellationDrawingSupported;
    std::optional<std::vector<float>> zoomRatioRange_;
    std::optional<bool> isMacroSupported_;
    std::optional<bool> isDepthFusionSupported_;
    std::optional<std::vector<float>> getDepthFusionThreshold_;
    std::vector<PortraitThemeType> supportedPortraitThemeTypes_;
    bool isPortraitThemeSupported_;
    bool isSketchSupported_;
    bool isManalExposureSupported_;
    std::vector<uint32_t> supportedManalExposureRange_;
    std::optional<float> canEnableSketchRatio_;
    std::vector<float> sketchFovRatio_;
};

class CaptureSession;
class CameraAbilityContainer : public RefBase {
public:
    ~CameraAbilityContainer();
    void PrepareSpecMaximumValue(std::vector<sptr<CameraAbility>>& abilities);

    CameraAbilityContainer(std::vector<sptr<CameraAbility>> abilities,
                           std::vector<sptr<CameraAbility>> conflictAbilities,
                           wptr<CaptureSession> session);
    void FilterByZoomRatio(float zoomRatio);
    void FilterByMacro(bool enableMacro);
    void FilterByNightSubMode(NightSubMode nightSubMode);

    std::vector<float> GetZoomRatioRange();
    bool IsMacroSupported();
    bool IsConstellationDrawingSupported();
    std::vector<NightSubMode> GetSupportedNightSubModeTypes();
    bool HasFlash();
    std::vector<uint32_t> GetExposureRange();
    std::vector<ColorEffect> GetSupportedColorEffects();
    std::vector<ColorSpace> GetSupportedColorSpaces();
    std::vector<FlashMode> GetSupportedFlashModes();

private:

    void OnAbilityChange();

private:
    wptr<CaptureSession> session_;
    std::vector<sptr<CameraAbility>> conflictAbilities_;

    bool IsMacroSupportedInSpec_ = false;
    std::vector<float> zoomRatioRangeInSpec_;
    std::vector<NightSubMode> nightSubModesInSpec_;
    std::vector<FlashMode> supportedFlashModesInSpec_;
    std::vector<ColorEffect> supportedColorEffectsInSpec_;
    std::vector<ColorSpace> supportedColorSpacesInSpec_;
    std::vector<uint32_t> supportedManalExposureRangeInSpec_;
    bool isConstellationDrawingSupportedInSpec_ = false;
    bool hasFlashInSpec_ = false;

    std::optional<std::vector<float>> lastGetZoomRatioRange_;
    std::optional<bool> lastIsMacroSupported_;

    std::optional<float> zoomRatioSet_;
    std::optional<bool> enableMacroSet_;
    std::optional<NightSubMode> nightSubModeSet_;
    sptr<CameraAbility> nightSubModeAbility_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CAMERA_ABILITY_H