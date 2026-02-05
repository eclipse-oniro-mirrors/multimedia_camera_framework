/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_CAPTURE_SESSION_FOR_SYS_H
#define OHOS_CAMERA_CAPTURE_SESSION_FOR_SYS_H

#include "session/capture_session.h"

namespace OHOS {
namespace CameraStandard {
class CaptureSessionForSys : public CaptureSession {
public:
    explicit CaptureSessionForSys(sptr<ICaptureSession> &captureSession) : CaptureSession(captureSession) {}
    virtual ~CaptureSessionForSys();

    /**
     * @brief Query whether given focus range type supported.
     * @param focusRangeType focus range type to query.
     * @param isSupported True is supported false otherwise.
     * @return Returns errCode.
     */
    int32_t IsFocusRangeTypeSupported(FocusRangeType focusRangeType, bool& isSupported);

    /**
     * @brief Get focus range type.
     * @param focusRangeType focus range type.
     * @return Returns errCode.
     */
    int32_t GetFocusRange(FocusRangeType& focusRangeType);

    /**
     * @brief Set focus range type.
     * @param focusRangeType focus range type to be set.
     * @return Returns errCode.
     */
    int32_t SetFocusRange(FocusRangeType focusRangeType);

    /**
     * @brief Query whether given focus driven type supported.
     * @param focusDrivenType focus driven type to query.
     * @param isSupported True is supported false otherwise.
     * @return Returns errCode.
     */
    int32_t IsFocusDrivenTypeSupported(FocusDrivenType focusDrivenType, bool& isSupported);

    /**
     * @brief Get focus driven type.
     * @param focusDrivenType focus driven type.
     * @return Returns errCode.
     */
    int32_t GetFocusDriven(FocusDrivenType& focusDrivenType);

    /**
     * @brief Set focus driven type.
     * @param focusDrivenType focus driven type to be set.
     * @return Returns errCode.
     */
    int32_t SetFocusDriven(FocusDrivenType focusDrivenType);

    /**
     * @brief Get the vector of color reservation types.
     * @param types vector of color reservation types.
     * @return Returns errCode.
     */
    int32_t GetSupportedColorReservationTypes(std::vector<ColorReservationType>& types);

    /**
     * @brief Get color reservation type.
     * @param colorReservationType color reservation type.
     * @return Returns errCode.
     */
    int32_t GetColorReservation(ColorReservationType& colorReservationType);

    /**
     * @brief Set color reservation type.
     * @param colorReservationType color reservation type to be set.
     * @return Returns errCode.
     */
    int32_t SetColorReservation(ColorReservationType colorReservationType);

    /**
     * @brief Get the supported Zoom point info.
     *
     * @param vector<ZoomPointInfo> of supported ZoomPointInfo.
     * @return Returns errCode.
     */
    int32_t GetZoomPointInfos(std::vector<ZoomPointInfo>& zoomPointInfoList);

    /**
     * @brief Gets the beauty effect in use.
     * @param type The type of beauty effect.
     * @return Returns errCode.
     */
    int32_t GetBeauty(BeautyType type);

    /**
     * @brief Sets a portrait theme type for a camera device.
     * @param type PortraitTheme type to be set.
     * @return Returns errCode.
     */
    int32_t SetPortraitThemeType(PortraitThemeType type);

    /**
     * @brief Set the color effect.
     */
    void SetColorEffect(ColorEffect colorEffect);

// Focus Distance
    /**
     * @brief Get the current FocusDistance.
     * @param distance current Focus Distance.
     * @return Returns errCode.
     */
    int32_t GetFocusDistance(float& distance);

    /**
     * @brief Check current status is support depth fusion or not.
     */
    bool IsDepthFusionSupported();

    /**
     * @brief Enable depth fusion.
     */
    int32_t EnableDepthFusion(bool isEnable);

    /**
     * @brief Get the depth fusion supported Zoom Ratio range,
     *
     * @return Returns vector<float> of depth fusion supported Zoom ratio range.
     */
    std::vector<float> GetDepthFusionThreshold();

    /**
     * @brief Get the depth fusion supported Zoom ratio range.
     *
     * @param vector<float> of depth fusion supported Zoom ratio range.
     * @return Returns errCode.
     */
    int32_t GetDepthFusionThreshold(std::vector<float>& depthFusionThreshold);

    /**
    * @brief Check curernt status is enabled depth fusion.
    */
    bool IsDepthFusionEnabled();

    

    /**
     * @brief Set the feature detection status callback.
     * which will be called when there is feature detection state change.
     *
     * @param The FeatureDetectionStatusCallback pointer.
     */
    void SetFeatureDetectionStatusCallback(std::shared_ptr<FeatureDetectionStatusCallback> callback);

    void SetEffectSuggestionCallback(std::shared_ptr<EffectSuggestionCallback> effectSuggestionCallback);

    /**
     * @brief Get whether effectSuggestion Supported.
     *
     * @return True if supported false otherwise.
     */
    bool IsEffectSuggestionSupported();

    /**
     * @brief Enable EffectSuggestion.
     * @param isEnable switch to control Effect Suggestion.
     * @return errCode
     */
    int32_t EnableEffectSuggestion(bool isEnable);

    /**
     * @brief Batch set effect suggestion status.
     * @param effectSuggestionStatusList effect suggestion status list to be set.
     * @return errCode
     */
    int32_t SetEffectSuggestionStatus(std::vector<EffectSuggestionStatus> effectSuggestionStatusList);

    /**
     * @brief Get supported EffectSuggestionInfo.
     * @return EffectSuggestionInfo parsed from tag
     */
    EffectSuggestionInfo GetSupportedEffectSuggestionInfo();

    /**
     * @brief Get supported effectSuggestionType.
     * @return EffectSuggestionTypeList which current mode supported.
     */
    std::vector<EffectSuggestionType> GetSupportedEffectSuggestionType();

    /**
     * @brief Set ar mode.
     * @param effectSuggestionType switch to control effect suggestion.
     * @param isEnable switch to control effect suggestion status.
     * @return errCode
     */
    int32_t UpdateEffectSuggestion(EffectSuggestionType effectSuggestionType, bool isEnable);

    /**
     * @brief Enables or disables LCD flash detection.
     *
     * This function enables or disables the detection of the LCD flash feature based on the provided `isEnable` flag.
     *
     * @param isEnable A boolean flag indicating whether to enable (`true`) or disable (`false`) LCD flash detection.
     *
     * @return Returns an `int32_t` value indicating the outcome of the operation.
     *         A return value of 0 typically signifies success, while a non-zero value indicates an error.
     */
    int32_t EnableLcdFlashDetection(bool isEnable);

    /**
     * @brief Sets the callback for LCD flash status updates.
     *
     * This function assigns a callback to be invoked whenever there is a change in the LCD flash status.
     * The callback is passed as a shared pointer, allowing for shared ownership and automatic memory management.
     *
     * @param lcdFlashStatusCallback A shared pointer to an LcdFlashStatusCallback object. This callback will
     *        be called to handle updates related to the LCD flash status. If the callback is already set,
     *        it will be overwritten with the new one.
     */
    void SetLcdFlashStatusCallback(std::shared_ptr<LcdFlashStatusCallback> lcdFlashStatusCallback);

    /**
     * @brief Enables or disables tripod detection.
     *
     * This function enables or disables the tripod detection feature based on the provided `enabled` flag.
     *
     * @param enabled A boolean flag that specifies whether to enable or disable tripod detection.
     *
     * @return Returns an `int32_t` value indicating the outcome of the operation.
     *         A return value of 0 typically indicates success, while a non-zero value indicates an error.
     */
    int32_t EnableTripodDetection(bool enabled);

    /**
     * @brief Set usage for the capture session.
     * @param usage - The capture session usage.
     * @param enabled - Enable usage for session if TRUE.
     */
    void SetUsage(UsageType usageType, bool enabled);

    /**
     * @brief Enables or disables the LCD flash feature.
     *
     * This function enables or disables the LCD flash feature based on the provided `isEnable` flag.
     *
     * @param isEnable A boolean flag indicating whether to enable (`true`) or disable (`false`) the LCD flash feature.
     *
     * @return Returns an `int32_t` value indicating the result of the operation.
     *         Typically, a return value of 0 indicates success, while a non-zero value indicates an error.
     */
    int32_t EnableLcdFlash(bool isEnable);

    /**
     * @brief This function is called when there is constellation drawing update
     * and process the constellation drawing update status callback.
     *
     * @param result Metadata got from callback from service layer.
     */
    void ProcessConstellationDrawingUpdates(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result);

    /**
     * @brief This function is called when there is constellation drawing state update
     *
     * @param result Metadata got from callback from service layer.
     */
    void ProcessConstellationDrawingState(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result);

    int32_t EnableConstellationDrawingDetection(bool isEnable);

    /**
     * @brief This function is called when there is image stabilization guide update
     * and process the image stabilization guide update status callback.
     *
     * @param result Metadata got from callback from service layer.
     */
    void ProcessImageStabilizationGuide(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result);

    int32_t EnableSuperMoonFeature(bool isEnable);

    bool IsStageBoostSupported();
    
    int32_t EnableStageBoost(bool isEnable);

    std::shared_ptr<ImageStabilizationGuideCallback> GetImageStabilizationGuideCallback();

    int32_t IsImagingModeSupported(ImagingMode imagingMode, bool& isSupported);
    int32_t GetActiveImagingMode(ImagingMode& imagingMode);
    int32_t SetImagingMode(ImagingMode imagingMode);
    int32_t GetSupportedImagingMode(std::vector<ImagingMode>& imagingMode);

private:
    int32_t IsColorReservationTypeSupported(ColorReservationType colorReservationType, bool& isSupported);
    volatile bool isDepthFusionEnable_ = false;
    static const std::unordered_map<EffectSuggestionType, CameraEffectSuggestionType> fwkEffectSuggestionTypeMap_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CAPTURE_SESSION_FOR_SYS_H
