/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_CAPTURE_SESSION_H
#define OHOS_CAMERA_CAPTURE_SESSION_H

#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <vector>

#include "camera_error_code.h"
#include "hcapture_session_callback_stub.h"
#include "icamera_util.h"
#include "icapture_session.h"
#include "icapture_session_callback.h"
#include "input/camera_death_recipient.h"
#include "input/capture_input.h"
#include "output/camera_output_capability.h"
#include "output/capture_output.h"
#include "refbase.h"
#include "color_space_info_parse.h"

namespace OHOS {
namespace CameraStandard {
enum ExposureMode {
    EXPOSURE_MODE_UNSUPPORTED = -1,
    EXPOSURE_MODE_LOCKED = 0,
    EXPOSURE_MODE_AUTO,
    EXPOSURE_MODE_CONTINUOUS_AUTO
};

enum FlashMode {
    FLASH_MODE_CLOSE = 0,
    FLASH_MODE_OPEN,
    FLASH_MODE_AUTO,
    FLASH_MODE_ALWAYS_OPEN,
};

enum FocusMode {
    FOCUS_MODE_MANUAL = 0,
    FOCUS_MODE_CONTINUOUS_AUTO,
    FOCUS_MODE_AUTO,
    FOCUS_MODE_LOCKED,
};

enum FocusState {
    FOCUS_STATE_SCAN = 0,
    FOCUS_STATE_FOCUSED,
    FOCUS_STATE_UNFOCUSED
};

enum ExposureState {
    EXPOSURE_STATE_SCAN = 0,
    EXPOSURE_STATE_CONVERGED
};

enum FilterType {
    NONE = 0,
    CLASSIC = 1,
    DAWN = 2,
    PURE = 3,
    GREY = 4,
    NATURAL = 5,
    MORI = 6,
    FAIR = 7,
    PINK = 8,
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
    COLOR_EFFECT_SOFT
};

typedef struct {
    float x;
    float y;
} Point;

template<class T>
struct RefBaseCompare {
public:
    bool operator()(const wptr<T>& firstPtr, const wptr<T>& secondPtr) const
    {
        return firstPtr.GetRefPtr() < secondPtr.GetRefPtr();
    }
};

class SessionCallback {
public:
    SessionCallback() = default;
    virtual ~SessionCallback() = default;
    /**
     * @brief Called when error occured during capture session callback.
     *
     * @param errorCode Indicates a {@link ErrorCode} which will give information for capture session callback error.
     */
    virtual void OnError(int32_t errorCode) = 0;
};

class ExposureCallback {
public:
    enum ExposureState {
        SCAN = 0,
        CONVERGED,
    };
    ExposureCallback() = default;
    virtual ~ExposureCallback() = default;
    virtual void OnExposureState(ExposureState state) = 0;
};

class FocusCallback {
public:
    enum FocusState {
        SCAN = 0,
        FOCUSED,
        UNFOCUSED
    };
    FocusCallback() = default;
    virtual ~FocusCallback() = default;
    virtual void OnFocusState(FocusState state) = 0;
    FocusState currentState;
};

class MacroStatusCallback {
public:
    enum MacroStatus { IDLE = 0, ACTIVE, UNKNOWN };
    MacroStatusCallback() = default;
    virtual ~MacroStatusCallback() = default;
    virtual void OnMacroStatusChanged(MacroStatus status) = 0;
    MacroStatus currentStatus = UNKNOWN;
};

class CaptureSessionCallback : public HCaptureSessionCallbackStub {
public:
    CaptureSession* captureSession_ = nullptr;
    CaptureSessionCallback() : captureSession_(nullptr) {}

    explicit CaptureSessionCallback(CaptureSession* captureSession) : captureSession_(captureSession) {}

    ~CaptureSessionCallback()
    {
        captureSession_ = nullptr;
    }

    int32_t OnError(int32_t errorCode) override;
};

enum VideoStabilizationMode {
    OFF = 0,
    LOW,
    MIDDLE,
    HIGH,
    AUTO
};

class CaptureOutput;
class CaptureSession : public RefBase {
public:
    sptr<CaptureInput> inputDevice_;
    explicit CaptureSession(sptr<ICaptureSession>& captureSession);
    CaptureSession() {};
    virtual ~CaptureSession();

    /**
     * @brief Begin the capture session config.
     */
    int32_t BeginConfig();

    /**
     * @brief Commit the capture session config.
     */
    int32_t CommitConfig();

    /**
     * @brief Determine if the given Input can be added to session.
     *
     * @param CaptureInput to be added to session.
     */
    int32_t CanAddInput(sptr<CaptureInput>& input);

    /**
     * @brief Add CaptureInput for the capture session.
     *
     * @param CaptureInput to be added to session.
     */
    int32_t AddInput(sptr<CaptureInput>& input);

    /**
     * @brief Determine if the given Ouput can be added to session.
     *
     * @param CaptureOutput to be added to session.
     */
    int32_t CanAddOutput(sptr<CaptureOutput>& output);

    /**
     * @brief Add CaptureOutput for the capture session.
     *
     * @param CaptureOutput to be added to session.
     */
    virtual int32_t AddOutput(sptr<CaptureOutput> &output);

    /**
     * @brief Remove CaptureInput for the capture session.
     *
     * @param CaptureInput to be removed from session.
     */
    int32_t RemoveInput(sptr<CaptureInput>& input);

    /**
     * @brief Remove CaptureOutput for the capture session.
     *
     * @param CaptureOutput to be removed from session.
     */
    int32_t RemoveOutput(sptr<CaptureOutput>& output);

    /**
     * @brief Starts session and preview.
     */
    int32_t Start();

    /**
     * @brief Stop session and preview..
     */
    int32_t Stop();

    /**
     * @brief Set the session callback for the capture session.
     *
     * @param SessionCallback pointer to be triggered.
     */
    void SetCallback(std::shared_ptr<SessionCallback> callback);

    /**
     * @brief Get the application callback information.
     *
     * @return Returns the pointer to SessionCallback set by application.
     */
    std::shared_ptr<SessionCallback> GetApplicationCallback();

    /**
     * @brief Releases CaptureSession instance.
     * @return Returns errCode.
     */
    int32_t Release();

    /**
     * @brief create new device control setting.
     */
    void LockForControl();

    /**
     * @brief submit device control setting.
     *
     * @return Returns CAMERA_OK is success.
     */
    int32_t UnlockForControl();

    /**
     * @brief Get the supported video sabilization modes.
     *
     * @return Returns vector of CameraVideoStabilizationMode supported stabilization modes.
     */
    std::vector<VideoStabilizationMode> GetSupportedStabilizationMode();

    /**
     * @brief Get the supported video sabilization modes.
     * @param vector of CameraVideoStabilizationMode supported stabilization modes.
     * @return Returns errCode.
     */
    int32_t GetSupportedStabilizationMode(std::vector<VideoStabilizationMode>& modes);

    /**
     * @brief Query whether given stabilization mode supported.
     *
     * @param VideoStabilizationMode stabilization mode to query.
     * @return True is supported false otherwise.
     */
    bool IsVideoStabilizationModeSupported(VideoStabilizationMode stabilizationMode);

    /**
     * @brief Query whether given stabilization mode supported.
     *
     * @param VideoStabilizationMode stabilization mode to query.
     * @param bool True is supported false otherwise.
     * @return errCode.
     */
    int32_t IsVideoStabilizationModeSupported(VideoStabilizationMode stabilizationMode, bool& isSupported);

    /**
     * @brief Get the current Video Stabilizaion mode.
     *
     * @return Returns current Video Stabilizaion mode.
     */
    VideoStabilizationMode GetActiveVideoStabilizationMode();

    /**
     * @brief Get the current Video Stabilizaion mode.
     * @param current Video Stabilizaion mode.
     * @return errCode
     */
    int32_t GetActiveVideoStabilizationMode(VideoStabilizationMode& mode);

    /**
     * @brief Set the Video Stabilizaion mode.
     * @param VideoStabilizationMode stabilization mode to set.
     * @return errCode
     */
    int32_t SetVideoStabilizationMode(VideoStabilizationMode stabilizationMode);

    /**
     * @brief Get the supported exposure modes.
     *
     * @return Returns vector of ExposureMode supported exposure modes.
     */
    std::vector<ExposureMode> GetSupportedExposureModes();

    /**
     * @brief Get the supported exposure modes.
     * @param vector of ExposureMode supported exposure modes.
     * @return errCode.
     */
    int32_t GetSupportedExposureModes(std::vector<ExposureMode>& exposureModes);

    /**
     * @brief Query whether given exposure mode supported.
     *
     * @param ExposureMode exposure mode to query.
     * @return True is supported false otherwise.
     */
    bool IsExposureModeSupported(ExposureMode exposureMode);

    /**
     * @brief Query whether given exposure mode supported.
     *
     * @param ExposureMode exposure mode to query.
     * @param bool True is supported false otherwise.
     * @return errCode.
     */
    int32_t IsExposureModeSupported(ExposureMode exposureMode, bool& isSupported);

    /**
     * @brief Set exposure mode.
     * @param ExposureMode exposure mode to be set.
     * @return errCode
     */
    int32_t SetExposureMode(ExposureMode exposureMode);

    /**
     * @brief Get the current exposure mode.
     *
     * @return Returns current exposure mode.
     */
    ExposureMode GetExposureMode();

    /**
     * @brief Get the current exposure mode.
     * @param ExposureMode current exposure mode.
     * @return errCode.
     */
    int32_t GetExposureMode(ExposureMode& exposureMode);

    /**
     * @brief Set the centre point of exposure area.
     * @param Point which specifies the area to expose.
     * @return errCode
     */
    int32_t SetMeteringPoint(Point exposurePoint);

    /**
     * @brief Get centre point of exposure area.
     *
     * @return Returns current exposure point.
     */
    Point GetMeteringPoint();

    /**
     * @brief Get centre point of exposure area.
     * @param Point current exposure point.
     * @return errCode
     */
    int32_t GetMeteringPoint(Point& exposurePoint);

    /**
     * @brief Get exposure compensation range.
     *
     * @return Returns supported exposure compensation range.
     */
    std::vector<float> GetExposureBiasRange();

    /**
     * @brief Get exposure compensation range.
     * @param vector of exposure bias range.
     * @return errCode.
     */
    int32_t GetExposureBiasRange(std::vector<float>& exposureBiasRange);

    /**
     * @brief Set exposure compensation value.
     * @param exposure compensation value to be set.
     * @return errCode.
     */
    int32_t SetExposureBias(float exposureBias);

    /**
     * @brief Get exposure compensation value.
     *
     * @return Returns current exposure compensation value.
     */
    float GetExposureValue();

    /**
     * @brief Get exposure compensation value.
     * @param exposure current exposure compensation value .
     * @return Returns errCode.
     */
    int32_t GetExposureValue(float& exposure);

    /**
     * @brief Set the exposure callback.
     * which will be called when there is exposure state change.
     *
     * @param The ExposureCallback pointer.
     */
    void SetExposureCallback(std::shared_ptr<ExposureCallback> exposureCallback);

    /**
     * @brief This function is called when there is exposure state change
     * and process the exposure state callback.
     *
     * @param result metadata got from callback from service layer.
     */
    void ProcessAutoExposureUpdates(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result);

    /**
     * @brief Get the supported Focus modes.
     *
     * @return Returns vector of FocusMode supported exposure modes.
     */
    std::vector<FocusMode> GetSupportedFocusModes();

    /**
     * @brief Get the supported Focus modes.
     * @param vector of FocusMode supported.
     * @return Returns errCode.
     */
    int32_t GetSupportedFocusModes(std::vector<FocusMode>& modes);

    /**
     * @brief Query whether given focus mode supported.
     *
     * @param camera_focus_mode_enum_t focus mode to query.
     * @return True is supported false otherwise.
     */
    bool IsFocusModeSupported(FocusMode focusMode);

    /**
     * @brief Query whether given focus mode supported.
     *
     * @param camera_focus_mode_enum_t focus mode to query.
     * @param bool True is supported false otherwise.
     * @return Returns errCode.
     */
    int32_t IsFocusModeSupported(FocusMode focusMode, bool& isSupported);

    /**
     * @brief Set Focus mode.
     *
     * @param FocusMode focus mode to be set.
     * @return Returns errCode.
     */
    int32_t SetFocusMode(FocusMode focusMode);

    /**
     * @brief Get the current focus mode.
     *
     * @return Returns current focus mode.
     */
    FocusMode GetFocusMode();

    /**
     * @brief Get the current focus mode.
     * @param FocusMode current focus mode.
     * @return Returns errCode.
     */
    int32_t GetFocusMode(FocusMode& focusMode);

    /**
     * @brief Set the focus callback.
     * which will be called when there is focus state change.
     *
     * @param The ExposureCallback pointer.
     */
    void SetFocusCallback(std::shared_ptr<FocusCallback> focusCallback);

    /**
     * @brief This function is called when there is focus state change
     * and process the focus state callback.
     *
     * @param result metadata got from callback from service layer.
     */
    void ProcessAutoFocusUpdates(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result);

    /**
     * @brief Set the Focus area.
     *
     * @param Point which specifies the area to focus.
     * @return Returns errCode.
     */
    int32_t SetFocusPoint(Point focusPoint);

    /**
     * @brief Get centre point of focus area.
     *
     * @return Returns current focus point.
     */
    Point GetFocusPoint();

    /**
     * @brief Get centre point of focus area.
     * @param Point current focus point.
     * @return Returns errCode.
     */
    int32_t GetFocusPoint(Point& focusPoint);

    /**
     * @brief Get focal length.
     *
     * @return Returns focal length value.
     */
    float GetFocalLength();

    /**
     * @brief Get focal length.
     * @param focalLength current focal length compensation value .
     * @return Returns errCode.
     */
    int32_t GetFocalLength(float& focalLength);

    /**
     * @brief Get the supported Focus modes.
     *
     * @return Returns vector of camera_focus_mode_enum_t supported exposure modes.
     */
    std::vector<FlashMode> GetSupportedFlashModes();

    /**
     * @brief Get the supported Focus modes.
     * @param vector of camera_focus_mode_enum_t supported exposure modes.
     * @return Returns errCode.
     */
    int32_t GetSupportedFlashModes(std::vector<FlashMode>& flashModes);

    /**
     * @brief Check whether camera has flash.
     */
    bool HasFlash();

    /**
     * @brief Check whether camera has flash.
     * @param bool True is has flash false otherwise.
     * @return Returns errCode.
     */
    int32_t HasFlash(bool& hasFlash);

    /**
     * @brief Query whether given flash mode supported.
     *
     * @param camera_flash_mode_enum_t flash mode to query.
     * @return True if supported false otherwise.
     */
    bool IsFlashModeSupported(FlashMode flashMode);

    /**
     * @brief Query whether given flash mode supported.
     *
     * @param camera_flash_mode_enum_t flash mode to query.
     * @param bool True if supported false otherwise.
     * @return errCode.
     */
    int32_t IsFlashModeSupported(FlashMode flashMode, bool& isSupported);

    /**
     * @brief Get the current flash mode.
     *
     * @return Returns current flash mode.
     */
    FlashMode GetFlashMode();

    /**
     * @brief Get the current flash mode.
     * @param current flash mode.
     * @return Returns errCode.
     */
    int32_t GetFlashMode(FlashMode& flashMode);

    /**
     * @brief Set flash mode.
     *
     * @param camera_flash_mode_enum_t flash mode to be set.
     * @return Returns errCode.
     */
    int32_t SetFlashMode(FlashMode flashMode);

    /**
     * @brief Get the supported Zoom Ratio range.
     *
     * @return Returns vector<float> of supported Zoom ratio range.
     */
    std::vector<float> GetZoomRatioRange();

    /**
     * @brief Get the supported Zoom Ratio range.
     *
     * @param vector<float> of supported Zoom ratio range.
     * @return Returns errCode.
     */
    int32_t GetZoomRatioRange(std::vector<float>& zoomRatioRange);

    /**
     * @brief Get the current Zoom Ratio.
     *
     * @return Returns current Zoom Ratio.
     */
    float GetZoomRatio();

    /**
     * @brief Get the current Zoom Ratio.
     * @param zoomRatio current Zoom Ratio.
     * @return Returns errCode.
     */
    int32_t GetZoomRatio(float& zoomRatio);

    /**
     * @brief Set Zoom ratio.
     *
     * @param Zoom ratio to be set.
     * @return Returns errCode.
     */
    int32_t SetZoomRatio(float zoomRatio);

    /**
     * @brief Set Metadata Object types.
     *
     * @param set of camera_face_detect_mode_t types.
     */
    void SetCaptureMetadataObjectTypes(std::set<camera_face_detect_mode_t> metadataObjectTypes);

    /**
     * @brief Get the supported filters.
     *
     * @return Returns the array of filter.
     */
    std::vector<FilterType> GetSupportedFilters();

    /**
     * @brief Verify ability for supported meta.
     *
     * @return Returns errorcode.
     */
    int32_t VerifyAbility(uint32_t ability);

    /**
     * @brief Get the current filter.
     *
     * @return Returns the array of filter.
     */
    FilterType GetFilter();

    /**
     * @brief Set the filter.
     */
    void SetFilter(FilterType filter);

    /**
     * @brief Get the supported beauty type.
     *
     * @return Returns the array of beautytype.
     */
    std::vector<BeautyType> GetSupportedBeautyTypes();

    /**
     * @brief Get the supported beauty range.
     *
     * @return Returns the array of beauty range.
     */
    std::vector<int32_t> GetSupportedBeautyRange(BeautyType type);

    /**
     * @brief Set the beauty.
     */
    void SetBeauty(BeautyType type, int value);
    /**
     * @brief according type to get the strength.
     */
    int32_t GetBeauty(BeautyType type);

    /**
     * @brief Get the supported color spaces.
     *
     * @return Returns supported color spaces.
     */
    std::vector<ColorSpace> GetSupportedColorSpaces();

    /**
     * @brief Get current color space.
     *
     * @return Returns current color space.
     */
    int32_t GetActiveColorSpace(ColorSpace& colorSpace);

    /**
     * @brief Set the color space.
     */
    int32_t SetColorSpace(ColorSpace colorSpace);

    /**
     * @brief Get the supported color effect.
     *
     * @return Returns supported color effects.
     */
    std::vector<ColorEffect> GetSupportedColorEffects();

    /**
     * @brief Get the current color effect.
     *
     * @return Returns current color effect.
     */
    ColorEffect GetColorEffect();

    /**
     * @brief Set the color effect.
     */
    void SetColorEffect(ColorEffect colorEffect);

    /**
     * @brief Check current status is support macro or not.
     */
    bool IsMacroSupported();

    /**
     * @brief Enable macro lens.
     */
    int32_t EnableMacro(bool isEnable);

    /**
     * @brief Set the macro status callback.
     * which will be called when there is macro state change.
     *
     * @param The MacroStatusCallback pointer.
     */
    void SetMacroStatusCallback(std::shared_ptr<MacroStatusCallback> callback);

    /**
     * @brief This function is called when there is macro status change
     * and process the macro status callback.
     *
     * @param result Metadata got from callback from service layer.
     */
    void ProcessMacroStatusChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result);

    /**
     * @brief Get whether or not commit config.
     *
     * @return Returns whether or not commit config.
     */
    bool IsSessionCommited();
    bool SetBeautyValue(BeautyType beautyType, int32_t value);
    /**
     * @brief Get whether or not commit config.
     *
     * @return Returns whether or not commit config.
     */
    bool IsSessionConfiged();
    void SetMode(int32_t modeName);
    int32_t GetMode();
    int32_t GetFeaturesMode();
    std::vector<int32_t> GetSubFeatureMods();
    bool IsSetEnableMacro();
    sptr<CaptureOutput> GetMetaOutput();
    void ProcessFaceRecUpdates(const uint64_t timestamp,
                                    const std::shared_ptr<OHOS::Camera::CameraMetadata> &result);
    virtual void ProcessCallbacks(const uint64_t timestamp,
                                    const std::shared_ptr<OHOS::Camera::CameraMetadata> &result);
protected:
    std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata_;
    Profile photoProfile_;
    Profile previewProfile_;
    std::map<BeautyType, std::vector<int32_t>> beautyTypeAndRanges_;
    std::map<BeautyType, int32_t> beautyTypeAndLevels_;
    int32_t modeName_;

private:
    std::mutex changeMetaMutex_;
    sptr<ICaptureSession> captureSession_;
    std::shared_ptr<SessionCallback> appCallback_;
    sptr<ICaptureSessionCallback> captureSessionCallback_;
    std::shared_ptr<ExposureCallback> exposureCallback_;
    std::shared_ptr<FocusCallback> focusCallback_;
    std::shared_ptr<MacroStatusCallback> macroStatusCallback_;
    std::vector<int32_t> skinSmoothBeautyRange_;
    std::vector<int32_t> faceSlendorBeautyRange_;
    std::vector<int32_t> skinToneBeautyRange_;
    std::mutex captureOutputSetsMutex_;
    std::set<wptr<CaptureOutput>, RefBaseCompare<CaptureOutput>> captureOutputSets_;
    volatile bool isSetMacroEnable_ = false;
    static const std::unordered_map<camera_focus_state_t, FocusCallback::FocusState> metaFocusStateMap_;
    static const std::unordered_map<camera_exposure_state_t, ExposureCallback::ExposureState> metaExposureStateMap_;
    static const std::unordered_map<camera_exposure_mode_enum_t, ExposureMode> metaExposureModeMap_;
    static const std::unordered_map<ExposureMode, camera_exposure_mode_enum_t> fwkExposureModeMap_;
    static const std::unordered_map<camera_focus_mode_enum_t, FocusMode> metaFocusModeMap_;
    static const std::unordered_map<FocusMode, camera_focus_mode_enum_t> fwkFocusModeMap_;
    static const std::unordered_map<camera_flash_mode_enum_t, FlashMode> metaFlashModeMap_;
    static const std::unordered_map<FlashMode, camera_flash_mode_enum_t> fwkFlashModeMap_;
    static const std::unordered_map<camera_filter_type_t, FilterType> metaFilterTypeMap_;
    static const std::unordered_map<FilterType, camera_filter_type_t> fwkFilterTypeMap_;
    static const std::unordered_map<camera_beauty_type_t, BeautyType> metaBeautyTypeMap_;
    static const std::unordered_map<BeautyType, camera_beauty_type_t> fwkBeautyTypeMap_;
    static const std::unordered_map<BeautyType, camera_device_metadata_tag_t> fwkBeautyAbilityMap_;
    static const std::unordered_map<BeautyType, camera_device_metadata_tag_t> fwkBeautyControlMap_;
    static const std::unordered_map<camera_device_metadata_tag_t, BeautyType> metaBeautyControlMap_;
    static const std::unordered_map<CameraVideoStabilizationMode, VideoStabilizationMode> metaVideoStabModesMap_;
    static const std::unordered_map<VideoStabilizationMode, CameraVideoStabilizationMode> fwkVideoStabModesMap_;
    static const std::unordered_map<camera_xmage_color_type_t, ColorEffect> metaColorEffectMap_;
    static const std::unordered_map<ColorEffect, camera_xmage_color_type_t> fwkColorEffectMap_;
    sptr<CaptureOutput> metaOutput_;
    sptr<CameraDeathRecipient> deathRecipient_ = nullptr;
    bool isColorSpaceSetted_ = false;
    int32_t UpdateSetting(std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata);
    void SetFrameRateRange(const std::vector<int32_t>& frameRateRange);
    Point CoordinateTransform(Point point);
    int32_t CalculateExposureValue(float exposureValue);
    Point VerifyFocusCorrectness(Point point);
    void ConfigureOutput(sptr<CaptureOutput>& output);
    void CameraServerDied(pid_t pid);
    void InsertOutputIntoSet(sptr<CaptureOutput>& output);
    void RemoveOutputFromSet(sptr<CaptureOutput>& output);
    void OnSettingUpdated(std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata);
    ColorSpaceInfo GetSupportedColorSpaceInfo();
    bool IsModeWithVideoStream();
    void SetDefaultColorSpace();
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CAPTURE_SESSION_H
