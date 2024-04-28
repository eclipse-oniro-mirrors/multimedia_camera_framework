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

#ifndef OHOS_CAMERA_PROFESSION_SESSION_H
#define OHOS_CAMERA_PROFESSION_SESSION_H

#include <atomic>
#include <iostream>
#include <set>
#include <stdint.h>
#include <vector>
#include "camera_device.h"
#include "camera_error_code.h"
#include "input/capture_input.h"
#include "output/capture_output.h"
#include "icamera_util.h"
#include "icapture_session.h"
#include "icapture_session_callback.h"
#include "capture_session.h"

namespace OHOS {
namespace CameraStandard {
class ExposureInfoCallback;
class IsoInfoCallback;
class ApertureInfoCallback;
class LuminationInfoCallback;
typedef enum {
    METERING_MODE_REGION = 0,
    METERING_MODE_CENTER_WEIGHTED,
    METERING_MODE_SPOT,
    METERING_MODE_OVERALL,
} MeteringMode;

typedef enum {
    FOCUS_ASSIST_FLASH_MODE_OFF = 0,
    FOCUS_ASSIST_FLASH_MODE_ON,
    FOCUS_ASSIST_FLASH_MODE_DEFAULT,
    FOCUS_ASSIST_FLASH_MODE_AUTO,
} FocusAssistFlashMode;

typedef enum {
    AWB_MODE_AUTO = 0,
    AWB_MODE_CLOUDY_DAYLIGHT,
    AWB_MODE_INCANDESCENT,
    AWB_MODE_FLUORESCENT,
    AWB_MODE_DAYLIGHT,
    AWB_MODE_OFF,
    AWB_MODE_WARM_FLUORESCENT,
    AWB_MODE_TWILIGHT,
    AWB_MODE_SHADE,
} WhiteBalanceMode;

typedef enum {
    EXPOSURE_HINT_MODE_OFF = 0,
    EXPOSURE_HINT_MODE_ON,
    EXPOSURE_HINT_UNSUPPORTED,
} ExposureHintMode;

typedef enum {
    OHOS_CAMERA_EXPOSURE_HINT_UNSUPPORTED = 0,
    OHOS_CAMERA_EXPOSURE_HINT_MODE_ON,
    OHOS_CAMERA_EXPOSURE_HINT_MODE_OFF,
} camera_exposure_hint_mode_enum_t;

class ProfessionSession : public CaptureSession {
public:
    class ProfessionSessionMetadataResultProcessor : public MetadataResultProcessor {
    public:
        explicit ProfessionSessionMetadataResultProcessor(wptr<ProfessionSession> session) : session_(session) {}
        void ProcessCallbacks(
            const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result) override;

    private:
        wptr<ProfessionSession> session_;
    };

    explicit ProfessionSession(sptr<ICaptureSession>& session,
        std::vector<sptr<CameraDevice>> devices) : CaptureSession(session)
    {
        metadataResultProcessor_ = std::make_shared<ProfessionSessionMetadataResultProcessor>(this);
        supportedDevices_.resize(devices.size());
        std::copy(devices.begin(), devices.end(), supportedDevices_.begin());
    }

    ~ProfessionSession();
// Metering mode
    /**
     * @brief Get Metering mode.
     * @param vector of Metering Mode.
     * @return errCode.
     */
    int32_t GetSupportedMeteringModes(std::vector<MeteringMode>& meteringModes);

    /**
     * @brief Query whether given meteringMode mode supported.
     *
     * @param camera_meter_mode_t flash mode to query.
     * @param bool True if supported false otherwise.
     * @return errCode.
     */
    int32_t IsMeteringModeSupported(MeteringMode meteringMode, bool &isSupported);

    /**
     * @brief Set Metering Mode.
     * @param exposure MeteringMode to be set.
     * @return errCode.
     */
    int32_t SetMeteringMode(MeteringMode mode);

    /**
     * @brief Get MeteringMode.
     * @param exposure current MeteringMode .
     * @return Returns errCode.
     */
    int32_t GetMeteringMode(MeteringMode& mode);

// ISO
    /**
     * @brief Get the supported iso.
     *
     * @return Returns the array of iso.
     */
    int32_t GetIsoRange(std::vector<int32_t>& isoRange);

    /**
     * @brief Get the iso.
     *
     * @return Returns the value of iso.
     */
    int32_t GetISO(int32_t &iso);

    /**
     * @brief Set the iso.
     */
    int32_t SetISO(int32_t iso);

    /**
     * @brief Check is support manual iso.
     */
    bool IsManualIsoSupported();

//Apertures
    /**
     * @brief Get the supported physical apertures.
     *
     * @return Returns the array of physical aperture.
     */
    int32_t GetSupportedPhysicalApertures(std::vector<std::vector<float>>& apertures);

    /**
     * @brief Get the physical aperture.
     *
     * @return Returns current physical aperture.
     */
    int32_t GetPhysicalAperture(float& aperture);

    /**
     * @brief Set the physical aperture.
     */
    int32_t SetPhysicalAperture(float physicalAperture);

// Focus mode
    /**
     * @brief Get Metering mode.
     * @param vector of Metering Mode.
     * @return errCode.
     */
    int32_t GetSupportedFocusModes(std::vector<FocusMode>& modes);

    /**
     * @brief Query whether given focus mode supported.
     *
     * @param camera_focus_mode_enum_t focus mode to query.
     * @param bool True if supported false otherwise.
     * @return errCode.
     */
    int32_t IsFocusModeSupported(FocusMode focusMode, bool &isSupported);

    /**
     * @brief Set Metering Mode.
     * @param exposure MeteringMode to be set.
     * @return errCode.
     */
    int32_t SetFocusMode(FocusMode mode);

    /**
     * @brief Get MeteringMode.
     * @param exposure current MeteringMode .
     * @return Returns errCode.
     */
    int32_t GetFocusMode(FocusMode& mode);

    /**
     * @brief Determine if the given Ouput can be added to session.
     *
     * @param CaptureOutput to be added to session.
     */

// White Balance
    /**
     * @brief Get Metering mode.
     * @param vector of Metering Mode.
     * @return errCode.
     */
    int32_t GetSupportedWhiteBalanceModes(std::vector<WhiteBalanceMode>& modes);

    /**
     * @brief Query whether given white-balance mode supported.
     *
     * @param camera_focus_mode_enum_t white-balance mode to query.
     * @param bool True if supported false otherwise.
     * @return errCode.
     */
    int32_t IsWhiteBalanceModeSupported(WhiteBalanceMode mode, bool &isSupported);

    /**
     * @brief Set WhiteBalanceMode.
     * @param mode WhiteBalanceMode to be set.
     * @return errCode.
     */
    int32_t SetWhiteBalanceMode(WhiteBalanceMode mode);

    /**
     * @brief Get WhiteBalanceMode.
     * @param mode current WhiteBalanceMode .
     * @return Returns errCode.
     */
    int32_t GetWhiteBalanceMode(WhiteBalanceMode& mode);

    /**
     * @brief Get ManualWhiteBalance Range.
     * @param whiteBalanceRange supported Manual WhiteBalance range .
     * @return Returns errCode.
     */
    int32_t GetManualWhiteBalanceRange(std::vector<int32_t> &whiteBalanceRange);

    /**
     * @brief Is Manual WhiteBalance Supported.
     * @param isSupported is Support Manual White Balance .
     * @return Returns errCode.
     */
    int32_t IsManualWhiteBalanceSupported(bool &isSupported);

    /**
     * @brief Set Manual WhiteBalance.
     * @param wbValue WhiteBalance value to be set.
     * @return Returns errCode.
     */
    int32_t SetManualWhiteBalance(int32_t wbValue);

    /**
     * @brief Get ManualWhiteBalance.
     * @param wbValue WhiteBalance value to be get.
     * @return Returns errCode.
     */
    int32_t GetManualWhiteBalance(int32_t &wbValue);

// ExposureHint mode
    /**
     * @brief Get ExposureHint mode.
     * @param vector of ExposureHint Mode.
     * @return errCode.
     */
    int32_t GetSupportedExposureHintModes(std::vector<ExposureHintMode>& modes);

    /**
     * @brief Set ExposureHint Mode.
     * @param mode ExposureHint Mode to be set.
     * @return errCode.
     */
    int32_t SetExposureHintMode(ExposureHintMode mode);

    /**
     * @brief Get MeteringMode.
     * @param mode current MeteringMode .
     * @return Returns errCode.
     */
    int32_t GetExposureHintMode(ExposureHintMode& mode);

// FocusAssistFlash mode
    /**
     * @brief Get FocusAssistFlash mode.
     * @param vector of FocusAssistFlash Mode.
     * @return errCode.
     */
    int32_t GetSupportedFocusAssistFlashModes(std::vector<FocusAssistFlashMode>& modes);

    /**
     * @brief Query whether given focus assist flash mode supported.
     *
     * @param FocusAssistFlashMode focus assist flash mode to query.
     * @param bool True if supported false otherwise.
     * @return errCode.
     */
    int32_t IsFocusAssistFlashModeSupported(FocusAssistFlashMode mode, bool &isSupported);

    /**
     * @brief Set FocusAssistFlashMode.
     * @param mode FocusAssistFlash Mode to be set.
     * @return errCode.
     */
    int32_t SetFocusAssistFlashMode(FocusAssistFlashMode mode);

    /**
     * @brief Get FocusAssistFlash Mode.
     * @param mode current FocusAssistFlash Mode .
     * @return Returns errCode.
     */
    int32_t GetFocusAssistFlashMode(FocusAssistFlashMode& mode);

// Flash Mode
    /**
     * @brief Get the supported Focus modes.
     * @param vector of camera_focus_mode_enum_t supported exposure modes.
     * @return Returns errCode.
     */
    int32_t GetSupportedFlashModes(std::vector<FlashMode>& flashModes);

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
     * @param bool True if supported false otherwise.
     * @return errCode.
     */
    int32_t IsFlashModeSupported(FlashMode flashMode, bool& isSupported);

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
     * @brief Determine if the given Ouput can be added to session.
     *
     * @param CaptureOutput to be added to session.
     */
// XMAGE
    /**
     * @brief Get the supported color effect.
     *
     * @return Returns supported color effects.
     */
    int32_t GetSupportedColorEffects(std::vector<ColorEffect>& colorEffects);

    /**
     * @brief Get the current color effect.
     *
     * @return Returns current color effect.
     */
    int32_t GetColorEffect(ColorEffect& colorEffect);

    /**
     * @brief Set the color effect.
     */
    int32_t SetColorEffect(ColorEffect colorEffect);

// SensorExposureTime Callback
    /**
     * @brief Set the SensorExposureTime callback.
     * which will be called when there is SensorExposureTime change.
     *
     * @param The ExposureInfoCallback pointer.
     */
    void SetExposureInfoCallback(std::shared_ptr<ExposureInfoCallback> callback);
// Focus Callback
    /**
     * @brief Set the ISO callback.
     * which will be called when there is ISO state change.
     *
     * @param The IsoInfoCallback pointer.
     */
    void SetIsoInfoCallback(std::shared_ptr<IsoInfoCallback> callback);
// Exposure Callback
    /**
     * @brief Set the focus distance callback.
     * which will be called when there is focus distance change.
     *
     * @param The ApertureInfoCallback pointer.
     */
    void SetApertureInfoCallback(std::shared_ptr<ApertureInfoCallback> callback);
// Exposurehint Callback
    /**
     * @brief Set the exposure hint callback.
     * which will be called when there is exposure hint change.
     *
     * @param The LuminationInfoCallback pointer.
     */
    void SetLuminationInfoCallback(std::shared_ptr<LuminationInfoCallback> callback);

    /**
     * @brief This function is called when there is SensorExposureTime change
     * and process the SensorExposureTime callback.
     *
     * @param result Metadata got from callback from service layer.
     */
    void ProcessSensorExposureTimeChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result);

    /**
     * @brief This function is called when there is Iso change
     * and process the Iso callback.
     *
     * @param result Metadata got from callback from service layer.
     */
    void ProcessIsoChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result);

    /**
     * @brief This function is called when there is Aperture change
     * and process the Aperture callback.
     *
     * @param result Metadata got from callback from service layer.
     */
    void ProcessApertureChange(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result);

    /**
     * @brief This function is called when there is Lumination change
     * and process the Lumination callback.
     *
     * @param result Metadata got from callback from service layer.
     */
    void ProcessLuminationChange(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result);

    /**
     * @brief This function is called when physical camera switch
     * and process the ability change callback.
     *
     * @param result Metadata got from callback from service layer.
     */
    void ProcessPhysicalCameraSwitch(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result);

    std::shared_ptr<OHOS::Camera::CameraMetadata> GetMetadata() override;

    bool CanAddOutput(sptr<CaptureOutput>& output) override;
protected:
    static const std::unordered_map<camera_meter_mode_t, MeteringMode> metaMeteringModeMap_;
    static const std::unordered_map<MeteringMode, camera_meter_mode_t> fwkMeteringModeMap_;

    static const std::unordered_map<camera_focus_assist_flash_mode_enum_t, FocusAssistFlashMode>
        metaFocusAssistFlashModeMap_;
    static const std::unordered_map<FocusAssistFlashMode, camera_focus_assist_flash_mode_enum_t>
        fwkFocusAssistFlashModeMap_;

    static const std::unordered_map<camera_awb_mode_t, WhiteBalanceMode>
        metaWhiteBalanceModeMap_;
    static const std::unordered_map<WhiteBalanceMode, camera_awb_mode_t>
        fwkWhiteBalanceModeMap_;

    static const std::unordered_map<camera_exposure_hint_mode_enum_t, ExposureHintMode> metaExposureHintModeMap_;
    static const std::unordered_map<ExposureHintMode, camera_exposure_hint_mode_enum_t> fwkExposureHintModeMap_;
private:
    std::vector<float> ParsePhysicalApertureRangeFromMeta(const camera_metadata_item_t &item);
    std::mutex sessionCallbackMutex_;
    std::shared_ptr<ExposureInfoCallback> exposureInfoCallback_ = nullptr;
    std::shared_ptr<IsoInfoCallback> isoInfoCallback_ = nullptr;
    std::shared_ptr<ApertureInfoCallback> apertureInfoCallback_ = nullptr;
    std::shared_ptr<LuminationInfoCallback> luminationInfoCallback_ = nullptr;
    std::atomic<uint8_t> physicalCameraId_ = 0;
    uint32_t isoValue_ = 0;
    float luminationValue_ = 0.0;
    float apertureValue_ = 0.0;
    std::vector<sptr<CameraDevice> > supportedDevices_;
};

typedef struct {
    uint32_t exposureDurationValue;
} ExposureInfo;

typedef struct {
    uint32_t isoValue;
} IsoInfo;

typedef struct {
    float apertureValue;
} ApertureInfo;

typedef struct {
    float luminationValue;
} LuminationInfo;

class ExposureInfoCallback {
public:
    ExposureInfoCallback() = default;
    virtual ~ExposureInfoCallback() = default;
    virtual void OnExposureInfoChanged(ExposureInfo info) = 0;
};

class IsoInfoCallback {
public:
    IsoInfoCallback() = default;
    virtual ~IsoInfoCallback() = default;
    virtual void OnIsoInfoChanged(IsoInfo info) = 0;
};

class ApertureInfoCallback {
public:
    ApertureInfoCallback() = default;
    virtual ~ApertureInfoCallback() = default;
    virtual void OnApertureInfoChanged(ApertureInfo info) = 0;
};

class LuminationInfoCallback {
public:
    LuminationInfoCallback() = default;
    virtual ~LuminationInfoCallback() = default;
    virtual void OnLuminationInfoChanged(LuminationInfo info) = 0;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_PROFESSION_SESSION_H
