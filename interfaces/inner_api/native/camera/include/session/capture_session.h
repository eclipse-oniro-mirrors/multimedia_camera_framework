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

#include <atomic>
#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <vector>

#include "camera_error_code.h"
#include "camera_photo_proxy.h"
#include "capture_scene_const.h"
#include "color_space_info_parse.h"
#include "features/moon_capture_boost_feature.h"
#include "hcapture_session_callback_stub.h"
#include "icamera_util.h"
#include "icapture_session.h"
#include "icapture_session_callback.h"
#include "input/camera_death_recipient.h"
#include "input/capture_input.h"
#include "output/camera_output_capability.h"
#include "output/capture_output.h"
#include "refbase.h"
#include "effect_suggestion_info_parse.h"
#include "capture_scene_const.h"
#include "ability/camera_ability.h"
#include "ability/camera_ability_parse_util.h"

namespace OHOS {
namespace CameraStandard {
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

enum PreconfigType : int32_t {
    PRECONFIG_720P = 0,
    PRECONFIG_1080P = 1,
    PRECONFIG_4K = 2,
    PRECONFIG_HIGH_QUALITY = 3
};

struct PreconfigProfiles {
public:
    explicit PreconfigProfiles(ColorSpace colorSpace) : colorSpace(colorSpace) {}
    Profile previewProfile;
    Profile photoProfile;
    VideoProfile videoProfile;
    ColorSpace colorSpace;

    std::string ToString()
    {
        std::ostringstream oss;
        oss << "colorSpace:[" << to_string(colorSpace);
        oss << "]\n";

        oss << "previewProfile:[";
        oss << " format:" << to_string(previewProfile.format_);
        oss << " size:" << to_string(previewProfile.size_.width) << "x" << to_string(previewProfile.size_.height);
        oss << " fps:" << to_string(previewProfile.fps_.minFps) << "," << to_string(previewProfile.fps_.maxFps) << ","
            << to_string(previewProfile.fps_.fixedFps);
        oss << "]\n";

        oss << "photoProfile:[";
        oss << " format:" << to_string(photoProfile.format_);
        oss << " size:" << to_string(photoProfile.size_.width) << "x" << to_string(photoProfile.size_.height);
        oss << " dynamic:" << to_string(photoProfile.sizeFollowSensorMax_) << "," << to_string(photoProfile.sizeRatio_);
        oss << "]\n";

        oss << "videoProfile:[";
        oss << " format:" << to_string(videoProfile.format_);
        oss << " size:" << to_string(videoProfile.size_.width) << "x" << to_string(videoProfile.size_.height);
        oss << " frameRates:";
        for (auto& fps : videoProfile.framerates_) {
            oss << to_string(fps) << " ";
        }
        oss << "]\n";
        return oss.str();
    }
};

enum EffectSuggestionType {
    EFFECT_SUGGESTION_NONE = 0,
    EFFECT_SUGGESTION_PORTRAIT,
    EFFECT_SUGGESTION_FOOD,
    EFFECT_SUGGESTION_SKY,
    EFFECT_SUGGESTION_SUNRISE_SUNSET
};

typedef enum {
    AWB_MODE_AUTO = 0,
    AWB_MODE_CLOUDY_DAYLIGHT,
    AWB_MODE_INCANDESCENT,
    AWB_MODE_FLUORESCENT,
    AWB_MODE_DAYLIGHT,
    AWB_MODE_OFF,
    AWB_MODE_LOCKED,
    AWB_MODE_WARM_FLUORESCENT,
    AWB_MODE_TWILIGHT,
    AWB_MODE_SHADE,
} WhiteBalanceMode;

enum LightPaintingType {
    CAR = 0,
    STAR,
    WATER,
    LIGHT
};

typedef struct {
    float x;
    float y;
} Point;

typedef struct {
    float zoomRatio;
    int32_t equivalentFocalLength;
} ZoomPointInfo;

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

class MoonCaptureBoostStatusCallback {
public:
    enum MoonCaptureBoostStatus { IDLE = 0, ACTIVE, UNKNOWN };
    MoonCaptureBoostStatusCallback() = default;
    virtual ~MoonCaptureBoostStatusCallback() = default;
    virtual void OnMoonCaptureBoostStatusChanged(MoonCaptureBoostStatus status) = 0;
    MoonCaptureBoostStatus currentStatus = UNKNOWN;
};

class FeatureDetectionStatusCallback {
public:
    enum FeatureDetectionStatus { IDLE = 0, ACTIVE, UNKNOWN };

    FeatureDetectionStatusCallback() = default;
    virtual ~FeatureDetectionStatusCallback() = default;
    virtual void OnFeatureDetectionStatusChanged(SceneFeature feature, FeatureDetectionStatus status) = 0;
    virtual bool IsFeatureSubscribed(SceneFeature feature) = 0;

    inline bool UpdateStatus(SceneFeature feature, FeatureDetectionStatus status)
    {
        std::lock_guard<std::mutex> lock(featureStatusMapMutex_);
        auto it = featureStatusMap_.find(feature);
        if (it == featureStatusMap_.end()) {
            featureStatusMap_[feature] = status;
            return true;
        } else if (it->second != status) {
            it->second = status;
            return true;
        }
        return false;
    }

private:
    std::mutex featureStatusMapMutex_;
    std::unordered_map<SceneFeature, FeatureDetectionStatus> featureStatusMap_;
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

class SmoothZoomCallback {
public:
    SmoothZoomCallback() = default;
    virtual ~SmoothZoomCallback() = default;
    virtual void OnSmoothZoom(int32_t duration) = 0;
};

class AbilityCallback {
public:
    AbilityCallback() = default;
    virtual ~AbilityCallback() = default;
    virtual void OnAbilityChange() = 0;
};

struct ARStatusInfo {
    std::vector<int32_t> laserData;
    float lensFocusDistance;
    int32_t sensorSensitivity;
    uint32_t exposureDurationValue;
    int64_t timestamp;
};

class ARCallback {
public:
    ARCallback() = default;
    virtual ~ARCallback() = default;
    virtual void OnResult(const ARStatusInfo &arStatusInfo) const = 0;
};

class EffectSuggestionCallback {
public:
    EffectSuggestionCallback() = default;
    virtual ~EffectSuggestionCallback() = default;
    virtual void OnEffectSuggestionChange(EffectSuggestionType effectSuggestionType) = 0;
    bool isFirstReport = true;
    EffectSuggestionType currentType = EffectSuggestionType::EFFECT_SUGGESTION_NONE;
};

struct EffectSuggestionStatus {
    EffectSuggestionType type;
    bool status;
};

inline bool FloatIsEqual(float x, float y)
{
    const float EPSILON = 0.000001;
    return std::fabs(x - y) < EPSILON;
}

inline float ConfusingNumber(float data)
{
    const float factor = 20;
    return data * factor;
}

class CaptureSession : public RefBase {
public:
    class CaptureSessionMetadataResultProcessor : public MetadataResultProcessor {
    public:
        explicit CaptureSessionMetadataResultProcessor(wptr<CaptureSession> session) : session_(session) {}
        void ProcessCallbacks(
            const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result) override;

    private:
        wptr<CaptureSession> session_;
    };

    explicit CaptureSession(sptr<ICaptureSession>& captureSession);
    virtual ~CaptureSession();

    /**
     * @brief Begin the capture session config.
     */
    int32_t BeginConfig();

    /**
     * @brief Commit the capture session config.
     */
    virtual int32_t CommitConfig();

    /**
     * @brief Determine if the given Input can be added to session.
     *
     * @param CaptureInput to be added to session.
     */
    virtual bool CanAddInput(sptr<CaptureInput>& input);

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
    virtual bool CanAddOutput(sptr<CaptureOutput>& output);

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
     * @brief Set the moving photo callback.
     *
     * @param photoProxy Requested for the pointer where moving photo callback is present.
     * @param uri get uri for medialibary.
     * @param cameraShotType get cameraShotType for medialibary.
     */

    void CreateMediaLibrary(sptr<CameraPhotoProxy> photoProxy, std::string &uri, int32_t &cameraShotType,
                            std::string &burstKey, int64_t timestamp);

    /**
     * @brief Get the application callback information.
     *
     * @return Returns the pointer to SessionCallback set by application.
     */
    std::shared_ptr<SessionCallback> GetApplicationCallback();

    /**
     * @brief Get the ExposureCallback.
     *
     * @return Returns the pointer to ExposureCallback.
     */
    std::shared_ptr<ExposureCallback> GetExposureCallback();

    /**
     * @brief Get the FocusCallback.
     *
     * @return Returns the pointer to FocusCallback.
     */
    std::shared_ptr<FocusCallback> GetFocusCallback();

    /**
     * @brief Get the MacroStatusCallback.
     *
     * @return Returns the pointer to MacroStatusCallback.
     */
    std::shared_ptr<MacroStatusCallback> GetMacroStatusCallback();

    /**
     * @brief Get the MoonCaptureBoostStatusCallback.
     *
     * @return Returns the pointer to MoonCaptureBoostStatusCallback.
     */
    std::shared_ptr<MoonCaptureBoostStatusCallback> GetMoonCaptureBoostStatusCallback();

    /**
     * @brief Get the FeatureDetectionStatusCallback.
     *
     * @return Returns the pointer to FeatureDetectionStatusCallback.
     */
    std::shared_ptr<FeatureDetectionStatusCallback> GetFeatureDetectionStatusCallback();

    /**
     * @brief Get the SmoothZoomCallback.
     *
     * @return Returns the pointer to SmoothZoomCallback.
     */
    std::shared_ptr<SmoothZoomCallback> GetSmoothZoomCallback();

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
    * @brief Set the smooth zoom callback.
    * which will be called when there is smooth zoom change.
    *
    * @param The SmoothZoomCallback pointer.
    */
    void SetSmoothZoomCallback(std::shared_ptr<SmoothZoomCallback> smoothZoomCallback);

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
     * @brief Prepare Zoom change.
     *
     * @return Returns errCode.
     */
    int32_t PrepareZoom();

    /**
     * @brief UnPrepare Zoom hange.
     *
     * @return Returns errCode.
     */
    int32_t UnPrepareZoom();

    /**
     * @brief Set Smooth Zoom.
     *
     * @param Target smooth zoom ratio.
     * @param Smooth zoom type.
     * @return Returns errCode.
     */
    int32_t SetSmoothZoom(float targetZoomRatio, uint32_t smoothZoomType);

    /**
     * @brief Get the supported Zoom point info.
     *
     * @param vector<ZoomPointInfo> of supported ZoomPointInfo.
     * @return Returns errCode.
     */
    int32_t GetZoomPointInfos(std::vector<ZoomPointInfo>& zoomPointInfoList);

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

// Focus Distance
    /**
     * @brief Get the current FocusDistance.
     * @param distance current Focus Distance.
     * @return Returns errCode.
     */
    int32_t GetFocusDistance(float& distance);

    /**
     * @brief Set Focus istance.
     *
     * @param distance to be set.
     * @return Returns errCode.
     */
    int32_t SetFocusDistance(float distance);

    /**
     * @brief Get the current FocusDistance.
     * @param distance current Focus Distance.
     * @return Returns errCode.
     */
    float GetMinimumFocusDistance();

    /**
     * @brief Check current status is support macro or not.
     */
    bool IsMacroSupported();

    /**
     * @brief Enable macro lens.
     */
    int32_t EnableMacro(bool isEnable);

    /**
    * @brief Check current status is support motion photo.
    */
    bool IsMovingPhotoSupported();

    /**
     * @brief Enable motion photo.
     */
    int32_t EnableMovingPhoto(bool isEnable);

    /**
     * @brief startMotionPhotoCapture.
     */
    int32_t StartMovingPhotoCapture(bool isMirror, int32_t rotation);

    /**
     * @brief Check current status is support moon capture boost or not.
     */
    bool IsMoonCaptureBoostSupported();

    /**
     * @brief Enable or disable moon capture boost ability.
     */
    int32_t EnableMoonCaptureBoost(bool isEnable);

    /**
     * @brief Check current status is support target feature or not.
     */
    bool IsFeatureSupported(SceneFeature feature);

    /**
     * @brief Enable or disable target feature ability.
     */
    int32_t EnableFeature(SceneFeature feature, bool isEnable);

    /**
     * @brief Set the macro status callback.
     * which will be called when there is macro state change.
     *
     * @param The MacroStatusCallback pointer.
     */
    void SetMacroStatusCallback(std::shared_ptr<MacroStatusCallback> callback);

    /**
     * @brief Set the moon detect status callback.
     * which will be called when there is moon detect state change.
     *
     * @param The MoonCaptureBoostStatusCallback pointer.
     */
    void SetMoonCaptureBoostStatusCallback(std::shared_ptr<MoonCaptureBoostStatusCallback> callback);

    /**
     * @brief Set the feature detection status callback.
     * which will be called when there is feature detection state change.
     *
     * @param The FeatureDetectionStatusCallback pointer.
     */
    void SetFeatureDetectionStatusCallback(std::shared_ptr<FeatureDetectionStatusCallback> callback);

    void SetEffectSuggestionCallback(std::shared_ptr<EffectSuggestionCallback> effectSuggestionCallback);

    /**
     * @brief This function is called when there is macro status change
     * and process the macro status callback.
     *
     * @param result Metadata got from callback from service layer.
     */
    void ProcessMacroStatusChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result);

    /**
     * @brief This function is called when there is moon detect status change
     * and process the moon detect status callback.
     *
     * @param result Metadata got from callback from service layer.
     */
    void ProcessMoonCaptureBoostStatusChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result);

    /**
     * @brief This function is called when there is low light detect status change
     * and process the low light detect status callback.
     *
     * @param result Metadata got from callback from service layer.
     */
    void ProcessLowLightBoostStatusChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result);

    /**
     * @brief Check current status is support moon capture boost or not.
     */
    bool IsLowLightBoostSupported();

    /**
     * @brief Enable or disable moon capture boost ability.
     */
    int32_t EnableLowLightBoost(bool isEnable);

    /**
     * @brief Enable or disable moon capture boost ability.
     */
    int32_t EnableLowLightDetection(bool isEnable);

    /**
     * @brief Verify that the output configuration is legitimate.
     *
     * @param outputProfile The target profile.
     * @param outputType The type of output profile.
     *
     * @return True if the profile is supported, false otherwise.
     */
    bool ValidateOutputProfile(Profile& outputProfile, CaptureOutputType outputType);

    /**
     * @brief Check the preconfig type is supported or not.
     *
     * @param preconfigType The target preconfig type.
     * @param preconfigRatio The target ratio enum
     *
     * @return True if the preconfig type is supported, false otherwise.
     */
    virtual bool CanPreconfig(PreconfigType preconfigType, ProfileSizeRatio preconfigRatio);

    /**
     * @brief Set the preconfig type.
     *
     * @param preconfigType The target preconfig type.
     * @param preconfigRatio The target ratio enum
     *
     * @return Camera error code.
     */
    virtual int32_t Preconfig(PreconfigType preconfigType, ProfileSizeRatio preconfigRatio);

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

     /**
     * @brief Get whether or not start session.
     *
     * @return Returns whether or not start session.
     */
    bool IsSessionStarted();

    /**
     * @brief Set FrameRate Range.
     *
     * @return Returns whether or not commit config.
     */
    void SetFrameRateRange(const std::vector<int32_t>& frameRateRange);

    /**
    * @brief Set camera sensor sensitivity.
    * @param sensitivity sensitivity value to be set.
    * @return errCode.
    */
    int32_t SetSensorSensitivity(uint32_t sensitivity);

    /**
    * @brief Get camera sensor sensitivity.
    * @param sensitivity current sensitivity value.
    * @return Returns errCode.
    */
    int32_t GetSensorSensitivityRange(std::vector<int32_t> &sensitivityRange);

    /**
    * @brief Get exposure time range.
    * @param vector of exposure time range.
    * @return errCode.
    */
    int32_t GetSensorExposureTimeRange(std::vector<uint32_t> &sensorExposureTimeRange);

    /**
    * @brief Set exposure time value.
    * @param exposure compensation value to be set.
    * @return errCode.
    */
    int32_t SetSensorExposureTime(uint32_t sensorExposureTime);

    /**
    * @brief Get exposure time value.
    * @param exposure current exposure time value .
    * @return Returns errCode.
    */
    int32_t GetSensorExposureTime(uint32_t &sensorExposureTime);

    /**
    * @brief Get sensor module type
    * @param moduleType sensor module type.
    * @return Returns errCode.
    */
    int32_t GetModuleType(uint32_t &moduleType);

    /**
     * @brief Set ar mode.
     * @param isEnable switch to control ar mode.
     * @return errCode
     */
    int32_t SetARMode(bool isEnable);

    /**
     * @brief Set the ar callback.
     * which will be called when there is ar info update.
     *
     * @param arCallback ARCallback pointer.
     */
    void SetARCallback(std::shared_ptr<ARCallback> arCallback);

    /**
     * @brief Get the ARCallback.
     *
     * @return Returns the pointer to ARCallback.
     */
    std::shared_ptr<ARCallback> GetARCallback();

    /**
     * @brief Get Session Functions.
     *
     * @param previewProfiles to be searched.
     * @param photoProfiles to be searched.
     * @param videoProfiles to be searched.
     */
    std::vector<sptr<CameraAbility>> GetSessionFunctions(std::vector<Profile>& previewProfiles,
                                                         std::vector<Profile>& photoProfiles,
                                                         std::vector<VideoProfile>& videoProfiles,
                                                         bool isForApp = true);

    /**
     * @brief Get Session Conflict Functions.
     *
     */
    std::vector<sptr<CameraAbility>> GetSessionConflictFunctions();

    /**
     * @brief Get CameraOutput Capabilities.
     *
     */
    std::vector<sptr<CameraOutputCapability>> GetCameraOutputCapabilities(sptr<CameraDevice> &camera);

    /**
     * @brief CreateCameraAbilityContainer.
     *
     */
    void CreateCameraAbilityContainer();

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
     * @brief Batch set effect suggestion status.
     * @param effectSuggestionStatusList effect suggestion status list to be set.
     * @return errCode
     */
    int32_t SetEffectSuggestionStatus(std::vector<EffectSuggestionStatus> effectSuggestionStatusList);

    /**
     * @brief Set ar mode.
     * @param effectSuggestionType switch to control effect suggestion.
     * @param isEnable switch to control effect suggestion status.
     * @return errCode
     */
    int32_t UpdateEffectSuggestion(EffectSuggestionType effectSuggestionType, bool isEnable);

    /**
     * @brief This function is called when there is effect suggestion type change
     * and process the effect suggestion callback.
     *
     * @param result metadata got from callback from service layer.
     */
    void ProcessEffectSuggestionTypeUpdates(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result);

    /**
     * @brief Get the supported portrait effects.
     *
     * @return Returns the array of portraiteffect.
     */
    std::vector<PortraitEffect> GetSupportedPortraitEffects();

    /**
     * @brief Get the supported virtual apertures.
     * @param apertures returns the array of virtual aperture.
     * @return Error code.
     */
    int32_t GetSupportedVirtualApertures(std::vector<float>& apertures);

    /**
     * @brief Get the virtual aperture.
     * @param aperture returns the current virtual aperture.
     * @return Error code.
     */
    int32_t GetVirtualAperture(float& aperture);

    /**
     * @brief Set the virtual aperture.
     * @param virtualAperture set virtual aperture value.
     * @return Error code.
     */
    int32_t SetVirtualAperture(const float virtualAperture);

    /**
     * @brief Get the supported physical apertures.
     * @param apertures returns the array of physical aperture.
     * @return Error code.
     */
    int32_t GetSupportedPhysicalApertures(std::vector<std::vector<float>>& apertures);

    /**
     * @brief Get the physical aperture.
     * @param aperture returns current physical aperture.
     * @return Error code.
     */
    int32_t GetPhysicalAperture(float& aperture);

    /**
     * @brief Set the physical aperture.
     * @param physicalAperture set physical aperture value.
     * @return Error code.
     */
    int32_t SetPhysicalAperture(float physicalAperture);

    void SetMode(SceneMode modeName);
    SceneMode GetMode();
    SceneFeaturesMode GetFeaturesMode();
    std::vector<SceneFeaturesMode> GetSubFeatureMods();
    bool IsSetEnableMacro();
    sptr<CaptureOutput> GetMetaOutput();
    void ProcessFaceRecUpdates(const uint64_t timestamp,
                                    const std::shared_ptr<OHOS::Camera::CameraMetadata> &result);
    void ProcessSnapshotDurationUpdates(const uint64_t timestamp,
                                    const std::shared_ptr<OHOS::Camera::CameraMetadata> &result);

    virtual std::shared_ptr<OHOS::Camera::CameraMetadata> GetMetadata();

    void ExecuteAbilityChangeCallback();
    void SetAbilityCallback(std::shared_ptr<AbilityCallback> abilityCallback);
    void ProcessAREngineUpdates(const uint64_t timestamp,
                                    const std::shared_ptr<OHOS::Camera::CameraMetadata> &result);

    void EnableDeferredType(DeferredDeliveryImageType deferredType, bool isEnableByUser);
    void SetUserId();
    bool IsMovingPhotoEnabled();
    bool IsImageDeferred();

    int32_t EnableAutoHighQualityPhoto(bool enabled);

    virtual bool CanSetFrameRateRange(int32_t minFps, int32_t maxFps, CaptureOutput* curOutput);
    bool CanSetFrameRateRangeForOutput(int32_t minFps, int32_t maxFps, CaptureOutput* curOutput);
    int32_t AddSecureOutput(sptr<CaptureOutput> &output);

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

    inline std::shared_ptr<MetadataResultProcessor> GetMetadataResultProcessor()
    {
        return metadataResultProcessor_;
    }

    inline sptr<CaptureInput> GetInputDevice()
    {
        std::lock_guard<std::mutex> lock(inputDeviceMutex_);
        return innerInputDevice_;
    }

    inline sptr<ICaptureSession> GetCaptureSession()
    {
        std::lock_guard<std::mutex> lock(captureSessionMutex_);
        return innerCaptureSession_;
    }

    int32_t SetPreviewRotation(std::string &deviceClass);

protected:

    static const std::unordered_map<camera_awb_mode_t, WhiteBalanceMode> metaWhiteBalanceModeMap_;
    static const std::unordered_map<WhiteBalanceMode, camera_awb_mode_t> fwkWhiteBalanceModeMap_;

    static const std::unordered_map<LightPaintingType, CameraLightPaintingType> fwkLightPaintingTypeMap_;
    static const std::unordered_map<CameraLightPaintingType, LightPaintingType> metaLightPaintingTypeMap_;

    std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata_;
    Profile photoProfile_;
    Profile previewProfile_;
    std::map<BeautyType, std::vector<int32_t>> beautyTypeAndRanges_;
    std::map<BeautyType, int32_t> beautyTypeAndLevels_;
    std::shared_ptr<MetadataResultProcessor> metadataResultProcessor_ = nullptr;
    bool isImageDeferred_ = false;
    std::atomic<bool> isMovingPhotoEnabled_ { false };

    std::shared_ptr<AbilityCallback> abilityCallback_;
    std::atomic<uint32_t> exposureDurationValue_ = 0;

    float apertureValue_ = 0.0;

    inline void ClearPreconfigProfiles()
    {
        std::lock_guard<std::mutex> lock(preconfigProfilesMutex_);
        preconfigProfiles_ = nullptr;
    }

    inline void SetPreconfigProfiles(std::shared_ptr<PreconfigProfiles> preconfigProfiles)
    {
        std::lock_guard<std::mutex> lock(preconfigProfilesMutex_);
        preconfigProfiles_ = preconfigProfiles;
    }

    inline std::shared_ptr<PreconfigProfiles> GetPreconfigProfiles()
    {
        std::lock_guard<std::mutex> lock(preconfigProfilesMutex_);
        return preconfigProfiles_;
    }

    inline void SetInputDevice(sptr<CaptureInput> inputDevice)
    {
        std::lock_guard<std::mutex> lock(inputDeviceMutex_);
        innerInputDevice_ = inputDevice;
    }

    inline sptr<CameraAbilityContainer> GetCameraAbilityContainer()
    {
        std::lock_guard<std::mutex> lock(abilityContainerMutex_);
        return cameraAbilityContainer_;
    }

    inline void SetCaptureSession(sptr<ICaptureSession> captureSession)
    {
        std::lock_guard<std::mutex> lock(captureSessionMutex_);
        innerCaptureSession_ = captureSession;
    }

    virtual std::shared_ptr<PreconfigProfiles> GeneratePreconfigProfiles(
        PreconfigType preconfigType, ProfileSizeRatio preconfigRatio);

private:
    std::mutex changeMetaMutex_;
    std::mutex sessionCallbackMutex_;
    std::mutex captureSessionMutex_;
    sptr<ICaptureSession> innerCaptureSession_ = nullptr;
    std::shared_ptr<SessionCallback> appCallback_;
    sptr<ICaptureSessionCallback> captureSessionCallback_;
    std::shared_ptr<ExposureCallback> exposureCallback_;
    std::shared_ptr<FocusCallback> focusCallback_;
    std::shared_ptr<MacroStatusCallback> macroStatusCallback_;
    std::shared_ptr<MoonCaptureBoostStatusCallback> moonCaptureBoostStatusCallback_;
    std::shared_ptr<FeatureDetectionStatusCallback> featureDetectionStatusCallback_;
    std::shared_ptr<SmoothZoomCallback> smoothZoomCallback_;
    std::shared_ptr<ARCallback> arCallback_;
    std::shared_ptr<EffectSuggestionCallback> effectSuggestionCallback_;
    std::vector<int32_t> skinSmoothBeautyRange_;
    std::vector<int32_t> faceSlendorBeautyRange_;
    std::vector<int32_t> skinToneBeautyRange_;
    std::mutex captureOutputSetsMutex_;
    std::set<wptr<CaptureOutput>, RefBaseCompare<CaptureOutput>> captureOutputSets_;

    std::mutex inputDeviceMutex_;
    sptr<CaptureInput> innerInputDevice_ = nullptr;
    volatile bool isSetMacroEnable_ = false;
    volatile bool isSetMoonCaptureBoostEnable_ = false;
    volatile bool isSetSecureOutput_ = false;
    std::atomic<bool> isSetLowLightBoostEnable_ = false;
    static const std::unordered_map<camera_focus_state_t, FocusCallback::FocusState> metaFocusStateMap_;
    static const std::unordered_map<camera_exposure_state_t, ExposureCallback::ExposureState> metaExposureStateMap_;

    static const std::unordered_map<camera_filter_type_t, FilterType> metaFilterTypeMap_;
    static const std::unordered_map<FilterType, camera_filter_type_t> fwkFilterTypeMap_;
    static const std::unordered_map<BeautyType, camera_device_metadata_tag_t> fwkBeautyControlMap_;
    static const std::unordered_map<camera_device_metadata_tag_t, BeautyType> metaBeautyControlMap_;
    static const std::unordered_map<CameraEffectSuggestionType, EffectSuggestionType> metaEffectSuggestionTypeMap_;
    static const std::unordered_map<EffectSuggestionType, CameraEffectSuggestionType> fwkEffectSuggestionTypeMap_;
    sptr<CaptureOutput> metaOutput_ = nullptr;
    sptr<CaptureOutput> photoOutput_;
    std::atomic<int32_t> prevDuration_ = 0;
    sptr<CameraDeathRecipient> deathRecipient_ = nullptr;
    bool isColorSpaceSetted_ = false;
    atomic<bool> isDeferTypeSetted_ = false;

    std::mutex preconfigProfilesMutex_;
    std::shared_ptr<PreconfigProfiles> preconfigProfiles_ = nullptr;

    // private tag
    uint32_t HAL_CUSTOM_AR_MODE = 0;
    uint32_t HAL_CUSTOM_LASER_DATA = 0;
    uint32_t HAL_CUSTOM_SENSOR_MODULE_TYPE = 0;
    uint32_t HAL_CUSTOM_LENS_FOCUS_DISTANCE = 0;
    uint32_t HAL_CUSTOM_SENSOR_SENSITIVITY = 0;

    std::mutex abilityContainerMutex_;
    sptr<CameraAbilityContainer> cameraAbilityContainer_ = nullptr;
    atomic<bool> supportSpecSearch_ = false;
    void CheckSpecSearch();
    void PopulateProfileLists(std::vector<Profile>& photoProfileList,
                              std::vector<Profile>& previewProfileList,
                              std::vector<VideoProfile>& videoProfileList);
    void PopulateSpecIdMaps(sptr<CameraDevice> device, int32_t modeName,
                            std::map<int32_t, std::vector<Profile>>& specIdPreviewMap,
                            std::map<int32_t, std::vector<Profile>>& specIdPhotoMap,
                            std::map<int32_t, std::vector<VideoProfile>>& specIdVideoMap);
    // Make sure you know what you are doing, you'd better to use {GetMode()} function instead of this variable.
    SceneMode currentMode_ = SceneMode::NORMAL;
    SceneMode guessMode_ = SceneMode::NORMAL;
    std::mutex moonCaptureBoostFeatureMutex_;
    std::shared_ptr<MoonCaptureBoostFeature> moonCaptureBoostFeature_ = nullptr;
    float focusDistance_ = 0.0;
    std::shared_ptr<MoonCaptureBoostFeature> GetMoonCaptureBoostFeature();
    void SetGuessMode(SceneMode mode);
    int32_t UpdateSetting(std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata);
    Point CoordinateTransform(Point point);
    int32_t CalculateExposureValue(float exposureValue);
    Point VerifyFocusCorrectness(Point point);
    int32_t ConfigureOutput(sptr<CaptureOutput>& output);
    int32_t ConfigurePreviewOutput(sptr<CaptureOutput>& output);
    int32_t ConfigurePhotoOutput(sptr<CaptureOutput>& output);
    int32_t ConfigureVideoOutput(sptr<CaptureOutput>& output);
    std::shared_ptr<Profile> GetMaxSizePhotoProfile(ProfileSizeRatio sizeRatio);
    std::shared_ptr<Profile> GetPreconfigPreviewProfile();
    std::shared_ptr<Profile> GetPreconfigPhotoProfile();
    std::shared_ptr<VideoProfile> GetPreconfigVideoProfile();
    void CameraServerDied(pid_t pid);
    void InsertOutputIntoSet(sptr<CaptureOutput>& output);
    void RemoveOutputFromSet(sptr<CaptureOutput>& output);
    void OnSettingUpdated(std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata);
    void OnResultReceived(std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata);
    ColorSpaceInfo GetSupportedColorSpaceInfo();
    bool IsModeWithVideoStream();
    void SetDefaultColorSpace();
    void UpdateDeviceDeferredability();
    void ProcessProfilesAbilityId(const SceneMode supportModes);
    int32_t ProcessCaptureColorSpace(ColorSpaceInfo colorSpaceInfo, ColorSpace& fwkCaptureColorSpace);
    void ProcessFocusDistanceUpdates(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result);
    void FindTagId();
    bool CheckFrameRateRangeWithCurrentFps(int32_t curMinFps, int32_t curMaxFps, int32_t minFps, int32_t maxFps);
    void SessionRemoveDeathRecipient();
    int32_t AdaptOutputVideoHighFrameRate(sptr<CaptureOutput>& output, sptr<ICaptureSession>& captureSession);
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CAPTURE_SESSION_H
