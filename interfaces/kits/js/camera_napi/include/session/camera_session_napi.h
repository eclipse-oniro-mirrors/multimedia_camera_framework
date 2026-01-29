/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef CAMERA_SESSION_NAPI_H_
#define CAMERA_SESSION_NAPI_H_

#include <memory>
#include <mutex>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <uv.h>

#include "camera_napi_event_emitter.h"
#include "input/camera_manager.h"
#include "listener_base.h"
#include "session/capture_session.h"
#include "camera_napi_adaptor.h"

namespace OHOS {
namespace CameraStandard {
static const char CAMERA_SESSION_NAPI_CLASS_NAME[] = "CaptureSession";

class IsoInfoCallbackListener : public IsoInfoCallback, public ListenerBase,
    public IsoInfoSyncCallback, public std::enable_shared_from_this<IsoInfoCallbackListener> {
public:
    IsoInfoCallbackListener(napi_env env) : ListenerBase(env) {}
    ~IsoInfoCallbackListener() = default;
    void OnIsoInfoChanged(IsoInfo info) override;
    void OnIsoInfoChangedSync(IsoInfo info) override;

private:
    void OnIsoInfoChangedCallback(IsoInfo info) const;
    void OnIsoInfoChangedCallbackOneArg(IsoInfo info) const;

    void OnIsoInfoChangedCallbackAsync(IsoInfo info, bool isSync) const;
};

struct IsoInfoChangedCallback {
    IsoInfo info_;
    weak_ptr<const IsoInfoCallbackListener> listener_;
    IsoInfoChangedCallback(IsoInfo info, shared_ptr<const IsoInfoCallbackListener> listener)
        : info_(info), listener_(listener) {}
};

class ExposureCallbackListener : public ExposureCallback, public ListenerBase,
    public std::enable_shared_from_this<ExposureCallbackListener> {
public:
    ExposureCallbackListener(napi_env env) : ListenerBase(env) {}
    ~ExposureCallbackListener() = default;
    void OnExposureState(const ExposureState state) override;

private:
    void OnExposureStateCallback(ExposureState state) const;
    void OnExposureStateCallbackAsync(ExposureState state) const;
};

struct ExposureCallbackInfo {
    ExposureCallback::ExposureState state_;
    weak_ptr<const ExposureCallbackListener> listener_;
    ExposureCallbackInfo(ExposureCallback::ExposureState state, shared_ptr<const ExposureCallbackListener> listener)
        : state_(state), listener_(listener) {}
};

class FocusCallbackListener : public FocusCallback, public ListenerBase,
    public std::enable_shared_from_this<FocusCallbackListener> {
public:
    FocusCallbackListener(napi_env env) : ListenerBase(env)
    {
        currentState = FocusState::UNFOCUSED;
    }
    ~FocusCallbackListener() = default;
    void OnFocusState(FocusState state) override;

private:
    void OnFocusStateCallback(FocusState state) const;
    void OnFocusStateCallbackAsync(FocusState state) const;
};

struct FocusCallbackInfo {
    FocusCallback::FocusState state_;
    weak_ptr<const FocusCallbackListener> listener_;
    FocusCallbackInfo(FocusCallback::FocusState state, shared_ptr<const FocusCallbackListener> listener)
        : state_(state), listener_(listener) {}
};

class MoonCaptureBoostCallbackListener : public MoonCaptureBoostStatusCallback, public ListenerBase,
    public std::enable_shared_from_this<MoonCaptureBoostCallbackListener> {
public:
    MoonCaptureBoostCallbackListener(napi_env env) : ListenerBase(env) {}
    ~MoonCaptureBoostCallbackListener() = default;
    void OnMoonCaptureBoostStatusChanged(MoonCaptureBoostStatus status) override;

private:
    void OnMoonCaptureBoostStatusCallback(MoonCaptureBoostStatus status) const;
    void OnMoonCaptureBoostStatusCallbackAsync(MoonCaptureBoostStatus status) const;
};

struct MoonCaptureBoostStatusCallbackInfo {
    MoonCaptureBoostStatusCallback::MoonCaptureBoostStatus status_;
    weak_ptr<const MoonCaptureBoostCallbackListener> listener_;
    MoonCaptureBoostStatusCallbackInfo(
        MoonCaptureBoostStatusCallback::MoonCaptureBoostStatus status,
            shared_ptr<const MoonCaptureBoostCallbackListener> listener)
        : status_(status), listener_(listener)
    {}
};

class SessionCallbackListener : public SessionCallback, public ListenerBase,
    public std::enable_shared_from_this<SessionCallbackListener> {
public:
    SessionCallbackListener(napi_env env) : ListenerBase(env) {}
    ~SessionCallbackListener() = default;
    void OnError(int32_t errorCode) override;

private:
    void OnErrorCallback(int32_t errorCode) const;
    void OnErrorCallbackAsync(int32_t errorCode) const;
};

class PressureCallbackListener : public PressureCallback, public ListenerBase,
    public std::enable_shared_from_this<PressureCallbackListener> {
public:
    PressureCallbackListener(napi_env env) : ListenerBase(env) {}
    ~PressureCallbackListener() = default;
    void OnPressureStatusChanged(PressureStatus status) override;

private:
    void OnPressureCallback(PressureStatus status) const;
    void OnPressureCallbackAsync(PressureStatus status) const;
};

class ControlCenterEffectStatusCallbackListener : public ControlCenterEffectCallback, public ListenerBase,
    public std::enable_shared_from_this<ControlCenterEffectStatusCallbackListener> {
public:
    ControlCenterEffectStatusCallbackListener(napi_env env) : ListenerBase(env) {}
    ~ControlCenterEffectStatusCallbackListener() = default;
    void OnControlCenterEffectStatusChanged(ControlCenterStatusInfo controlCenterStatusInfo) override;

private:
    void OnControlCenterEffectStatusCallback(ControlCenterStatusInfo controlCenterStatusInfo) const;
    void OnControlCenterEffectStatusCallbackAsync(ControlCenterStatusInfo controlCenterStatusInfo) const;
};

struct SessionCallbackInfo {
    int32_t errorCode_;
    weak_ptr<const SessionCallbackListener> listener_;
    SessionCallbackInfo(int32_t errorCode, shared_ptr<const SessionCallbackListener> listener)
        : errorCode_(errorCode), listener_(listener) {}
};

struct PressureCallbackInfo {
    PressureStatus status_;
    weak_ptr<const PressureCallbackListener> listener_;
    PressureCallbackInfo(PressureStatus status, shared_ptr<const PressureCallbackListener> listener)
        : status_(status), listener_(listener) {}
};

struct ControlCenterEffectCallbackInfo {
    ControlCenterStatusInfo statusInfo_;
    weak_ptr<const ControlCenterEffectStatusCallbackListener> listener_;
    ControlCenterEffectCallbackInfo(ControlCenterStatusInfo statusInfo,
        shared_ptr<const ControlCenterEffectStatusCallbackListener> listener)
        : statusInfo_(statusInfo), listener_(listener) {}
};

class SmoothZoomCallbackListener : public SmoothZoomCallback, public ListenerBase,
    public std::enable_shared_from_this<SmoothZoomCallbackListener> {
public:
    SmoothZoomCallbackListener(napi_env env) : ListenerBase(env) {}
    ~SmoothZoomCallbackListener() = default;
    void OnSmoothZoom(int32_t duration) override;

private:
    void OnSmoothZoomCallback(int32_t duration) const;
    void OnSmoothZoomCallbackAsync(int32_t duration) const;
};

struct SmoothZoomCallbackInfo {
    int32_t duration_;
    weak_ptr<const SmoothZoomCallbackListener> listener_;
    SmoothZoomCallbackInfo(int32_t duration, shared_ptr<const SmoothZoomCallbackListener> listener)
        : duration_(duration), listener_(listener) {}
};

class AbilityCallbackListener : public AbilityCallback, public ListenerBase,
    public std::enable_shared_from_this<AbilityCallbackListener> {
public:
    AbilityCallbackListener(napi_env env) : ListenerBase(env) {}
    ~AbilityCallbackListener() = default;
    void OnAbilityChange() override;

private:
    void OnAbilityChangeCallback() const;
    void OnAbilityChangeCallbackAsync() const;
};

struct AbilityCallbackInfo {
    weak_ptr<const AbilityCallbackListener> listener_;
    AbilityCallbackInfo(shared_ptr<const AbilityCallbackListener> listener) : listener_(listener) {}
};

class AutoDeviceSwitchCallbackListener : public AutoDeviceSwitchCallback, public ListenerBase {
public:
    AutoDeviceSwitchCallbackListener(napi_env env) : ListenerBase(env) {}
    ~AutoDeviceSwitchCallbackListener() = default;
    void OnAutoDeviceSwitchStatusChange(bool isDeviceSwitched, bool isDeviceCapabilityChanged) const override;
private:
    void OnAutoDeviceSwitchCallback(bool isDeviceSwitched, bool isDeviceCapabilityChanged) const;
    void OnAutoDeviceSwitchCallbackAsync(bool isDeviceSwitched, bool isDeviceCapabilityChanged) const;
};

struct AutoDeviceSwitchCallbackListenerInfo {
    bool isDeviceSwitched_;
    bool isDeviceCapabilityChanged_;
    const AutoDeviceSwitchCallbackListener* listener_;
    AutoDeviceSwitchCallbackListenerInfo(bool isDeviceSwitched, bool isDeviceCapabilityChanged,
        const AutoDeviceSwitchCallbackListener* listener)
        : isDeviceSwitched_(isDeviceSwitched), isDeviceCapabilityChanged_(isDeviceCapabilityChanged),
        listener_(listener) {}
};

class CompositionPositionCalibrationCallbackListener : public CompositionPositionCalibrationCallback,
    public ListenerBase, public std::enable_shared_from_this<CompositionPositionCalibrationCallbackListener> {
public:
    CompositionPositionCalibrationCallbackListener(napi_env env) : ListenerBase(env) {}
    ~CompositionPositionCalibrationCallbackListener() = default;
    void OnCompositionPositionCalibrationAvailable(
        const CompositionPositionCalibrationInfo info) const override;
private:
    void OnCompositionPositionCalibrationCallback(
        const CompositionPositionCalibrationInfo info) const;
    void OnCompositionPositionCalibrationCallbackAsync(
        const CompositionPositionCalibrationInfo info) const;
};

struct CompositionPositionCalibrationCallbackListenerInfo {
    CompositionPositionCalibrationInfo info_;
    weak_ptr<const CompositionPositionCalibrationCallbackListener> listener_;
    CompositionPositionCalibrationCallbackListenerInfo(CompositionPositionCalibrationInfo info,
        shared_ptr<const CompositionPositionCalibrationCallbackListener> listener)
        : info_(info), listener_(listener) {}
};

class CompositionBeginCallbackListener : public CompositionBeginCallback, public ListenerBase,
    public std::enable_shared_from_this<CompositionBeginCallbackListener> {
public:
    CompositionBeginCallbackListener(napi_env env) : ListenerBase(env) {}
    ~CompositionBeginCallbackListener() = default;
    void OnCompositionBeginAvailable() const override;
private:
    void OnCompositionBeginCallback() const;
    void OnCompositionBeginCallbackAsync() const;
};

struct CompositionBeginCallbackListenerInfo {
    weak_ptr<const CompositionBeginCallbackListener> listener_;
    CompositionBeginCallbackListenerInfo(shared_ptr<const CompositionBeginCallbackListener> listener)
        : listener_(listener) {}
};

class CompositionEndCallbackListener : public CompositionEndCallback, public ListenerBase,
    public std::enable_shared_from_this<CompositionEndCallbackListener> {
public:
    CompositionEndCallbackListener(napi_env env) : ListenerBase(env) {}
    ~CompositionEndCallbackListener() = default;
    void OnCompositionEndAvailable(CompositionEndState state) const override;
private:
    void OnCompositionEndCallback(CompositionEndState state) const;
    void OnCompositionEndCallbackAsync(CompositionEndState state) const;
};

struct CompositionEndCallbackListenerInfo {
    CompositionEndState state_;
    weak_ptr<const CompositionEndCallbackListener> listener_;
    CompositionEndCallbackListenerInfo(CompositionEndState state,
        shared_ptr<const CompositionEndCallbackListener> listener)
        : state_(state), listener_(listener) {}
};

class CompositionPositionMatchCallbackListener : public CompositionPositionMatchCallback, public ListenerBase,
    public std::enable_shared_from_this<CompositionPositionMatchCallbackListener> {
public:
    CompositionPositionMatchCallbackListener(napi_env env) : ListenerBase(env) {}
    ~CompositionPositionMatchCallbackListener() = default;
    void OnCompositionPositionMatchAvailable(const std::vector<float> zoomRatios) const override;
private:
    void OnCompositionPositionMatchCallback(const std::vector<float> zoomRatios) const;
    void OnCompositionPositionMatchCallbackAsync(const std::vector<float> zoomRatios) const;
};

struct CompositionPositionMatchCallbackListenerInfo {
    std::vector<float> zoomRatios_;
    weak_ptr<const CompositionPositionMatchCallbackListener> listener_;
    CompositionPositionMatchCallbackListenerInfo(std::vector<float> zoomRatios,
        shared_ptr<const CompositionPositionMatchCallbackListener> listener)
        : zoomRatios_(zoomRatios), listener_(listener) {}
};

class ImageStabilizationGuideCallbackListener : public ImageStabilizationGuideCallback, public ListenerBase,
    public std::enable_shared_from_this<ImageStabilizationGuideCallbackListener> {
public:
    ImageStabilizationGuideCallbackListener(napi_env env) : ListenerBase(env) {}
    ~ImageStabilizationGuideCallbackListener() = default;
    void OnImageStabilizationGuideChange(std::vector<Point> lineSegments) override;

private:
    void OnImageStabilizationGuideCallback(std::vector<Point> lineSegments) const;
    void OnImageStabilizationGuideCallbackAsync(std::vector<Point> lineSegments) const;
};

struct ImageStabilizationGuideCallbackInfo {
    std::vector<Point> lineSegments_;
    weak_ptr<const ImageStabilizationGuideCallbackListener> listener_;
    ImageStabilizationGuideCallbackInfo(std::vector<Point> lineSegments,
        shared_ptr<const ImageStabilizationGuideCallbackListener> listener)
        : lineSegments_(lineSegments), listener_(listener) {}
};


class ApertureEffectChangeCallbackListener :
    public ApertureEffectChangeCallback,
    public ListenerBase,
    public std::enable_shared_from_this<ApertureEffectChangeCallbackListener> {
public:
    ApertureEffectChangeCallbackListener(napi_env env) : ListenerBase(env) {}
    ~ApertureEffectChangeCallbackListener() = default;
    void OnApertureEffectChange(ApertureEffectType apertureEffectType) const override;

private:
    void OnApertureEffectChangeCallback(ApertureEffectType apertureEffectType) const;
    void OnApertureEffectChangeCallbackAsync(ApertureEffectType apertureEffectType) const;
};

struct ApertureEffectChangeCallbackInfo {
    ApertureEffectChangeCallbackInfo(ApertureEffectType apertureEffectType,
        shared_ptr<const ApertureEffectChangeCallbackListener> listener)
            : apertureEffectType_(apertureEffectType), listener_(listener) {}
    ApertureEffectType apertureEffectType_;
    weak_ptr<const ApertureEffectChangeCallbackListener> listener_;
};

class CameraSwitchRequestCallbackListener :
    public CameraSwitchRequestCallback,
    public ListenerBase,
    public std::enable_shared_from_this<CameraSwitchRequestCallbackListener> {
public:
    CameraSwitchRequestCallbackListener(napi_env env) : ListenerBase(env) {}
    ~CameraSwitchRequestCallbackListener() = default;
    void OnAppCameraSwitch(const std::string &cameraId) override;

private:
    void OnAppCameraSwitchCallback(std::string &cameraId) const;
    void OnAppCameraSwitchCallbackAsync(const std::string &cameraId) const;
};

struct CameraSwitchRequestCallbackInfoCameraId {
    std::string cameraId_;
    weak_ptr<const CameraSwitchRequestCallbackListener> listener_;
    CameraSwitchRequestCallbackInfoCameraId(
        const std::string &cameraId, shared_ptr<const CameraSwitchRequestCallbackListener> listener)
        : cameraId_(cameraId), listener_(listener) {}
};

class MacroStatusCallbackListener : public MacroStatusCallback, public ListenerBase,
    public std::enable_shared_from_this<MacroStatusCallbackListener> {
public:
    MacroStatusCallbackListener(napi_env env) : ListenerBase(env) {}
    ~MacroStatusCallbackListener() = default;
    void OnMacroStatusChanged(MacroStatus status) override;

private:
    void OnMacroStatusCallback(MacroStatus status) const;
    void OnMacroStatusCallbackAsync(MacroStatus status) const;
};

struct MacroStatusCallbackInfo {
    MacroStatusCallback::MacroStatus status_;
    weak_ptr<const MacroStatusCallbackListener> listener_;
    MacroStatusCallbackInfo(
        MacroStatusCallback::MacroStatus status,
            shared_ptr<const MacroStatusCallbackListener> listener)
        : status_(status), listener_(listener)
    {}
};

class CameraSessionNapi : public CameraNapiEventEmitter<CameraSessionNapi> {
private:
    sptr<CaptureSession> GetSession()
    {
        return cameraSession_;
    }
    using Adaptor = CameraNapiAdaptor<CameraSessionNapi, CaptureSession, &CameraSessionNapi::GetSession>;
    friend Adaptor;

public:
    static void Init(napi_env env);
    static napi_value CreateCameraSession(napi_env env);
    CameraSessionNapi();
    ~CameraSessionNapi() override;

    static void CameraSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value CameraSessionNapiConstructor(napi_env env, napi_callback_info info);

    static napi_value HasFlash(napi_env env, napi_callback_info info);
    static napi_value IsFlashModeSupported(napi_env env, napi_callback_info info);
    static napi_value GetFlashMode(napi_env env, napi_callback_info info);
    static napi_value SetFlashMode(napi_env env, napi_callback_info info);
    static napi_value IsLcdFlashSupported(napi_env env, napi_callback_info info);
    static napi_value EnableLcdFlash(napi_env env, napi_callback_info info);
    static napi_value IsExposureModeSupported(napi_env env, napi_callback_info info);
    static napi_value GetExposureMode(napi_env env, napi_callback_info info);
    static napi_value SetExposureMode(napi_env env, napi_callback_info info);
    static napi_value SetMeteringPoint(napi_env env, napi_callback_info info);
    static napi_value GetMeteringPoint(napi_env env, napi_callback_info info);
    static napi_value GetJSArgsForCameraOutput(napi_env env, size_t argc, const napi_value argv[],
        sptr<CaptureOutput> &cameraOutput);
    static napi_value GetExposureBiasRange(napi_env env, napi_callback_info info);
    static napi_value SetExposureBias(napi_env env, napi_callback_info info);
    static napi_value GetExposureValue(napi_env env, napi_callback_info info);
    static napi_value IsFocusModeSupported(napi_env env, napi_callback_info info);
    static napi_value GetFocusMode(napi_env env, napi_callback_info info);
    static napi_value SetFocusMode(napi_env env, napi_callback_info info);
    static napi_value SetQualityPrioritization(napi_env env, napi_callback_info info);
    static napi_value SetFocusPoint(napi_env env, napi_callback_info info);
    static napi_value GetFocusPoint(napi_env env, napi_callback_info info);
    static napi_value GetFocalLength(napi_env env, napi_callback_info info);
    static napi_value IsFocusRangeTypeSupported(napi_env env, napi_callback_info info);
    static napi_value GetFocusRange(napi_env env, napi_callback_info info);
    static napi_value SetFocusRange(napi_env env, napi_callback_info info);
    static napi_value IsFocusDrivenTypeSupported(napi_env env, napi_callback_info info);
    static napi_value GetFocusDriven(napi_env env, napi_callback_info info);
    static napi_value SetFocusDriven(napi_env env, napi_callback_info info);
    static napi_value GetZoomRatioRange(napi_env env, napi_callback_info info);
    static napi_value GetZoomRatio(napi_env env, napi_callback_info info);
    static napi_value SetZoomRatio(napi_env env, napi_callback_info info);
    static napi_value IsZoomCenterPointSupported(napi_env env, napi_callback_info info);
    static napi_value GetZoomCenterPoint(napi_env env, napi_callback_info info);
    static napi_value SetZoomCenterPoint(napi_env env, napi_callback_info info);
    static napi_value PrepareZoom(napi_env env, napi_callback_info info);
    static napi_value UnPrepareZoom(napi_env env, napi_callback_info info);
    static napi_value SetSmoothZoom(napi_env env, napi_callback_info info);
    static napi_value GetZoomPointInfos(napi_env env, napi_callback_info info);
    static napi_value GetSupportedFilters(napi_env env, napi_callback_info info);
    static napi_value GetFilter(napi_env env, napi_callback_info info);
    static napi_value SetFilter(napi_env env, napi_callback_info info);
    static napi_value GetSupportedBeautyTypes(napi_env env, napi_callback_info info);
    static napi_value GetSupportedBeautyRange(napi_env env, napi_callback_info info);
    static napi_value GetBeauty(napi_env env, napi_callback_info info);
    static napi_value SetBeauty(napi_env env, napi_callback_info info);
    static napi_value GetSupportedColorSpaces(napi_env env, napi_callback_info info);
    static napi_value IsControlCenterSupported(napi_env env, napi_callback_info info);
    static napi_value GetSupportedEffectTypes(napi_env env, napi_callback_info info);
    static napi_value EnableControlCenter(napi_env env, napi_callback_info info);
    static napi_value GetActiveColorSpace(napi_env env, napi_callback_info info);
    static napi_value SetColorSpace(napi_env env, napi_callback_info info);
    static napi_value IsMacroSupported(napi_env env, napi_callback_info info);
    static napi_value EnableMacro(napi_env env, napi_callback_info info);
    static napi_value CanPreconfig(napi_env env, napi_callback_info info);
    static napi_value Preconfig(napi_env env, napi_callback_info info);

    static napi_value IsMoonCaptureBoostSupported(napi_env env, napi_callback_info info);
    static napi_value EnableMoonCaptureBoost(napi_env env, napi_callback_info info);

    static napi_value GetSupportedWhiteBalanceModes(napi_env env, napi_callback_info info);
    static napi_value IsWhiteBalanceModeSupported(napi_env env, napi_callback_info info);
    static napi_value GetWhiteBalanceMode(napi_env env, napi_callback_info info);
    static napi_value SetWhiteBalanceMode(napi_env env, napi_callback_info info);

    static napi_value GetWhiteBalanceRange(napi_env env, napi_callback_info info);
    static napi_value IsManualWhiteBalanceSupported(napi_env env, napi_callback_info info);
    static napi_value GetWhiteBalance(napi_env env, napi_callback_info info);
    static napi_value SetWhiteBalance(napi_env env, napi_callback_info info);

    static napi_value BeginConfig(napi_env env, napi_callback_info info);
    static napi_value CommitConfig(napi_env env, napi_callback_info info);

    static napi_value AddInput(napi_env env, napi_callback_info info);
    static napi_value CanAddInput(napi_env env, napi_callback_info info);
    static napi_value RemoveInput(napi_env env, napi_callback_info info);

    static napi_value AddOutput(napi_env env, napi_callback_info info);
    static napi_value CanAddOutput(napi_env env, napi_callback_info info);
    static napi_value RemoveOutput(napi_env env, napi_callback_info info);

    static napi_value Start(napi_env env, napi_callback_info info);
    static napi_value Stop(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);
    static napi_value IsVideoStabilizationModeSupported(napi_env env, napi_callback_info info);
    static napi_value GetActiveVideoStabilizationMode(napi_env env, napi_callback_info info);
    static napi_value SetVideoStabilizationMode(napi_env env, napi_callback_info info);

    static napi_value LockForControl(napi_env env, napi_callback_info info);
    static napi_value UnlockForControl(napi_env env, napi_callback_info info);

    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Once(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);

    static napi_value GetCameraOutputCapabilities(napi_env env, napi_callback_info info);

    static napi_value GetSessionFunctions(napi_env env, napi_callback_info info);
    static napi_value GetSessionConflictFunctions(napi_env env, napi_callback_info info);
    const EmitterFunctions& GetEmitterFunctions() override;
    static napi_value SetUsage(napi_env env, napi_callback_info info);
    static napi_value IsAutoDeviceSwitchSupported(napi_env env, napi_callback_info info);
    static napi_value EnableAutoDeviceSwitch(napi_env env, napi_callback_info info);
    static napi_value IsCompositionSuggestionSupported(napi_env env, napi_callback_info info);
    static napi_value EnableCompositionSuggestion(napi_env env, napi_callback_info info);
    static napi_value IsCompositionEffectPreviewSupported(napi_env env, napi_callback_info info);
    static napi_value EnableCompositionEffectPreview(napi_env env, napi_callback_info info);
    static napi_value GetSupportedRecommendedInfoLanguage(napi_env env, napi_callback_info info);
    static napi_value SetRecommendedInfoLanguage(napi_env env, napi_callback_info info);
    static napi_value IsColorStyleSupported(napi_env env, napi_callback_info info);
    static napi_value GetDefaultColorStyleSettings(napi_env env, napi_callback_info info);
    static napi_value SetColorStyleSetting(napi_env env, napi_callback_info info);

    static napi_value IsImageStabilizationGuideSupported(napi_env env, napi_callback_info info);
    static napi_value EnableImageStabilizationGuide(napi_env env, napi_callback_info info);

    static napi_value IsFocusTrackingModeSupported(napi_env env, napi_callback_info info);
    static napi_value GetFocusTrackingMode(napi_env env, napi_callback_info info);
    static napi_value SetFocusTrackingMode(napi_env env, napi_callback_info info);

    static napi_value OnIsoInfoChange(napi_env env, napi_callback_info info);
    static napi_value OffIsoInfoChange(napi_env env, napi_callback_info info);

    static napi_value SetParameters(napi_env env, napi_callback_info info);
    static napi_value SetExposureMeteringMode(napi_env env, napi_callback_info info);

    static napi_value IsImagingModeSupported(napi_env env, napi_callback_info info);
    static napi_value GetActiveImagingMode(napi_env env, napi_callback_info info);
    static napi_value SetImagingMode(napi_env env, napi_callback_info info);

    napi_env env_;
    sptr<CaptureSession> cameraSession_;
    std::shared_ptr<IsoInfoCallbackListener> isoInfoCallback_ = nullptr;
    std::shared_ptr<FocusCallbackListener> focusCallback_;
    std::shared_ptr<SessionCallbackListener> sessionCallback_;
    std::shared_ptr<PressureCallbackListener> pressureCallback_;
    std::shared_ptr<ControlCenterEffectStatusCallbackListener> controlCenterEffectStatusCallback_;
    std::shared_ptr<ExposureCallbackListener> exposureCallback_;
    std::shared_ptr<MoonCaptureBoostCallbackListener> moonCaptureBoostCallback_;
    std::shared_ptr<SmoothZoomCallbackListener> smoothZoomCallback_;
    std::shared_ptr<AbilityCallbackListener> abilityCallback_;
    std::shared_ptr<AutoDeviceSwitchCallbackListener> autoDeviceSwitchCallback_;
    std::shared_ptr<CompositionPositionCalibrationCallbackListener> compositionPositionCalibrationCallback_;
    std::shared_ptr<CompositionBeginCallbackListener> compositionBeginCallback_;
    std::shared_ptr<NapiInfoCallback<CompositionEffectInfo>> compositionEffectReceiveCallback_;
    std::shared_ptr<CompositionPositionMatchCallbackListener> compositionPositionMatchCallback_;
    std::shared_ptr<CompositionEndCallbackListener> compositionEndCallback_;
    std::shared_ptr<ImageStabilizationGuideCallbackListener> imageStabilizationGuideCallback_;
    std::shared_ptr<ApertureEffectChangeCallbackListener> apertureEffectChangeCallbackListener_;
    std::shared_ptr<MacroStatusCallbackListener> macroStatusCallback_ = nullptr;
    std::shared_ptr<CameraSwitchRequestCallbackListener> cameraSwitchSessionNapiCallback_;

    static thread_local napi_ref sConstructor_;
    static thread_local sptr<CaptureSession> sCameraSession_;
    static thread_local uint32_t cameraSessionTaskId;
    static const std::vector<napi_property_descriptor> camera_output_capability_sys_props;
    static const std::vector<napi_property_descriptor> camera_ability_sys_props;
    static const std::vector<napi_property_descriptor> camera_process_props;
    static const std::vector<napi_property_descriptor> camera_process_sys_props;
    static const std::vector<napi_property_descriptor> stabilization_props;
    static const std::vector<napi_property_descriptor> flash_props;
    static const std::vector<napi_property_descriptor> flash_sys_props;
    static const std::vector<napi_property_descriptor> auto_exposure_props;
    static const std::vector<napi_property_descriptor> focus_props;
    static const std::vector<napi_property_descriptor> focus_sys_props;
    static const std::vector<napi_property_descriptor> zoom_props;
    static const std::vector<napi_property_descriptor> zoom_sys_props;
    static const std::vector<napi_property_descriptor> filter_props;
    static const std::vector<napi_property_descriptor> beauty_props;
    static const std::vector<napi_property_descriptor> macro_props;
    static const std::vector<napi_property_descriptor> moon_capture_boost_props;
    static const std::vector<napi_property_descriptor> color_management_props;
    static const std::vector<napi_property_descriptor> control_center_props;
    static const std::vector<napi_property_descriptor> preconfig_props;
    static const std::vector<napi_property_descriptor> white_balance_props;
    static const std::vector<napi_property_descriptor> auto_switch_props;
    static const std::vector<napi_property_descriptor> quality_prioritization_props;
    static const std::vector<napi_property_descriptor> composition_suggestion;
    static const std::vector<napi_property_descriptor> color_style_props;
    static const std::vector<napi_property_descriptor> image_stabilization_guide_props;
    static const std::vector<napi_property_descriptor> focus_tracking_props;
    static const std::vector<napi_property_descriptor> iso_props;
    static const std::vector<napi_property_descriptor> imaging_mode_props;

private:
    static const EmitterFunctions fun_map_;
    static void CommitConfigAsync(uv_work_t *work);
    static void StartAsync(uv_work_t *work);
    static void UvWorkAsyncCompleted(uv_work_t* work, int status);

protected:
    void RegisterExposureCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterExposureCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterFocusCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterFocusCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterMoonCaptureBoostCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterMoonCaptureBoostCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterSessionErrorCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterSessionErrorCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterSmoothZoomCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterSmoothZoomCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterAutoDeviceSwitchCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    void UnregisterAutoDeviceSwitchCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);

    virtual void RegisterIsoInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterIsoInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);
    virtual void RegisterMacroStatusCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterMacroStatusCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    virtual void RegisterFeatureDetectionStatusListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterFeatureDetectionStatusListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    virtual void RegisterEffectSuggestionCallbackListener(const std::string& eventName, napi_env env,
        napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterEffectSuggestionCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    virtual void RegisterAbilityChangeCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterAbilityChangeCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);
    virtual void RegisterLcdFlashStatusCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterLcdFlashStatusCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);
    virtual void RegisterFocusTrackingInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterFocusTrackingInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);
    virtual void RegisterPressureStatusCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterPressureStatusCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    virtual void RegisterCompositionPositionCalibrationCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterCompositionPositionCalibrationCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);
    virtual void RegisterCompositionBeginCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterCompositionBeginCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);
    virtual void RegisterCompositionEffectReceiveCallbackListener(const std::string& eventName, napi_env env,
        napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterCompositionEffectReceiveCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    virtual void RegisterCompositionPositionMatchCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterCompositionPositionMatchCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);
    virtual void RegisterCompositionEndCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterCompositionEndCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);
    virtual void RegisterImageStabilizationGuideCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterImageStabilizationGuideCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);
    virtual void RegisterControlCenterEffectStatusCallbackListener(const std::string& eventName, napi_env env,
        napi_value callback,const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterControlCenterEffectStatusCallbackListener(const std::string& eventName, napi_env env,
        napi_value callback, const std::vector<napi_value>& args);
    virtual void RegisterCameraSwitchRequestCallbackListener(const std::string &eventName, napi_env env,
        napi_value callback, const std::vector<napi_value> &args, bool isOnce);
    virtual void UnregisterCameraSwitchRequestCallbackListener(
        const std::string &eventName, napi_env env, napi_value callback, const std::vector<napi_value> &args);
    virtual void RegisterZoomInfoCbListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterZoomInfoCbListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);
    virtual void RegisterApertureEffectChangeCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterApertureEffectChangeCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);

    virtual void RegisterSlowMotionStateCb(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce) {}
    virtual void UnregisterSlowMotionStateCb(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args) {}
    virtual void RegisterExposureInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) {}
    virtual void UnregisterExposureInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) {}
    virtual void RegisterApertureInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) {}
    virtual void UnregisterApertureInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) {}
    virtual void RegisterLuminationInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) {}
    virtual void UnregisterLuminationInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) {}
    virtual void RegisterLightStatusCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) {}
    virtual void UnregisterLightStatusCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) {}
    virtual void RegisterTryAEInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) {}
    virtual void UnregisterTryAEInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) {}
    virtual void RegisterStitchingTargetInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) {}
    virtual void UnregisterStitchingTargetInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) {}
    virtual void RegisterStitchingCaptureInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) {}
    virtual void UnregisterStitchingCaptureInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) {}
    virtual void RegisterStitchingHintInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) {}
    virtual void UnregisterStitchingHintInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) {}
    virtual void RegisterStitchingCaptureStateCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) {}
    virtual void UnregisterStitchingCaptureStateCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) {}
    typedef enum {
        MATRIX = 0,
        CENTER = 1,
        SPOT = 2,
        CENTER_HIGHLIGHT_WEIGHTED = 3
    } ExposureMeteringModeofSdk;
};

struct CameraSessionAsyncContext : public AsyncContext {
    CameraSessionAsyncContext(std::string funcName, int32_t taskId) : AsyncContext(funcName, taskId) {};
    CameraSessionNapi* objectInfo = nullptr;
    std::string errorMsg;
    napi_env env = nullptr;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_SESSION_NAPI_H_ */
