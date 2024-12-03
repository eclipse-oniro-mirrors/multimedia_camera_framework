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

#ifndef CAMERA_SESSION_NAPI_H_
#define CAMERA_SESSION_NAPI_H_

#include <memory>
#include <mutex>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>

#include "ability/camera_ability_napi.h"
#include "camera_napi_utils.h"
#include "capture_scene_const.h"
#include "input/camera_device.h"
#include "input/camera_input_napi.h"
#include "input/camera_manager.h"
#include "listener_base.h"
#include "output/depth_data_output_napi.h"
#include "output/metadata_output_napi.h"
#include "output/preview_output_napi.h"
#include "output/video_output_napi.h"
#include "session/capture_session.h"

namespace OHOS {
namespace CameraStandard {
static const char CAMERA_SESSION_NAPI_CLASS_NAME[] = "CaptureSession";

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

class FeatureDetectionStatusCallbackListener : public FeatureDetectionStatusCallback, public ListenerBase,
    public std::enable_shared_from_this<FeatureDetectionStatusCallbackListener> {
public:
    FeatureDetectionStatusCallbackListener(napi_env env) : ListenerBase(env) {};
    ~FeatureDetectionStatusCallbackListener() = default;
    void OnFeatureDetectionStatusChanged(SceneFeature feature, FeatureDetectionStatus status) override;
    bool IsFeatureSubscribed(SceneFeature feature) override;

private:
    void OnFeatureDetectionStatusChangedCallback(SceneFeature feature, FeatureDetectionStatus status) const;
    void OnFeatureDetectionStatusChangedCallbackAsync(SceneFeature feature, FeatureDetectionStatus status) const;
};

struct FeatureDetectionStatusCallbackInfo {
    SceneFeature feature_;
    FeatureDetectionStatusCallback::FeatureDetectionStatus status_;
    weak_ptr<const FeatureDetectionStatusCallbackListener> listener_;
    FeatureDetectionStatusCallbackInfo(SceneFeature feature,
        FeatureDetectionStatusCallback::FeatureDetectionStatus status,
        shared_ptr<const FeatureDetectionStatusCallbackListener> listener)
        : feature_(feature), status_(status), listener_(listener)
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

struct SessionCallbackInfo {
    int32_t errorCode_;
    weak_ptr<const SessionCallbackListener> listener_;
    SessionCallbackInfo(int32_t errorCode, shared_ptr<const SessionCallbackListener> listener)
        : errorCode_(errorCode), listener_(listener) {}
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

class EffectSuggestionCallbackListener : public EffectSuggestionCallback, public ListenerBase,
    public std::enable_shared_from_this<EffectSuggestionCallbackListener> {
public:
    EffectSuggestionCallbackListener(napi_env env) : ListenerBase(env) {}
    ~EffectSuggestionCallbackListener() = default;
    void OnEffectSuggestionChange(EffectSuggestionType effectSuggestionType) override;

private:
    void OnEffectSuggestionCallback(EffectSuggestionType effectSuggestionType) const;
    void OnEffectSuggestionCallbackAsync(EffectSuggestionType effectSuggestionType) const;
};

struct EffectSuggestionCallbackInfo {
    EffectSuggestionType effectSuggestionType_;
    weak_ptr<const EffectSuggestionCallbackListener> listener_;
    EffectSuggestionCallbackInfo(EffectSuggestionType effectSuggestionType,
    shared_ptr<const EffectSuggestionCallbackListener> listener)
        : effectSuggestionType_(effectSuggestionType), listener_(listener) {}
};

class LcdFlashStatusCallbackListener : public LcdFlashStatusCallback, public ListenerBase,
    public std::enable_shared_from_this<LcdFlashStatusCallbackListener> {
public:
    LcdFlashStatusCallbackListener(napi_env env) : ListenerBase(env) {}
    ~LcdFlashStatusCallbackListener() = default;
    void OnLcdFlashStatusChanged(LcdFlashStatusInfo lcdFlashStatusInfo) override;

private:
    void OnLcdFlashStatusCallback(LcdFlashStatusInfo lcdFlashStatusInfo) const;
    void OnLcdFlashStatusCallbackAsync(LcdFlashStatusInfo lcdFlashStatusInfo) const;
};

struct LcdFlashStatusStatusCallbackInfo {
    LcdFlashStatusInfo lcdFlashStatusInfo_;
    weak_ptr<const LcdFlashStatusCallbackListener> listener_;
    LcdFlashStatusStatusCallbackInfo(LcdFlashStatusInfo lcdFlashStatusInfo,
    shared_ptr<const LcdFlashStatusCallbackListener> listener)
        : lcdFlashStatusInfo_(lcdFlashStatusInfo), listener_(listener) {}
};

class AutoDeviceSwitchCallbackListener : public AutoDeviceSwitchCallback, public ListenerBase,
    public std::enable_shared_from_this<AutoDeviceSwitchCallbackListener> {
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
    weak_ptr<const AutoDeviceSwitchCallbackListener> listener_;
    AutoDeviceSwitchCallbackListenerInfo(bool isDeviceSwitched, bool isDeviceCapabilityChanged,
        shared_ptr<const AutoDeviceSwitchCallbackListener> listener)
        : isDeviceSwitched_(isDeviceSwitched), isDeviceCapabilityChanged_(isDeviceCapabilityChanged),
        listener_(listener) {}
};

class CameraSessionNapi : public CameraNapiEventEmitter<CameraSessionNapi> {
public:
    static napi_value Init(napi_env env, napi_value exports);
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
    static napi_value SetFocusPoint(napi_env env, napi_callback_info info);
    static napi_value GetFocusPoint(napi_env env, napi_callback_info info);
    static napi_value GetFocalLength(napi_env env, napi_callback_info info);
    static napi_value GetZoomRatioRange(napi_env env, napi_callback_info info);
    static napi_value GetZoomRatio(napi_env env, napi_callback_info info);
    static napi_value SetZoomRatio(napi_env env, napi_callback_info info);
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
    static napi_value GetSupportedPortraitThemeTypes(napi_env env, napi_callback_info info);
    static napi_value IsPortraitThemeSupported(napi_env env, napi_callback_info info);
    static napi_value SetPortraitThemeType(napi_env env, napi_callback_info info);
    static napi_value GetSupportedColorSpaces(napi_env env, napi_callback_info info);
    static napi_value GetActiveColorSpace(napi_env env, napi_callback_info info);
    static napi_value SetColorSpace(napi_env env, napi_callback_info info);
    static napi_value GetSupportedColorEffects(napi_env env, napi_callback_info info);
    static napi_value GetColorEffect(napi_env env, napi_callback_info info);
    static napi_value SetColorEffect(napi_env env, napi_callback_info info);
    static napi_value GetFocusDistance(napi_env env, napi_callback_info info);
    static napi_value SetFocusDistance(napi_env env, napi_callback_info info);
    static napi_value IsMacroSupported(napi_env env, napi_callback_info info);
    static napi_value EnableMacro(napi_env env, napi_callback_info info);
    static napi_value IsDepthFusionSupported(napi_env env, napi_callback_info info);
    static napi_value GetDepthFusionThreshold(napi_env env, napi_callback_info info);
    static napi_value IsDepthFusionEnabled(napi_env env, napi_callback_info info);
    static napi_value EnableDepthFusion(napi_env env, napi_callback_info info);
    static napi_value CanPreconfig(napi_env env, napi_callback_info info);
    static napi_value Preconfig(napi_env env, napi_callback_info info);
    static napi_value IsEffectSuggestionSupported(napi_env env, napi_callback_info info);
    static napi_value EnableEffectSuggestion(napi_env env, napi_callback_info info);
    static napi_value GetSupportedEffectSuggestionType(napi_env env, napi_callback_info info);
    static napi_value SetEffectSuggestionStatus(napi_env env, napi_callback_info info);
    static napi_value UpdateEffectSuggestion(napi_env env, napi_callback_info info);

    static napi_value IsMoonCaptureBoostSupported(napi_env env, napi_callback_info info);
    static napi_value EnableMoonCaptureBoost(napi_env env, napi_callback_info info);

    static napi_value IsFeatureSupported(napi_env env, napi_callback_info info);
    static napi_value EnableFeature(napi_env env, napi_callback_info info);

    static napi_value GetSupportedWhiteBalanceModes(napi_env env, napi_callback_info info);
    static napi_value IsWhiteBalanceModeSupported(napi_env env, napi_callback_info info);
    static napi_value GetWhiteBalanceMode(napi_env env, napi_callback_info info);
    static napi_value SetWhiteBalanceMode(napi_env env, napi_callback_info info);

    static napi_value GetManualWhiteBalanceRange(napi_env env, napi_callback_info info);
    static napi_value IsManualWhiteBalanceSupported(napi_env env, napi_callback_info info);
    static napi_value GetManualWhiteBalance(napi_env env, napi_callback_info info);
    static napi_value SetManualWhiteBalance(napi_env env, napi_callback_info info);

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

    static napi_value GetSupportedVirtualApertures(napi_env env, napi_callback_info info);
    static napi_value GetVirtualAperture(napi_env env, napi_callback_info info);
    static napi_value SetVirtualAperture(napi_env env, napi_callback_info info);

    static napi_value GetSupportedPhysicalApertures(napi_env env, napi_callback_info info);
    static napi_value GetPhysicalAperture(napi_env env, napi_callback_info info);
    static napi_value SetPhysicalAperture(napi_env env, napi_callback_info info);

    static napi_value LockForControl(napi_env env, napi_callback_info info);
    static napi_value UnlockForControl(napi_env env, napi_callback_info info);

    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Once(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);

    static napi_value GetCameraOutputCapabilities(napi_env env, napi_callback_info info);

    static napi_value GetSessionFunctions(napi_env env, napi_callback_info info);
    static napi_value GetSessionConflictFunctions(napi_env env, napi_callback_info info);
    static napi_value CreateFunctionsJSArray(
        napi_env env, std::vector<sptr<CameraAbility>> functionsList, FunctionsType type);
    const EmitterFunctions& GetEmitterFunctions() override;
    static napi_value SetUsage(napi_env env, napi_callback_info info);
    static napi_value IsAutoDeviceSwitchSupported(napi_env env, napi_callback_info info);
    static napi_value EnableAutoDeviceSwitch(napi_env env, napi_callback_info info);

    napi_env env_;
    sptr<CaptureSession> cameraSession_;
    std::shared_ptr<FocusCallbackListener> focusCallback_;
    std::shared_ptr<SessionCallbackListener> sessionCallback_;
    std::shared_ptr<ExposureCallbackListener> exposureCallback_;
    std::shared_ptr<MacroStatusCallbackListener> macroStatusCallback_;
    std::shared_ptr<MoonCaptureBoostCallbackListener> moonCaptureBoostCallback_;
    std::shared_ptr<FeatureDetectionStatusCallbackListener> featureDetectionStatusCallback_;
    std::shared_ptr<SmoothZoomCallbackListener> smoothZoomCallback_;
    std::shared_ptr<AbilityCallbackListener> abilityCallback_;
    std::shared_ptr<EffectSuggestionCallbackListener> effectSuggestionCallback_;
    std::shared_ptr<LcdFlashStatusCallbackListener> lcdFlashStatusCallback_;
    std::shared_ptr<AutoDeviceSwitchCallbackListener> autoDeviceSwitchCallback_;

    static thread_local napi_ref sConstructor_;
    static thread_local sptr<CaptureSession> sCameraSession_;
    static thread_local uint32_t cameraSessionTaskId;
    static const std::map<SceneMode, FunctionsType> modeToFunctionTypeMap_;
    static const std::map<SceneMode, FunctionsType> modeToConflictFunctionTypeMap_;
    static const std::vector<napi_property_descriptor> camera_output_capability_props;
    static const std::vector<napi_property_descriptor> camera_ability_props;
    static const std::vector<napi_property_descriptor> camera_process_props;
    static const std::vector<napi_property_descriptor> stabilization_props;
    static const std::vector<napi_property_descriptor> flash_props;
    static const std::vector<napi_property_descriptor> auto_exposure_props;
    static const std::vector<napi_property_descriptor> focus_props;
    static const std::vector<napi_property_descriptor> manual_focus_props;
    static const std::vector<napi_property_descriptor> zoom_props;
    static const std::vector<napi_property_descriptor> filter_props;
    static const std::vector<napi_property_descriptor> beauty_props;
    static const std::vector<napi_property_descriptor> color_effect_props;
    static const std::vector<napi_property_descriptor> macro_props;
    static const std::vector<napi_property_descriptor> depth_fusion_props;
    static const std::vector<napi_property_descriptor> moon_capture_boost_props;
    static const std::vector<napi_property_descriptor> features_props;
    static const std::vector<napi_property_descriptor> color_management_props;
    static const std::vector<napi_property_descriptor> preconfig_props;
    static const std::vector<napi_property_descriptor> effect_suggestion_props;
    static const std::vector<napi_property_descriptor> aperture_props;
    static const std::vector<napi_property_descriptor> auto_wb_props;
    static const std::vector<napi_property_descriptor> manual_wb_props;
    static const std::vector<napi_property_descriptor> auto_switch_props;

protected:
    virtual void RegisterSlowMotionStateCb(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterSlowMotionStateCb(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);

private:
    void RegisterExposureCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterExposureCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterFocusCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterFocusCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterMacroStatusCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterMacroStatusCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterMoonCaptureBoostCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterMoonCaptureBoostCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterFeatureDetectionStatusListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterFeatureDetectionStatusListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterSessionErrorCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterSessionErrorCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterSmoothZoomCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterSmoothZoomCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);
    void RegisterEffectSuggestionCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce);
    void UnregisterEffectSuggestionCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args);

    static const EmitterFunctions fun_map_;
protected:
    virtual void RegisterExposureInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterExposureInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);

    virtual void RegisterAbilityChangeCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterAbilityChangeCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);

    virtual void RegisterIsoInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterIsoInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);

    virtual void RegisterApertureInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterApertureInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);

    virtual void RegisterLuminationInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterLuminationInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);

    virtual void RegisterTryAEInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterTryAEInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);

    virtual void RegisterLcdFlashStatusCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterLcdFlashStatusCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);
    virtual void RegisterAutoDeviceSwitchCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce);
    virtual void UnregisterAutoDeviceSwitchCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args);
};

struct CameraSessionAsyncContext : public AsyncContext {
    CameraSessionAsyncContext(std::string funcName, int32_t taskId) : AsyncContext(funcName, taskId) {};
    CameraSessionNapi* objectInfo = nullptr;
    std::string errorMsg;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_SESSION_NAPI_H_ */
