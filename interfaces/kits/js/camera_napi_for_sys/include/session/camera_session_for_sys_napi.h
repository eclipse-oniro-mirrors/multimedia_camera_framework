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

#ifndef CAMERA_SESSION_FOR_SYS_NAPI_H_
#define CAMERA_SESSION_FOR_SYS_NAPI_H_

#include "session/camera_session_napi.h"

#include "ability/camera_ability_napi.h"
#include "session/capture_session_for_sys.h"

namespace OHOS {
namespace CameraStandard {

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

class CameraSessionForSysNapi : public CameraSessionNapi {
public:
    CameraSessionForSysNapi() = default;
    ~CameraSessionForSysNapi() override;

    static void Init(napi_env env);
    static napi_value CreateCameraSession(napi_env env);
    static napi_value CameraSessionNapiForSysConstructor(napi_env env, napi_callback_info info);
    static void CameraSessionNapiForSysDestructor(napi_env env, void* nativeObject, void* finalize_hint);

    static napi_value SetUsage(napi_env env, napi_callback_info info);
    static napi_value GetCameraOutputCapabilities(napi_env env, napi_callback_info info);

    static napi_value GetSessionFunctions(napi_env env, napi_callback_info info);
    static napi_value GetSessionConflictFunctions(napi_env env, napi_callback_info info);
    static napi_value CreateFunctionsJSArray(
        napi_env env, std::vector<sptr<CameraAbility>> functionsList, FunctionsType type);

    static napi_value IsLcdFlashSupported(napi_env env, napi_callback_info info);
    static napi_value EnableLcdFlash(napi_env env, napi_callback_info info);

    static napi_value IsFocusRangeTypeSupported(napi_env env, napi_callback_info info);
    static napi_value GetFocusRange(napi_env env, napi_callback_info info);
    static napi_value SetFocusRange(napi_env env, napi_callback_info info);
    static napi_value IsFocusDrivenTypeSupported(napi_env env, napi_callback_info info);
    static napi_value GetFocusDriven(napi_env env, napi_callback_info info);
    static napi_value SetFocusDriven(napi_env env, napi_callback_info info);

    static napi_value GetFocusDistance(napi_env env, napi_callback_info info);
    static napi_value SetFocusDistance(napi_env env, napi_callback_info info);

    static napi_value PrepareZoom(napi_env env, napi_callback_info info);
    static napi_value UnPrepareZoom(napi_env env, napi_callback_info info);
    static napi_value GetZoomPointInfos(napi_env env, napi_callback_info info);

    static napi_value GetSupportedBeautyTypes(napi_env env, napi_callback_info info);
    static napi_value GetSupportedBeautyRange(napi_env env, napi_callback_info info);
    static napi_value GetBeauty(napi_env env, napi_callback_info info);
    static napi_value SetBeauty(napi_env env, napi_callback_info info);
    static napi_value GetSupportedPortraitThemeTypes(napi_env env, napi_callback_info info);
    static napi_value IsPortraitThemeSupported(napi_env env, napi_callback_info info);
    static napi_value SetPortraitThemeType(napi_env env, napi_callback_info info);

    static napi_value GetSupportedColorEffects(napi_env env, napi_callback_info info);
    static napi_value GetColorEffect(napi_env env, napi_callback_info info);
    static napi_value SetColorEffect(napi_env env, napi_callback_info info);

    static napi_value IsDepthFusionSupported(napi_env env, napi_callback_info info);
    static napi_value GetDepthFusionThreshold(napi_env env, napi_callback_info info);
    static napi_value IsDepthFusionEnabled(napi_env env, napi_callback_info info);
    static napi_value EnableDepthFusion(napi_env env, napi_callback_info info);

    static napi_value IsFeatureSupported(napi_env env, napi_callback_info info);
    static napi_value EnableFeature(napi_env env, napi_callback_info info);

    static napi_value IsEffectSuggestionSupported(napi_env env, napi_callback_info info);
    static napi_value EnableEffectSuggestion(napi_env env, napi_callback_info info);
    static napi_value GetSupportedEffectSuggestionType(napi_env env, napi_callback_info info);
    static napi_value SetEffectSuggestionStatus(napi_env env, napi_callback_info info);
    static napi_value UpdateEffectSuggestion(napi_env env, napi_callback_info info);

    static napi_value GetSupportedVirtualApertures(napi_env env, napi_callback_info info);
    static napi_value GetVirtualAperture(napi_env env, napi_callback_info info);
    static napi_value SetVirtualAperture(napi_env env, napi_callback_info info);

    static napi_value GetSupportedPhysicalApertures(napi_env env, napi_callback_info info);
    static napi_value GetPhysicalAperture(napi_env env, napi_callback_info info);
    static napi_value SetPhysicalAperture(napi_env env, napi_callback_info info);

    static napi_value GetSupportedColorReservationTypes(napi_env env, napi_callback_info info);
    static napi_value GetColorReservation(napi_env env, napi_callback_info info);
    static napi_value SetColorReservation(napi_env env, napi_callback_info info);

    sptr<CaptureSessionForSys> cameraSessionForSys_ = nullptr;
    static thread_local sptr<CaptureSessionForSys> sCameraSessionForSys_;
    static const std::map<SceneMode, FunctionsType> modeToFunctionTypeMap_;
    static const std::map<SceneMode, FunctionsType> modeToConflictFunctionTypeMap_;
    static const std::vector<napi_property_descriptor> camera_output_capability_sys_props;
    static const std::vector<napi_property_descriptor> camera_ability_sys_props;
    static const std::vector<napi_property_descriptor> camera_process_sys_props;
    static const std::vector<napi_property_descriptor> focus_sys_props;
    static const std::vector<napi_property_descriptor> flash_sys_props;
    static const std::vector<napi_property_descriptor> zoom_sys_props;
    static const std::vector<napi_property_descriptor> manual_focus_sys_props;
    static const std::vector<napi_property_descriptor> beauty_sys_props;
    static const std::vector<napi_property_descriptor> color_effect_sys_props;
    static const std::vector<napi_property_descriptor> depth_fusion_sys_props;
    static const std::vector<napi_property_descriptor> scene_detection_sys_props;
    static const std::vector<napi_property_descriptor> effect_suggestion_sys_props;
    static const std::vector<napi_property_descriptor> aperture_sys_props;
    static const std::vector<napi_property_descriptor> color_reservation_sys_props;

    std::shared_ptr<LcdFlashStatusCallbackListener> lcdFlashStatusCallback_ = nullptr;
    std::shared_ptr<EffectSuggestionCallbackListener> effectSuggestionCallback_ = nullptr;
    std::shared_ptr<FeatureDetectionStatusCallbackListener> featureDetectionStatusCallback_ = nullptr;

protected:
    void RegisterLcdFlashStatusCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterLcdFlashStatusCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
    void RegisterFocusTrackingInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterFocusTrackingInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
    void RegisterEffectSuggestionCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterEffectSuggestionCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
    void RegisterFeatureDetectionStatusListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterFeatureDetectionStatusListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args) override;

    void RegisterSlowMotionStateCb(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterSlowMotionStateCb(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
    void RegisterExposureInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterExposureInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
    void RegisterIsoInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterIsoInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
    void RegisterApertureInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterApertureInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
    void RegisterLuminationInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterLuminationInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
    void RegisterTryAEInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterTryAEInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
    void RegisterLightStatusCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterLightStatusCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* CAMERA_SESSION_FOR_SYS_NAPI_H_ */
