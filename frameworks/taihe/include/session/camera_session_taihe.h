/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_CAMERA_SESSION_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_CAMERA_SESSION_TAIHE_H

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "taihe/runtime.hpp"
#include "session/capture_session.h"
#include "camera_worker_queue_keeper_taihe.h"
#include "camera_event_emitter_taihe.h"
#include "listener_base_taihe.h"
#include "camera_query_taihe.h"

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace ohos::multimedia::camera;

class SessionCallbackListener : public OHOS::CameraStandard::SessionCallback, public ListenerBase,
    public std::enable_shared_from_this<SessionCallbackListener> {
public:
    SessionCallbackListener(ani_env* env) : ListenerBase(env) {}
    ~SessionCallbackListener() = default;
    void OnError(int32_t errorCode) override;

private:
    void OnErrorCallback(int32_t errorCode) const;
};

class FocusCallbackListener : public OHOS::CameraStandard::FocusCallback, public ListenerBase,
    public std::enable_shared_from_this<FocusCallbackListener> {
public:
    FocusCallbackListener(ani_env* env) : ListenerBase(env)
    {
        currentState = FocusState::UNFOCUSED;
    }
    ~FocusCallbackListener() = default;
    void OnFocusState(OHOS::CameraStandard::FocusCallback::FocusState state) override;

private:
    void OnFocusStateCallback(OHOS::CameraStandard::FocusCallback::FocusState state) const;
};

class SmoothZoomCallbackListener : public OHOS::CameraStandard::SmoothZoomCallback, public ListenerBase,
    public std::enable_shared_from_this<SmoothZoomCallbackListener> {
public:
    SmoothZoomCallbackListener(ani_env* env) : ListenerBase(env) {}
    ~SmoothZoomCallbackListener() = default;
    void OnSmoothZoom(int32_t duration) override;

private:
    void OnSmoothZoomCallback(int32_t duration) const;
};

class LcdFlashStatusCallbackListener : public OHOS::CameraStandard::LcdFlashStatusCallback, public ListenerBase,
    public std::enable_shared_from_this<LcdFlashStatusCallbackListener> {
public:
    LcdFlashStatusCallbackListener(ani_env* env) : ListenerBase(env) {}
    ~LcdFlashStatusCallbackListener() = default;
    void OnLcdFlashStatusChanged(OHOS::CameraStandard::LcdFlashStatusInfo lcdFlashStatusInfo) override;
private:
    void OnLcdFlashStatusCallback(OHOS::CameraStandard::LcdFlashStatusInfo lcdFlashStatusInfo) const;
};

class AutoDeviceSwitchCallbackListener : public OHOS::CameraStandard::AutoDeviceSwitchCallback, public ListenerBase,
    public std::enable_shared_from_this<AutoDeviceSwitchCallbackListener> {
public:
    AutoDeviceSwitchCallbackListener(ani_env* env) : ListenerBase(env) {}
    ~AutoDeviceSwitchCallbackListener() = default;
    void OnAutoDeviceSwitchStatusChange(bool isDeviceSwitched, bool isDeviceCapabilityChanged) const override;
private:
    void OnAutoDeviceSwitchCallback(bool isDeviceSwitched, bool isDeviceCapabilityChanged) const;
};

class FeatureDetectionStatusCallbackListener : public OHOS::CameraStandard::FeatureDetectionStatusCallback,
    public ListenerBase, public std::enable_shared_from_this<FeatureDetectionStatusCallbackListener> {
public:
    FeatureDetectionStatusCallbackListener(ani_env* env) : ListenerBase(env) {};
    ~FeatureDetectionStatusCallbackListener() = default;
    void OnFeatureDetectionStatusChanged(OHOS::CameraStandard::SceneFeature feature,
        FeatureDetectionStatus status) override;
    bool IsFeatureSubscribed(OHOS::CameraStandard::SceneFeature feature) override;

private:
    void OnFeatureDetectionStatusChangedCallback(
        OHOS::CameraStandard::SceneFeature feature, FeatureDetectionStatus status) const;
};

class MacroStatusCallbackListener : public OHOS::CameraStandard::MacroStatusCallback, public ListenerBase,
    public std::enable_shared_from_this<MacroStatusCallbackListener> {
public:
    MacroStatusCallbackListener(ani_env* env) : ListenerBase(env) {}
    ~MacroStatusCallbackListener() = default;
    void OnMacroStatusChanged(MacroStatus status) override;

private:
    void OnMacroStatusCallback(MacroStatus status) const;
};

class EffectSuggestionCallbackListener : public OHOS::CameraStandard::EffectSuggestionCallback, public ListenerBase,
    public std::enable_shared_from_this<EffectSuggestionCallbackListener> {
public:
    EffectSuggestionCallbackListener(ani_env* env) : ListenerBase(env) {}
    ~EffectSuggestionCallbackListener() = default;
    void OnEffectSuggestionChange(OHOS::CameraStandard::EffectSuggestionType effectSuggestionType) override;

private:
    void OnEffectSuggestionCallback(OHOS::CameraStandard::EffectSuggestionType effectSuggestionType) const;
};

class PressureCallbackListener : public OHOS::CameraStandard::PressureCallback, public ListenerBase,
    public std::enable_shared_from_this<PressureCallbackListener> {
public:
    PressureCallbackListener(ani_env* env) : ListenerBase(env) {}
    ~PressureCallbackListener() = default;
    void OnPressureStatusChanged(OHOS::CameraStandard::PressureStatus systemPressureLevel) override;

private:
    void OnSystemPressureLevelCallback(OHOS::CameraStandard::PressureStatus systemPressureLevel) const;
};

class SessionImpl : public CameraAniEventEmitter<SessionImpl>,
                    virtual public SessionBase {
public:
    explicit SessionImpl(sptr<OHOS::CameraStandard::CaptureSession> obj)
    {
        if (obj != nullptr) {
            captureSession_ = obj;
            isSessionBase_ = true;
        }
    }
    virtual ~SessionImpl() = default;

    void BeginConfig();
    void StartSync();
    void StopSync();
    void CommitConfigSync();
    void ReleaseSync();
    void AddInput(weak::CameraInput cameraInput);
    void RemoveInput(weak::CameraInput cameraInput);
    void AddOutput(weak::CameraOutput cameraOutput);
    void RemoveOutput(weak::CameraOutput cameraOutput);
    void SetUsage(UsageType usage, bool enabled);
    array<CameraOutputCapability> GetCameraOutputCapabilities(CameraDevice const& camera);
    bool CanAddInput(weak::CameraInput cameraInput);
    bool CanAddOutput(weak::CameraOutput cameraOutput);

    const EmitterFunctions& GetEmitterFunctions() override;

    void OnError(callback_view<void(uintptr_t)> callback);
    void OffError(optional_view<callback<void(uintptr_t)>> callback);
    void OnFocusStateChange(callback_view<void(uintptr_t, FocusState)> callback);
    void OffFocusStateChange(optional_view<callback<void(uintptr_t, FocusState)>> callback);
    void OnExposureInfoChange(callback_view<void(uintptr_t, ExposureInfo const&)> callback);
    void OffExposureInfoChange(optional_view<callback<void(uintptr_t, ExposureInfo const&)>> callback);
    void OnIsoInfoChange(callback_view<void(uintptr_t, IsoInfo const&)> callback);
    void OffIsoInfoChange(optional_view<callback<void(uintptr_t, IsoInfo const&)>> callback);
    void OnSmoothZoomInfoAvailable(callback_view<void(uintptr_t, SmoothZoomInfo const&)> callback);
    void OffSmoothZoomInfoAvailable(optional_view<callback<void(uintptr_t, SmoothZoomInfo const&)>> callback);
    void OnLcdFlashStatus(callback_view<void(uintptr_t, LcdFlashStatus const&)> callback);
    void OffLcdFlashStatus(optional_view<callback<void(uintptr_t, LcdFlashStatus const&)>> callback);
    void OnApertureInfoChange(callback_view<void(uintptr_t, ApertureInfo const&)> callback);
    void OffApertureInfoChange(optional_view<callback<void(uintptr_t, ApertureInfo const&)>> callback);
    void OnLuminationInfoChange(callback_view<void(uintptr_t, LuminationInfo const&)> callback);
    void OffLuminationInfoChange(optional_view<callback<void(uintptr_t, LuminationInfo const&)>> callback);
    void OnAutoDeviceSwitchStatusChange(callback_view<void(uintptr_t, AutoDeviceSwitchStatus const&)> callback);
    void OffAutoDeviceSwitchStatusChange(
        optional_view<callback<void(uintptr_t, AutoDeviceSwitchStatus const&)>> callback);
    void OnFeatureDetection(SceneFeatureType featureType,
        callback_view<void(uintptr_t, SceneFeatureDetectionResult const&)> callback);
    void OffFeatureDetection(SceneFeatureType featureType,
        optional_view<callback<void(uintptr_t, SceneFeatureDetectionResult const&)>> callback);
    void OnMacroStatusChanged(callback_view<void(uintptr_t, bool)> callback);
    void OffMacroStatusChanged(optional_view<callback<void(uintptr_t, bool)>> callback);
    void OnLightStatusChange(callback_view<void(uintptr_t, LightStatus)> callback);
    void OffLightStatusChange(optional_view<callback<void(uintptr_t, LightStatus)>> callback);
    void OnFocusTrackingInfoAvailable(callback_view<void(FocusTrackingInfo const&)> callback);
    void OffFocusTrackingInfoAvailable(optional_view<callback<void(FocusTrackingInfo const&)>> callback);
    void OnEffectSuggestionChange(callback_view<void(uintptr_t, EffectSuggestionType)> callback);
    void OffEffectSuggestionChange(optional_view<callback<void(uintptr_t, EffectSuggestionType)>> callback);
    void OnTryAEInfoChange(callback_view<void(uintptr_t, TryAEInfo const&)> callback);
    void OffTryAEInfoChange(optional_view<callback<void(uintptr_t, TryAEInfo const&)>> callback);
    void OnSlowMotionStatus(callback_view<void(uintptr_t, SlowMotionStatus)> callback);
    void OffSlowMotionStatus(optional_view<callback<void(uintptr_t, SlowMotionStatus)>> callback);
    void OnSystemPressureLevelChange(callback_view<void(uintptr_t, SystemPressureLevel)> callback);
    void OffSystemPressureLevelChange(optional_view<callback<void(uintptr_t, SystemPressureLevel)>> callback);

    std::shared_ptr<SessionCallbackListener> sessionCallback_ = nullptr;
    std::shared_ptr<FocusCallbackListener> focusCallback_ = nullptr;
    std::shared_ptr<SmoothZoomCallbackListener> smoothZoomCallback_ = nullptr;
    std::shared_ptr<AutoDeviceSwitchCallbackListener> autoDeviceSwitchCallback_ = nullptr;
    std::shared_ptr<LcdFlashStatusCallbackListener> lcdFlashStatusCallback_ = nullptr;
    std::shared_ptr<FeatureDetectionStatusCallbackListener> featureDetectionCallback_ = nullptr;
    std::shared_ptr<MacroStatusCallbackListener> macroStatusCallback_ = nullptr;
    std::shared_ptr<EffectSuggestionCallbackListener> effectSuggestionCallback_ = nullptr;
    
    static uint32_t cameraSessionTaskId_;
    int32_t featureType_;

private:
    void RegisterSessionErrorCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce);
    void UnregisterSessionErrorCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterFocusCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce);
    void UnregisterFocusCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterSmoothZoomCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce);
    void UnregisterSmoothZoomCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterAutoDeviceSwitchCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce);
    void UnregisterAutoDeviceSwitchCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterLcdFlashStatusCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce);
    void UnregisterLcdFlashStatusCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterFeatureDetectionStatusListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce);
    void UnregisterFeatureDetectionStatusListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterMacroStatusCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce);
    void UnregisterMacroStatusCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    void RegisterEffectSuggestionCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce);
    void UnregisterEffectSuggestionCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);

    static const EmitterFunctions fun_map_;

protected:
    virtual void RegisterIsoInfoCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce);
    virtual void UnregisterIsoInfoCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback);
    virtual void RegisterExposureInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    virtual void UnregisterExposureInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback);
    virtual void RegisterApertureInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    virtual void UnregisterApertureInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback);
    virtual void RegisterLuminationInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    virtual void UnregisterLuminationInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback);
    virtual void RegisterLightStatusCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    virtual void UnregisterLightStatusCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback);
    virtual void RegisterFocusTrackingInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    virtual void UnregisterFocusTrackingInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback);
    virtual void RegisterTryAEInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    virtual void UnregisterTryAEInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback);
    virtual void RegisterSlowMotionStateCb(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    virtual void UnregisterSlowMotionStateCb(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback);
    virtual void RegisterPressureStatusCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce);
    virtual void UnregisterPressureStatusCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback);
};

struct SessionTaiheAsyncContext : public TaiheAsyncContext {
    SessionTaiheAsyncContext(std::string funcName, int32_t taskId) : TaiheAsyncContext(funcName, taskId) {};

    ~SessionTaiheAsyncContext()
    {
        objectInfo = nullptr;
    }
    SessionImpl* objectInfo = nullptr;
};
} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_CAMERA_SESSION_TAIHE_H