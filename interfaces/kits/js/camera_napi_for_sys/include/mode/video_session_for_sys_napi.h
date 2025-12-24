/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef VIDEO_SESSION_FOR_SYS_NAPI_H
#define VIDEO_SESSION_FOR_SYS_NAPI_H

#include "session/camera_session_for_sys_napi.h"
#include "session/video_session_for_sys.h"
#include "zoom_info_change_callback.h"

namespace OHOS {
namespace CameraStandard {
static const char VIDEO_SESSION_FOR_SYS_NAPI_CLASS_NAME[] = "VideoSessionForSys";

class FocusTrackingCallbackListener : public FocusTrackingCallback, public ListenerBase,
    public std::enable_shared_from_this<FocusTrackingCallbackListener> {
public:
    explicit FocusTrackingCallbackListener(napi_env env) : ListenerBase(env) {}
    virtual ~FocusTrackingCallbackListener() = default;
    void OnFocusTrackingInfoAvailable(FocusTrackingInfo &focusTrackingInfo) const override;

private:
    void OnFocusTrackingInfoCallback(FocusTrackingInfo &focusTrackingInfo) const;
    void OnFocusTrackingInfoCallbackAsync(FocusTrackingInfo &focusTrackingInfo) const;
};

struct FocusTrackingCallbackInfo {
    FocusTrackingInfo focusTrackingInfo_;
    weak_ptr<const FocusTrackingCallbackListener> listener_;
    FocusTrackingCallbackInfo(FocusTrackingInfo focusTrackingInfo,
        shared_ptr<const FocusTrackingCallbackListener> listener)
        : focusTrackingInfo_(focusTrackingInfo), listener_(listener) {}
};

class LightStatusCallbackListener : public LightStatusCallback,
                                    public ListenerBase,
                                    public std::enable_shared_from_this<LightStatusCallbackListener> {
public:
    LightStatusCallbackListener(napi_env env) : ListenerBase(env)
    {}
    ~LightStatusCallbackListener() = default;
    void OnLightStatusChanged(LightStatus &status) override;

private:
    void OnLightStatusChangedCallback(LightStatus &status) const;
    void OnLightStatusChangedCallbackAsync(LightStatus &status) const;
};

struct LightStatusChangedCallback {
    LightStatus status_;
    weak_ptr<const LightStatusCallbackListener> listener_;
    LightStatusChangedCallback(LightStatus status, shared_ptr<const LightStatusCallbackListener> listener)
        : status_(status), listener_(listener)
    {}
};

class HighFrameRateZoomInfoListener : public ZoomInfoCallback, public ListenerBase,
    public std::enable_shared_from_this<HighFrameRateZoomInfoListener> {
public:
    explicit HighFrameRateZoomInfoListener(napi_env env) : ListenerBase(env) {};
    ~HighFrameRateZoomInfoListener() = default;
    void OnZoomInfoChange(const std::vector<float> zoomRatioRange) override;
private:
    void OnHighFrameRateZoomInfoChange(const std::vector<float> zoomRatioRange) const;
    void OnHighFrameRateZoomInfoChangeAsync(const std::vector<float> zoomRatioRange) const;
};

struct HighFrameRateZoomInfoListenerInfo {
    std::vector<float> zoomRatioRange_;
    weak_ptr<const HighFrameRateZoomInfoListener> listener_;
    HighFrameRateZoomInfoListenerInfo(std::vector<float> zoomRatioRange,
    shared_ptr<const HighFrameRateZoomInfoListener> listener)
        : zoomRatioRange_(zoomRatioRange), listener_(listener) {}
};

class VideoSessionForSysNapi : public CameraSessionForSysNapi  {
public:
    static void Init(napi_env env);
    static napi_value CreateCameraSession(napi_env env);
    VideoSessionForSysNapi();
    ~VideoSessionForSysNapi();

    static void VideoSessionForSysNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value VideoSessionForSysNapiConstructor(napi_env env, napi_callback_info info);

    static napi_value SetQualityPrioritization(napi_env env, napi_callback_info info);
    static napi_value IsExternalCameraLensBoostSupported(napi_env env, napi_callback_info info);
    static napi_value EnableExternalCameraLensBoost(napi_env env, napi_callback_info info);

    static const std::vector<napi_property_descriptor> video_session_sys_props;

    napi_env env_;
    sptr<VideoSessionForSys> videoSessionForSys_;
    static thread_local napi_ref sConstructor_;
    std::shared_ptr<FocusTrackingCallbackListener> focusTrackingInfoCallback_ = nullptr;
    std::shared_ptr<LightStatusCallbackListener> lightStatusCallback_ = nullptr;
    std::shared_ptr<HighFrameRateZoomInfoListener> zoomInfoListener_;

protected:
    void RegisterFocusTrackingInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterFocusTrackingInfoCallbackListener(const std::string& eventName,
        napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
    void RegisterLightStatusCallbackListener(const std::string &eventName, napi_env env, napi_value callback,
        const std::vector<napi_value> &args, bool isOnce) override;
    void UnregisterLightStatusCallbackListener(
        const std::string &eventName, napi_env env, napi_value callback, const std::vector<napi_value> &args) override;
    void RegisterZoomInfoCbListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterZoomInfoCbListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
    void RegisterPressureStatusCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterPressureStatusCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
    void RegisterCameraSwitchRequestCallbackListener(const std::string &eventName, napi_env env, napi_value callback,
        const std::vector<napi_value> &args, bool isOnce) override;
    void UnregisterCameraSwitchRequestCallbackListener(
        const std::string &eventName, napi_env env, napi_value callback, const std::vector<napi_value> &args) override;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* VIDEO_SESSION_FOR_SYS_NAPI_H */
