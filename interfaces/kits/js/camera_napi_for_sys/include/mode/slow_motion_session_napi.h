/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef SLOW_MOTION_SESSION_NAPI_H
#define SLOW_MOTION_SESSION_NAPI_H

#include "session/camera_session_for_sys_napi.h"
#include "session/slow_motion_session.h"

namespace OHOS {
namespace CameraStandard {
static const char SLOW_MOTION_SESSION_NAPI_CLASS_NAME[] = "SlowMotionSession";

class SlowMotionStateListener : public SlowMotionStateCallback, public ListenerBase,
    public std::enable_shared_from_this<SlowMotionStateListener> {
public:
    explicit SlowMotionStateListener(napi_env env) : ListenerBase(env)
    {
        SetSlowMotionState(SlowMotionState::DEFAULT);
    }
    ~SlowMotionStateListener() = default;
    void OnSlowMotionState(const SlowMotionState state) override;
private:
    void OnSlowMotionStateCb(const SlowMotionState state) const;
    void OnSlowMotionStateCbAsync(const SlowMotionState state) const;
};

struct SlowMotionStateListenerInfo {
    SlowMotionState state_;
    weak_ptr<const SlowMotionStateListener> listener_;
    SlowMotionStateListenerInfo(SlowMotionState state, shared_ptr<const SlowMotionStateListener> listener)
        : state_(state), listener_(listener) {}
};

class SlowMotionZoomInfoListener : public ZoomInfoCallback, public ListenerBase,
    public std::enable_shared_from_this<SlowMotionZoomInfoListener> {
public:
    explicit SlowMotionZoomInfoListener(napi_env env) : ListenerBase(env) {};
    ~SlowMotionZoomInfoListener() = default;
    void OnZoomInfoChange(const std::vector<float> zoomRatioRange) override;
private:
    void OnSlowMotionZoomInfoChange(const std::vector<float> zoomRatioRange) const;
    void OnSlowMotionZoomInfoChangeAsync(const std::vector<float> zoomRatioRange) const;
};

struct SlowMotionZoomInfoListenerInfo {
    std::vector<float> zoomRatioRange_;
    weak_ptr<const SlowMotionZoomInfoListener> listener_;
    SlowMotionZoomInfoListenerInfo(std::vector<float> zoomRatioRange,
    shared_ptr<const SlowMotionZoomInfoListener> listener)
        : zoomRatioRange_(zoomRatioRange), listener_(listener) {}
};

class SlowMotionSessionNapi : public CameraSessionForSysNapi {
public:
    static void Init(napi_env env);
    static napi_value CreateCameraSession(napi_env env);
    SlowMotionSessionNapi();
    ~SlowMotionSessionNapi() override;

    static void SlowMotionSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value SlowMotionSessionNapiConstructor(napi_env env, napi_callback_info info);
    static napi_value IsSlowMotionDetectionSupported(napi_env env, napi_callback_info info);
    static napi_value SetSlowMotionDetectionArea(napi_env env, napi_callback_info info);
    napi_env env_;
    sptr<SlowMotionSession> slowMotionSession_;
    static thread_local napi_ref sConstructor_;
    std::shared_ptr<SlowMotionStateListener> slowMotionStateListener_;
    std::shared_ptr<SlowMotionZoomInfoListener> zoomInfoListener_;
private:
    static napi_value GetDoubleProperty(napi_env env, napi_value param, const std::string& propertyName,
        double& propertyValue);
    void RegisterSlowMotionStateCb(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterSlowMotionStateCb(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
    void RegisterZoomInfoCbListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterZoomInfoCbListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
};
}
}
#endif /* SLOW_MOTION_SESSION_NAPI_H */
