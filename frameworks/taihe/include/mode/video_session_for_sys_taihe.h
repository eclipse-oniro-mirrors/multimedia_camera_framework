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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_VIDEO_SESSION_FOR_SYS_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_VIDEO_SESSION_FOR_SYS_TAIHE_H

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "session/camera_session_taihe.h"
#include "taihe/runtime.hpp"
#include "video_session_taihe.h"
#include "session/video_session_for_sys.h"

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace ohos::multimedia::camera;

class FocusTrackingCallbackListener : public OHOS::CameraStandard::FocusTrackingCallback,
                                      public ListenerBase,
                                      public std::enable_shared_from_this<FocusTrackingCallbackListener> {
public:
    explicit FocusTrackingCallbackListener(ani_env* env) : ListenerBase(env) {}
    virtual ~FocusTrackingCallbackListener() = default;
    void OnFocusTrackingInfoAvailable(OHOS::CameraStandard::FocusTrackingInfo &focusTrackingInfo) const override;

private:
    void OnFocusTrackingInfoCallback(OHOS::CameraStandard::FocusTrackingInfo &focusTrackingInfo) const;
};

class LightStatusCallbackListener : public OHOS::CameraStandard::LightStatusCallback,
                                    public ListenerBase,
                                    public std::enable_shared_from_this<LightStatusCallbackListener> {
public:
    LightStatusCallbackListener(ani_env* env) : ListenerBase(env) {}
    ~LightStatusCallbackListener() = default;
    void OnLightStatusChanged(OHOS::CameraStandard::LightStatus &status) override;

private:
    void OnLightStatusChangedCallback(OHOS::CameraStandard::LightStatus &status) const;
};

class VideoSessionForSysImpl : public VideoSessionImpl, public ColorReservationImpl, public BeautyImpl,
                               public ColorEffectImpl, public ApertureImpl, public EffectSuggestionImpl {
public:
    explicit VideoSessionForSysImpl(sptr<OHOS::CameraStandard::CaptureSession> &obj) : VideoSessionImpl(obj)
    {
        if (obj != nullptr) {
            videoSessionForSys_ = static_cast<OHOS::CameraStandard::VideoSessionForSys*>(obj.GetRefPtr());
        }
    }
    ~VideoSessionForSysImpl() = default;
    std::shared_ptr<FocusTrackingCallbackListener> focusTrackingInfoCallback_ = nullptr;
    std::shared_ptr<LightStatusCallbackListener> lightStatusCallback_ = nullptr;

protected:
    sptr<OHOS::CameraStandard::VideoSessionForSys> videoSessionForSys_ = nullptr;

    void RegisterFocusTrackingInfoCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce) override;
    void UnregisterFocusTrackingInfoCallbackListener(
        const std::string& eventName, std::shared_ptr<uintptr_t> callback) override;
    void RegisterLightStatusCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce) override;
    void UnregisterLightStatusCallbackListener(
        const std::string& eventName, std::shared_ptr<uintptr_t> callback) override;
};
} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_VIDEO_SESSION_FOR_SYS_TAIHE_H