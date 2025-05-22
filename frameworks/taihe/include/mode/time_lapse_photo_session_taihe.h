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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_TIME_LAPSE_PHOTO_SESSION_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_TIME_LAPSE_PHOTO_SESSION_TAIHE_H

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "session/camera_session_taihe.h"
#include "session/time_lapse_photo_session.h"
#include "session/profession_session.h"
#include "taihe/runtime.hpp"

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace ohos::multimedia::camera;

class IsoInfoCallbackListenerTime : public OHOS::CameraStandard::IsoInfoCallback, public ListenerBase,
    public std::enable_shared_from_this<IsoInfoCallbackListenerTime> {
public:
    IsoInfoCallbackListenerTime(ani_env* env) : ListenerBase(env) {}
    ~IsoInfoCallbackListenerTime() = default;
    void OnIsoInfoChanged(OHOS::CameraStandard::IsoInfo info) override;
private:
    void OnIsoInfoChangedCallback(OHOS::CameraStandard::IsoInfo info) const;
};

class ExposureInfoCallbackListenerTime : public OHOS::CameraStandard::ExposureInfoCallback, public ListenerBase,
    public std::enable_shared_from_this<ExposureInfoCallbackListenerTime> {
public:
    ExposureInfoCallbackListenerTime(ani_env* env) : ListenerBase(env) {}
    ~ExposureInfoCallbackListenerTime() = default;
    void OnExposureInfoChanged(OHOS::CameraStandard::ExposureInfo info) override;
    
private:
    void OnExposureInfoChangedCallback(OHOS::CameraStandard::ExposureInfo info) const;
};

class LuminationInfoCallbackListenerTime : public OHOS::CameraStandard::LuminationInfoCallback, public ListenerBase,
    public std::enable_shared_from_this<LuminationInfoCallbackListenerTime> {
public:
    LuminationInfoCallbackListenerTime(ani_env* env) : ListenerBase(env) {}
    ~LuminationInfoCallbackListenerTime() = default;
    void OnLuminationInfoChanged(OHOS::CameraStandard::LuminationInfo info) override;
    
private:
    void OnLuminationInfoChangedCallback(OHOS::CameraStandard::LuminationInfo info) const;
};

class TryAEInfoCallbackListener : public OHOS::CameraStandard::TryAEInfoCallback, public ListenerBase,
    public std::enable_shared_from_this<TryAEInfoCallbackListener> {
public:
    TryAEInfoCallbackListener(ani_env* env) : ListenerBase(env) {}
    ~TryAEInfoCallbackListener() = default;
    void OnTryAEInfoChanged(OHOS::CameraStandard::TryAEInfo info) override;
    
private:
    void OnTryAEInfoChangedCallback(OHOS::CameraStandard::TryAEInfo info) const;
};

class TimeLapsePhotoSessionImpl : public SessionImpl, public FlashQueryImpl, public ZoomQueryImpl {
public:
    explicit TimeLapsePhotoSessionImpl(sptr<OHOS::CameraStandard::CaptureSession> &obj) : SessionImpl(obj),
        FlashQueryImpl(obj), ZoomQueryImpl(obj)
    {
        if (obj != nullptr) {
            timeLapsePhotoSession_ = static_cast<OHOS::CameraStandard::TimeLapsePhotoSession*>(obj.GetRefPtr());
        }
    }
    ~TimeLapsePhotoSessionImpl() = default;
private:
    sptr<OHOS::CameraStandard::TimeLapsePhotoSession> timeLapsePhotoSession_ = nullptr;

    std::shared_ptr<IsoInfoCallbackListenerTime> isoInfoCallback_ = nullptr;
    std::shared_ptr<LuminationInfoCallbackListenerTime> luminationInfoCallback_ = nullptr;
    std::shared_ptr<ExposureInfoCallbackListenerTime> exposureInfoCallback_ = nullptr;
    std::shared_ptr<TryAEInfoCallbackListener> tryAEInfoCallback_ = nullptr;

protected:
    void RegisterIsoInfoCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce) override;
    void UnregisterIsoInfoCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback) override;

    void RegisterLuminationInfoCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce) override;
    void UnregisterLuminationInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback) override;

    void RegisterExposureInfoCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce) override;
    void UnregisterExposureInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback) override;
    
    void RegisterTryAEInfoCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce) override;
    void UnregisterTryAEInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback) override;
};
} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_TIME_LAPSE_PHOTO_SESSION_TAIHE_H