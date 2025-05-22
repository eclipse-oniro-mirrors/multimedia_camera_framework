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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_PROFESSIONAL_SESSION_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_PROFESSIONAL_SESSION_TAIHE_H

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "session/camera_session_taihe.h"
#include "session/profession_session.h"
#include "taihe/runtime.hpp"

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace ohos::multimedia::camera;

class IsoInfoCallbackListener : public OHOS::CameraStandard::IsoInfoCallback, public ListenerBase,
    public std::enable_shared_from_this<IsoInfoCallbackListener> {
public:
    IsoInfoCallbackListener(ani_env* env) : ListenerBase(env) {}
    ~IsoInfoCallbackListener() = default;
    void OnIsoInfoChanged(OHOS::CameraStandard::IsoInfo info) override;

private:
    void OnIsoInfoChangedCallback(OHOS::CameraStandard::IsoInfo info) const;
};

class ExposureInfoCallbackListener : public OHOS::CameraStandard::ExposureInfoCallback, public ListenerBase,
    public std::enable_shared_from_this<ExposureInfoCallbackListener> {
public:
    ExposureInfoCallbackListener(ani_env* env) : ListenerBase(env) {}
    ~ExposureInfoCallbackListener() = default;
    void OnExposureInfoChanged(OHOS::CameraStandard::ExposureInfo info) override;

private:
    void OnExposureInfoChangedCallback(OHOS::CameraStandard::ExposureInfo info) const;
};

class ApertureInfoCallbackListener : public OHOS::CameraStandard::ApertureInfoCallback, public ListenerBase,
    public std::enable_shared_from_this<ApertureInfoCallbackListener> {
public:
    ApertureInfoCallbackListener(ani_env* env) : ListenerBase(env) {}
    ~ApertureInfoCallbackListener() = default;
    void OnApertureInfoChanged(OHOS::CameraStandard::ApertureInfo info) override;

private:
    void OnApertureInfoChangedCallback(OHOS::CameraStandard::ApertureInfo info) const;
};

class LuminationInfoCallbackListener : public OHOS::CameraStandard::LuminationInfoCallback, public ListenerBase,
    public std::enable_shared_from_this<LuminationInfoCallbackListener> {
public:
    LuminationInfoCallbackListener(ani_env* env) : ListenerBase(env) {}
    ~LuminationInfoCallbackListener() = default;
    void OnLuminationInfoChanged(OHOS::CameraStandard::LuminationInfo info) override;

private:
    void OnLuminationInfoChangedCallback(OHOS::CameraStandard::LuminationInfo info) const;
};

class ProfessionalSessionImpl : public SessionImpl, public FlashQueryImpl, public ZoomQueryImpl {
public:
    explicit ProfessionalSessionImpl(sptr<OHOS::CameraStandard::CaptureSession> &obj) : SessionImpl(obj),
        FlashQueryImpl(obj), ZoomQueryImpl(obj)
    {
        if (obj != nullptr) {
            professionSession_ = static_cast<OHOS::CameraStandard::ProfessionSession*>(obj.GetRefPtr());
        }
    }
    virtual ~ProfessionalSessionImpl() = default;
private:
    sptr<OHOS::CameraStandard::ProfessionSession> professionSession_ = nullptr;

    std::shared_ptr<IsoInfoCallbackListener> isoInfoCallback_ = nullptr;
    std::shared_ptr<ExposureInfoCallbackListener> exposureInfoCallback_ = nullptr;
    std::shared_ptr<ApertureInfoCallbackListener> apertureInfoCallback_ = nullptr;
    std::shared_ptr<LuminationInfoCallbackListener> luminationInfoCallback_ = nullptr;

protected:
    void RegisterIsoInfoCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce) override;
    void UnregisterIsoInfoCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback) override;
    void RegisterExposureInfoCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce) override;
    void UnregisterExposureInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback) override;
    void RegisterApertureInfoCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce) override;
    void UnregisterApertureInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback) override;
    void RegisterLuminationInfoCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce) override;
    void UnregisterLuminationInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback) override;
};
} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_PROFESSIONAL_SESSION_TAIHE_H