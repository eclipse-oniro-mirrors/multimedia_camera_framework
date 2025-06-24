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

class TimeLapsePhotoSessionImpl : public SessionImpl, public FlashImpl, public ZoomImpl, public FocusImpl,
                                  public AutoExposureImpl, public WhiteBalanceImpl, public ManualExposureImpl,
                                  public ColorEffectImpl, public ManualIsoImpl, public ManualFocusImpl {
public:
    explicit TimeLapsePhotoSessionImpl(sptr<OHOS::CameraStandard::CaptureSession> &obj) : SessionImpl(obj)
    {
        if (obj != nullptr) {
            timeLapsePhotoSession_ = static_cast<OHOS::CameraStandard::TimeLapsePhotoSession*>(obj.GetRefPtr());
        }
    }
    ~TimeLapsePhotoSessionImpl() = default;

    void SetTimeLapsePreviewType(ohos::multimedia::camera::TimeLapsePreviewType type);
    void SetTimeLapseInterval(int32_t interval);
    int32_t GetTimeLapseInterval();
    void SetTimeLapseRecordState(ohos::multimedia::camera::TimeLapseRecordState state);
    array<int32_t> GetSupportedTimeLapseIntervalRange();
    void StartTryAE();
    void StopTryAE();
    bool IsTryAENeeded();
    void SetIso(int32_t iso) override;
    int32_t GetIso() override;
    int32_t GetExposure() override;
    void SetExposure(int32_t exposure) override;
    array<int32_t> GetIsoRange() override;
    bool IsManualIsoSupported() override;
    bool IsWhiteBalanceModeSupported(WhiteBalanceMode mode) override;
    void SetWhiteBalance(int32_t whiteBalance) override;
    int32_t GetWhiteBalance() override;
    void SetWhiteBalanceMode(WhiteBalanceMode mode) override;
    WhiteBalanceMode GetWhiteBalanceMode() override;
    ExposureMeteringMode GetExposureMeteringMode() override;
    void SetExposureMeteringMode(ExposureMeteringMode aeMeteringMode) override;
    bool IsExposureMeteringModeSupported(ExposureMeteringMode aeMeteringMode) override;
    array<int32_t> GetSupportedExposureRange() override;
    array<int32_t> GetWhiteBalanceRange() override;

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