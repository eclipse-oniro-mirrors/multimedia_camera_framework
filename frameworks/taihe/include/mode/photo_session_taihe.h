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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_PHOTO_SESSION_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_PHOTO_SESSION_TAIHE_H

#include "session/camera_session_taihe.h"
#include "session/photo_session.h"

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace ohos::multimedia::camera;

class PhotoSessionImpl : public SessionImpl, public FlashImpl, public ZoomImpl, public AutoExposureImpl,
                         public ColorManagementImpl, public AutoDeviceSwitchImpl, public FocusImpl,
                         public WhiteBalanceImpl, public MacroImpl, public ManualIsoImpl, public ManualFocusImpl,
                         public ManualExposureImpl, public ApertureImpl {
public:
    explicit PhotoSessionImpl(sptr<OHOS::CameraStandard::CaptureSession> &obj) : SessionImpl(obj)
    {
        if (obj != nullptr) {
            photoSession_ = obj;
        }
    }
    ~PhotoSessionImpl() = default;
    void Preconfig(PreconfigType preconfigType, optional_view<PreconfigRatio> preconfigRatio);
    bool CanPreconfig(PreconfigType preconfigType, optional_view<PreconfigRatio> preconfigRatio);
    taihe::array<PhotoFunctions> GetSessionFunctions(CameraOutputCapability const& outputCapability);
    taihe::array<PhotoConflictFunctions> GetSessionConflictFunctions();
    inline int64_t GetSpecificImplPtr()
    {
        return reinterpret_cast<uintptr_t>(this);
    }
    sptr<OHOS::CameraStandard::CaptureSession> GetPhotoSession()
    {
        return photoSession_;
    }
    void SetIso(int32_t iso) override;
    int32_t GetIso() override;
    array<int32_t> GetSupportedIsoRange() override;
    double GetFocusDistance() override;
    void SetFocusDistance(double distance) override;
    bool IsFocusDistanceSupported() override;
    int32_t GetExposureDuration() override;
    array<int32_t> GetSupportedExposureDurationRange() override;
    double GetExposureBiasStep() override;
    void SetExposureDuration(int32_t exposure) override;
    ExposureMeteringMode GetExposureMeteringMode() override;
    void SetExposureMeteringMode(ExposureMeteringMode aeMeteringMode) override;
    bool IsExposureMeteringModeSupported(ExposureMeteringMode aeMeteringMode) override;
    array<PhysicalAperture> GetSupportedPhysicalApertures() override;
    void SetPhysicalAperture(double aperture) override;
    double GetPhysicalAperture() override;
    array<double> GetRAWCaptureZoomRatioRange() override;
protected:
    sptr<OHOS::CameraStandard::CaptureSession> photoSession_ = nullptr;
    std::shared_ptr<PressureCallbackListener> pressureCallback_ = nullptr;
    void RegisterPressureStatusCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce) override;
    void UnregisterPressureStatusCallbackListener(
        const std::string& eventName, std::shared_ptr<uintptr_t> callback) override;
    void RegisterExposureInfoCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce) override;
    void UnregisterExposureInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback) override;
    void RegisterFlashStateCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce) override;
    void UnregisterFlashStateCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback) override;
    void RegisterIsoInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback, bool isOnce) override;
    void UnregisterIsoInfoCallbackListener(const std::string& eventName,
        std::shared_ptr<uintptr_t> callback) override;
        
private:
    std::shared_ptr<ExposureInfoCallbackListener> exposureInfoCallback_ = nullptr;
    std::shared_ptr<FlashStateCallbackListener> flashStateCallback_ = nullptr;
    std::shared_ptr<IsoInfoSyncCallbackListener> isoInfoCallback_ = nullptr;
};
} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_PHOTO_SESSION_TAIHE_H