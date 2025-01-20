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

#ifndef CAMERA_MANAGER_IMPL_H
#define CAMERA_MANAGER_IMPL_H

#include "camera_error.h"
#include "camera_utils.h"
#include "ffi_remote_data.h"
#include "input/camera_manager.h"
#include "listener_base.h"

namespace OHOS {
namespace CameraStandard {
class CJCameraManagerCallback : public CameraManagerCallback, public ListenerBase<const CameraStatusInfo &> {
public:
    CJCameraManagerCallback() = default;
    ~CJCameraManagerCallback() = default;
    void OnCameraStatusChanged(const CameraStatusInfo &cameraStatusInfo) const override;
    void OnFlashlightStatusChanged(const std::string &cameraID, const FlashStatus flashStatus) const override;
};

class CJFoldListener : public FoldListener, public ListenerBase<const FoldStatusInfo &> {
public:
    CJFoldListener() = default;
    ~CJFoldListener() = default;
    void OnFoldStatusChanged(const FoldStatusInfo &foldStatusInfo) const override;
};

class CJTorchListener : public TorchListener, public ListenerBase<const TorchStatusInfo &> {
public:
    CJTorchListener() = default;
    ~CJTorchListener() = default;
    void OnTorchStatusChange(const TorchStatusInfo &torchStatusInfo) const override;
};

class CJCameraManager : public OHOS::FFI::FFIData {
    DECL_TYPE(CJCameraManager, OHOS::FFI::FFIData)
public:
    CJCameraManager();
    ~CJCameraManager() override;
    CArrCJCameraDevice GetSupportedCameras(int32_t *errCode);
    CArrI32 GetSupportedSceneModes(std::string cameraId, int32_t *errCode);
    sptr<CameraOutputCapability> GetSupportedOutputCapability(sptr<CameraDevice> &camera, int32_t modeType = 0);
    static bool IsCameraMuted();
    int64_t CreateCameraInputWithCameraDevice(sptr<CameraDevice> &camera, sptr<CameraInput> *pCameraInput);
    int64_t CreateCameraInputWithCameraDeviceInfo(CameraPosition position, CameraType cameraType,
                                                  sptr<CameraInput> *pCameraInput);
    static sptr<CameraStandard::CaptureSession> CreateSession(int32_t mode);
    static bool IsTorchSupported();
    static bool IsTorchModeSupported(int32_t modeType);
    static int32_t GetTorchMode();
    static int32_t SetTorchMode(int32_t modeType);
    void OnCameraStatusChanged(int64_t callbackId);
    void OffCameraStatusChanged(int64_t callbackId);
    void OffAllCameraStatusChanged();
    void OnFoldStatusChanged(int64_t callbackId);
    void OffFoldStatusChanged(int64_t callbackId);
    void OffAllFoldStatusChanged();
    void OnTorchStatusChange(int64_t callbackId);
    void OffTorchStatusChange(int64_t callbackId);
    void OffAllTorchStatusChange();

    sptr<CameraDevice> GetCameraDeviceById(std::string cameraId);

private:
    sptr<CameraManager> cameraManager_;
    std::shared_ptr<CJCameraManagerCallback> cameraManagerCallback_;
    std::shared_ptr<CJFoldListener> foldListener_;
    std::shared_ptr<CJTorchListener> torchListener_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif