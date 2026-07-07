/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_H_CAMERA_DEVICE_WRAPPER_H
#define OHOS_CAMERA_H_CAMERA_DEVICE_WRAPPER_H

#include <string>
#include <mutex>
#include <refbase.h>

#include "hcamera_device.h"
#include "camera_device_service_stub.h"

namespace OHOS {
namespace CameraStandard {

class HCameraDeviceWrapper : public CameraDeviceServiceStub {
public:
    explicit HCameraDeviceWrapper(
        const std::string& cameraId,
        pid_t ownerPid,
        const sptr<HCameraDevice>& device,
        bool isSharedDevice);

    ~HCameraDeviceWrapper();

    std::string GetCameraId() const;

    pid_t GetOwnerPid() const;

    sptr<HCameraDevice> GetRealDevice() const;

    bool IsSharedMode() const;

    sptr<HCameraDevice> SwitchToSharedMode(const sptr<HCameraDevice>& sharedDevice);

    int32_t Open() override;
    int32_t OpenSecureCamera(uint64_t& secureSeqId) override;
    int32_t Open(int32_t concurrentType) override;
    int32_t Open(const CallerDeviceInfo& callerInfo) override;
    int32_t Close() override;
    int32_t closeDelayed() override;
    int32_t Release() override;
    int32_t UpdateSetting(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings) override;
    int32_t SetUsedAsPosition(uint8_t value) override;
    int32_t GetStatus(const std::shared_ptr<OHOS::Camera::CameraMetadata>& metaIn,
            std::shared_ptr<OHOS::Camera::CameraMetadata>& metaOut) override;
    int32_t GetEnabledResults(std::vector<int32_t>& results) override;
    int32_t EnableResult(const std::vector<int32_t>& results) override;
    int32_t DisableResult(const std::vector<int32_t>& results) override;
    int32_t SetDeviceRetryTime() override;
    int32_t SetCallback(const sptr<ICameraDeviceServiceCallback>& callback) override;
    int32_t UnSetCallback() override;
    int32_t SetMdmCheck(bool mdmCheck) override;
    int32_t SetCameraIdTransform(const std::string& originCameraId) override;
    int32_t SetFirstCallerTokenID(uint32_t tokenId) override;
    int32_t SetUsePhysicalCameraOrientation(bool isUsed) override;
    int32_t GetNaturalDirectionCorrect(bool& isNaturalDirectionCorrect) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

private:
    pid_t ownerPid_;
    std::string cameraId_;
    bool isSharedMode_;
    sptr<HCameraDevice> device_; // shared mode: HSharedCameraDevice; independent mode: HCameraDevice
    sptr<ICameraDeviceServiceCallback> savedCallback_; // cache callback, used for SwitchToSharedMode migration
    std::mutex mutex_; // protect device_ / isSharedMode_ / savedCallback_ concurrent access
};

} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAMERA_DEVICE_WRAPPER_H
