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

#ifndef OHOS_CAMERA_H_SHARED_CAMERA_DEVICE_H
#define OHOS_CAMERA_H_SHARED_CAMERA_DEVICE_H

#include <string>
#include <map>
#include <atomic>
#include <refbase.h>

#include "hcamera_device.h"
#include "icamera_device_service_callback.h"

namespace OHOS {
namespace CameraStandard {

class SharedDeviceCallbackAggregator;

class HSharedCameraDevice : public HCameraDevice {
public:
    static sptr<HSharedCameraDevice> GetOrCreateSharedDevice(
        const std::string& cameraId,
        sptr<HCameraHostManager>& cameraHostManager,
        const OHOS::Security::AccessToken::AccessTokenID& callerToken);

    static sptr<HSharedCameraDevice> GetSharedDevice(const std::string& cameraId);

    HSharedCameraDevice(const std::string& cameraId,
        sptr<HCameraHostManager>& cameraHostManager,
        const OHOS::Security::AccessToken::AccessTokenID& callerToken,
        const sptr<HCameraDevice>& realDevice);

    ~HSharedCameraDevice();

    void AddRef(pid_t pid);
    void ReleaseRef(pid_t pid);

    void RegisterAppCallback(pid_t pid, const sptr<ICameraDeviceServiceCallback>& callback);
    void UnregisterAppCallback(pid_t pid);

    std::string GetCameraId() const;

    // Get the real HCameraDevice
    sptr<HCameraDevice> GetRealDevice() const;

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
    int32_t OnError(OHOS::HDI::Camera::V1_0::ErrorType type, int32_t errorMsg) override;
    int32_t OnResult(uint64_t timestamp, const std::vector<uint8_t>& result) override;
    int32_t OperatePermissionCheck(uint32_t interfaceCode) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

private:
    friend class SharedDeviceCallbackAggregator;

    static std::map<std::string, sptr<HSharedCameraDevice>> sharedDeviceMap_;
    static std::mutex sharedDeviceMutex_;

    sptr<HCameraDevice> realDevice_; // The real HCameraDevice, all interfaces delegate to it

    std::string cameraId_;
    std::map<pid_t, uint32_t> refCount_;
    std::mutex refMutex_;
    std::mutex lifecycleMutex_;
    std::map<pid_t, sptr<ICameraDeviceServiceCallback>> appCallbacks_;
    std::mutex callbackMutex_;
    sptr<ICameraDeviceServiceCallback> aggregator_;

    int32_t OnRealDeviceOpened();
    void UnregisterFromMap();
    std::atomic<bool> isOpened_{false}; // Prevent duplicate Open
};

} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_SHARED_CAMERA_DEVICE_H
