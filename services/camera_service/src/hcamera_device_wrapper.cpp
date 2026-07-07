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

#include "hcamera_device_wrapper.h"
#include "hshared_camera_device.h"
#include "camera_log.h"
#include "camera_util.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace CameraStandard {

HCameraDeviceWrapper::HCameraDeviceWrapper(
    const std::string& cameraId,
    pid_t ownerPid,
    const sptr<HCameraDevice>& device,
    bool isSharedDevice)
    : ownerPid_(ownerPid), cameraId_(cameraId), isSharedMode_(isSharedDevice), device_(nullptr)
{
    MEDIA_INFO_LOG("HCameraDeviceWrapper::Constructor cameraId: %{public}s, pid: %{public}d",
        cameraId_.c_str(), ownerPid_);

    if (device == nullptr) {
        MEDIA_ERR_LOG("HCameraDeviceWrapper::Constructor device is null");
        return;
    }

    device_ = device;
    if (isSharedMode_) {
        auto* sharedDevice = static_cast<HSharedCameraDevice*>(device_.GetRefPtr());
        if (sharedDevice != nullptr) {
            sharedDevice->AddRef(ownerPid_);
        }
        MEDIA_INFO_LOG("HCameraDeviceWrapper::Constructor using shared device");
    } else {
        MEDIA_INFO_LOG("HCameraDeviceWrapper::Constructor using independent device");
    }
}

HCameraDeviceWrapper::~HCameraDeviceWrapper()
{
    MEDIA_INFO_LOG("HCameraDeviceWrapper::Destructor pid: %{public}d, cameraId: %{public}s",
        ownerPid_, cameraId_.c_str());
    if (isSharedMode_ && device_ != nullptr) {
        HSharedCameraDevice* sharedDevice = static_cast<HSharedCameraDevice*>(device_.GetRefPtr());
        if (sharedDevice != nullptr) {
            sharedDevice->UnregisterAppCallback(ownerPid_);
            sharedDevice->ReleaseRef(ownerPid_);
        }
    }
}

std::string HCameraDeviceWrapper::GetCameraId() const
{
    return cameraId_;
}

pid_t HCameraDeviceWrapper::GetOwnerPid() const
{
    return ownerPid_;
}

sptr<HCameraDevice> HCameraDeviceWrapper::GetRealDevice() const
{
    return device_;
}

bool HCameraDeviceWrapper::IsSharedMode() const
{
    return isSharedMode_;
}

sptr<HCameraDevice> HCameraDeviceWrapper::SwitchToSharedMode(const sptr<HCameraDevice>& sharedDevice)
{
    MEDIA_INFO_LOG("HCameraDeviceWrapper::SwitchToSharedMode cameraId: %{public}s, pid: %{public}d",
        cameraId_.c_str(), ownerPid_);

    if (sharedDevice == nullptr) {
        MEDIA_ERR_LOG("HCameraDeviceWrapper::SwitchToSharedMode sharedDevice is null");
        return nullptr;
    }

    // Save reference to old independent device
    sptr<HCameraDevice> oldDevice = device_;
    device_ = sharedDevice;
    isSharedMode_ = true;

    // Add ref to shared device
    HSharedCameraDevice* sharedDev = static_cast<HSharedCameraDevice*>(sharedDevice.GetRefPtr());
    if (sharedDev != nullptr) {
        sharedDev->AddRef(ownerPid_);
        MEDIA_INFO_LOG("HCameraDeviceWrapper::SwitchToSharedMode added ref for pid: %{public}d", ownerPid_);
    }

    // Migrate already registered callback to shared device
    if (savedCallback_ != nullptr && sharedDev != nullptr) {
        MEDIA_INFO_LOG("HCameraDeviceWrapper::SwitchToSharedMode migrating callback for pid: %{public}d", ownerPid_);
        sharedDev->RegisterAppCallback(ownerPid_, savedCallback_);
    }

    // Close the old independent device
    if (oldDevice != nullptr) {
        MEDIA_INFO_LOG("HCameraDeviceWrapper::SwitchToSharedMode closing old independent device");
        oldDevice->Close();
    }

    MEDIA_INFO_LOG("HCameraDeviceWrapper::SwitchToSharedMode success");
    return device_;
}

int32_t HCameraDeviceWrapper::Open()
{
    if (device_ != nullptr) {
        return device_->Open();
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::Open device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::OpenSecureCamera(uint64_t& secureSeqId)
{
    if (device_ != nullptr) {
        return device_->OpenSecureCamera(secureSeqId);
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::OpenSecureCamera device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::Open(int32_t concurrentType)
{
    if (device_ != nullptr) {
        return device_->Open(concurrentType);
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::Open(concurrentType) device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::Open(const CallerDeviceInfo& callerInfo)
{
    if (device_ != nullptr) {
        return device_->Open(callerInfo);
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::Open(callerInfo) device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::Close()
{
    if (device_ != nullptr) {
        return device_->Close();
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::Close device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::closeDelayed()
{
    if (device_ != nullptr) {
        return device_->closeDelayed();
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::closeDelayed device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::Release()
{
    if (device_ != nullptr) {
        return device_->Release();
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::Release device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::UpdateSetting(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    if (device_ != nullptr) {
        return device_->UpdateSetting(settings);
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::UpdateSetting device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::SetUsedAsPosition(uint8_t value)
{
    if (device_ != nullptr) {
        return device_->SetUsedAsPosition(value);
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::SetUsedAsPosition device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::GetStatus(const std::shared_ptr<OHOS::Camera::CameraMetadata>& metaIn,
    std::shared_ptr<OHOS::Camera::CameraMetadata>& metaOut)
{
    if (device_ != nullptr) {
        return device_->GetStatus(metaIn, metaOut);
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::GetStatus device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::GetEnabledResults(std::vector<int32_t>& results)
{
    if (device_ != nullptr) {
        return device_->GetEnabledResults(results);
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::GetEnabledResults device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::EnableResult(const std::vector<int32_t>& results)
{
    if (device_ != nullptr) {
        return device_->EnableResult(results);
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::EnableResult device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::DisableResult(const std::vector<int32_t>& results)
{
    if (device_ != nullptr) {
        return device_->DisableResult(results);
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::DisableResult device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::SetDeviceRetryTime()
{
    if (device_ != nullptr) {
        return device_->SetDeviceRetryTime();
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::SetDeviceRetryTime device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::SetCallback(const sptr<ICameraDeviceServiceCallback>& callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    savedCallback_ = callback;
    if (isSharedMode_ && device_ != nullptr) {
        HSharedCameraDevice* sharedDevice = static_cast<HSharedCameraDevice*>(device_.GetRefPtr());
        if (sharedDevice != nullptr) {
            sharedDevice->RegisterAppCallback(ownerPid_, callback);
            return CAMERA_OK;
        }
    }
    if (device_ != nullptr) {
        return device_->SetCallback(callback);
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::SetCallback device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::UnSetCallback()
{
    std::lock_guard<std::mutex> lock(mutex_);
    savedCallback_ = nullptr;
    if (isSharedMode_ && device_ != nullptr) {
        HSharedCameraDevice* sharedDevice = static_cast<HSharedCameraDevice*>(device_.GetRefPtr());
        if (sharedDevice != nullptr) {
            sharedDevice->UnregisterAppCallback(ownerPid_);
            return CAMERA_OK;
        }
    }
    if (device_ != nullptr) {
        return device_->UnSetCallback();
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::UnSetCallback device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::SetMdmCheck(bool mdmCheck)
{
    if (device_ != nullptr) {
        return device_->SetMdmCheck(mdmCheck);
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::SetMdmCheck device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::SetCameraIdTransform(const std::string& originCameraId)
{
    if (device_ != nullptr) {
        return device_->SetCameraIdTransform(originCameraId);
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::SetCameraIdTransform device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::SetFirstCallerTokenID(uint32_t tokenId)
{
    if (device_ != nullptr) {
        return device_->SetFirstCallerTokenID(tokenId);
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::SetFirstCallerTokenID device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::SetUsePhysicalCameraOrientation(bool isUsed)
{
    if (device_ != nullptr) {
        return device_->SetUsePhysicalCameraOrientation(isUsed);
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::SetUsePhysicalCameraOrientation device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::GetNaturalDirectionCorrect(bool& isNaturalDirectionCorrect)
{
    if (device_ != nullptr) {
        return device_->GetNaturalDirectionCorrect(isNaturalDirectionCorrect);
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::GetNaturalDirectionCorrect device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::CallbackEnter([[maybe_unused]] uint32_t code)
{
    if (device_ != nullptr) {
        return device_->CallbackEnter(code);
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::CallbackEnter device is null");
    return CAMERA_INVALID_STATE;
}

int32_t HCameraDeviceWrapper::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    if (device_ != nullptr) {
        return device_->CallbackExit(code, result);
    }
    MEDIA_ERR_LOG("HCameraDeviceWrapper::CallbackExit device is null");
    return CAMERA_INVALID_STATE;
}

} // namespace CameraStandard
} // namespace OHOS
