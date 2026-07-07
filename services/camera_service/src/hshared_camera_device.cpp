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

#include "hshared_camera_device.h"
#include "camera_log.h"
#include "camera_util.h"
#include "hcamera_device_manager.h"
#include "ipc_skeleton.h"
#include <cstdint>

namespace OHOS {
namespace CameraStandard {

// Aggregator: registered with realDevice_ as the sole callback, dispatches events to all app callbacks
class SharedDeviceCallbackAggregator : public ICameraDeviceServiceCallback {
public:
    explicit SharedDeviceCallbackAggregator(wptr<HSharedCameraDevice> device) : device_(device) {}

    int32_t OnError(const int32_t errorType, const int32_t errorMsg) override
    {
        auto device = device_.promote();
        if (device == nullptr) {
            MEDIA_ERR_LOG("SharedDeviceCallbackAggregator::OnError device expired");
            return CAMERA_INVALID_STATE;
        }
        std::lock_guard<std::mutex> lock(device->callbackMutex_);
        MEDIA_INFO_LOG("SharedDeviceCallbackAggregator::OnError fanning out to %zu callbacks",
            device->appCallbacks_.size());
        for (auto& [pid, callback] : device->appCallbacks_) {
            if (callback != nullptr) {
                callback->OnError(errorType, errorMsg);
            }
        }
        return CAMERA_OK;
    }

    int32_t OnResult(const uint64_t timestamp,
        const std::shared_ptr<OHOS::Camera::CameraMetadata>& result) override
    {
        auto device = device_.promote();
        if (device == nullptr) {
            MEDIA_ERR_LOG("SharedDeviceCallbackAggregator::OnResult device expired");
            return CAMERA_INVALID_STATE;
        }
        std::lock_guard<std::mutex> lock(device->callbackMutex_);
        for (auto& [pid, callback] : device->appCallbacks_) {
            if (callback != nullptr) {
                callback->OnResult(timestamp, result);
            }
        }
        return CAMERA_OK;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }

private:
    wptr<HSharedCameraDevice> device_;
};

std::map<std::string, sptr<HSharedCameraDevice>> HSharedCameraDevice::sharedDeviceMap_;
std::mutex HSharedCameraDevice::sharedDeviceMutex_;

sptr<HSharedCameraDevice> HSharedCameraDevice::GetOrCreateSharedDevice(
    const std::string& cameraId,
    sptr<HCameraHostManager>& cameraHostManager,
    const OHOS::Security::AccessToken::AccessTokenID& callerToken)
{
    std::lock_guard<std::mutex> lock(sharedDeviceMutex_);
    auto it = sharedDeviceMap_.find(cameraId);
    if (it != sharedDeviceMap_.end() && it->second != nullptr) {
        MEDIA_INFO_LOG("HSharedCameraDevice::GetOrCreateSharedDevice found existing, cameraId: %{public}s",
            cameraId.c_str());
        return it->second;
    }

    sptr<HCameraDevice> realDevice = new (std::nothrow) HCameraDevice(cameraHostManager, cameraId, callerToken);
    if (realDevice == nullptr) {
        MEDIA_ERR_LOG("HSharedCameraDevice::GetOrCreateSharedDevice real device allocation failed");
        return nullptr;
    }

    sptr<HSharedCameraDevice> sharedDevice = new (std::nothrow) HSharedCameraDevice(cameraId,
        cameraHostManager, callerToken, realDevice);
    if (sharedDevice != nullptr) {
        sharedDeviceMap_[cameraId] = sharedDevice;
        MEDIA_INFO_LOG("HSharedCameraDevice::GetOrCreateSharedDevice created new, cameraId: %{public}s",
            cameraId.c_str());
    }
    return sharedDevice;
}

sptr<HSharedCameraDevice> HSharedCameraDevice::GetSharedDevice(const std::string& cameraId)
{
    std::lock_guard<std::mutex> lock(sharedDeviceMutex_);
    auto it = sharedDeviceMap_.find(cameraId);
    if (it != sharedDeviceMap_.end()) {
        MEDIA_INFO_LOG("HSharedCameraDevice::GetSharedDevice found, cameraId: %{public}s", cameraId.c_str());
        return it->second;
    }
    MEDIA_INFO_LOG("HSharedCameraDevice::GetSharedDevice not found, cameraId: %{public}s", cameraId.c_str());
    return nullptr;
}

HSharedCameraDevice::HSharedCameraDevice(const std::string& cameraId,
    sptr<HCameraHostManager>& cameraHostManager,
    const OHOS::Security::AccessToken::AccessTokenID& callerToken,
    const sptr<HCameraDevice>& realDevice)
    : HCameraDevice(cameraHostManager, cameraId, callerToken), realDevice_(realDevice), cameraId_(cameraId)
{
    MEDIA_INFO_LOG("HSharedCameraDevice::Constructor cameraId: %{public}s", cameraId_.c_str());

    // Create callback aggregator and register with realDevice_, all app callbacks dispatched through it
    aggregator_ = new (std::nothrow) SharedDeviceCallbackAggregator(this);
    if (aggregator_ == nullptr) {
        MEDIA_ERR_LOG("HSharedCameraDevice::Constructor aggregator allocation failed");
        return;
    }
    if (realDevice_ != nullptr) {
        realDevice_->SetCallback(aggregator_);
        MEDIA_INFO_LOG("HSharedCameraDevice::Constructor aggregator registered with realDevice");
    }
}

HSharedCameraDevice::~HSharedCameraDevice()
{
    MEDIA_INFO_LOG("HSharedCameraDevice::Destructor cameraId: %{public}s", cameraId_.c_str());
    if (realDevice_ != nullptr) {
        realDevice_->Close();
    }

    UnregisterFromMap();
}

void HSharedCameraDevice::UnregisterFromMap()
{
    std::lock_guard<std::mutex> lock(sharedDeviceMutex_);
    if (!cameraId_.empty()) {
        sharedDeviceMap_.erase(cameraId_);
        MEDIA_INFO_LOG("HSharedCameraDevice::UnregisterFromMap cameraId: %{public}s", cameraId_.c_str());
    }
}

void HSharedCameraDevice::AddRef(pid_t pid)
{
    std::lock_guard<std::mutex> lock(refMutex_);
    refCount_[pid]++;
    MEDIA_INFO_LOG("HSharedCameraDevice::AddRef pid: %{public}d, count: %{public}u", pid, refCount_[pid]);
}

void HSharedCameraDevice::ReleaseRef(pid_t pid)
{
    bool shouldClose = false;
    {
        std::lock_guard<std::mutex> lock(refMutex_);
        auto it = refCount_.find(pid);
        if (it != refCount_.end()) {
            if (it->second > 1) {
                it->second--;
                MEDIA_INFO_LOG("HSharedCameraDevice::ReleaseRef pid: %{public}d, count: %{public}u", pid, it->second);
                return;
            }
            refCount_.erase(it);
        }
        shouldClose = refCount_.empty();
        MEDIA_INFO_LOG("HSharedCameraDevice::ReleaseRef pid: %{public}d, shouldClose: %{public}d", pid, shouldClose);
    }

    if (!shouldClose) {
        return;
    }

    std::lock_guard<std::mutex> lifecycleLock(lifecycleMutex_);
    {
        std::lock_guard<std::mutex> lock(refMutex_);
        if (!refCount_.empty()) {
            MEDIA_INFO_LOG("HSharedCameraDevice::ReleaseRef close canceled, new client joined");
            return;
        }
    }

    MEDIA_INFO_LOG("HSharedCameraDevice::ReleaseRef all clients closed, closing device");
    isOpened_.store(false);
    if (realDevice_ != nullptr) {
        realDevice_->Close();
    }
    UnregisterFromMap();
}

void HSharedCameraDevice::RegisterAppCallback(pid_t pid, const sptr<ICameraDeviceServiceCallback>& callback)
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    appCallbacks_[pid] = callback;
    MEDIA_INFO_LOG("HSharedCameraDevice::RegisterAppCallback pid: %{public}d", pid);
    // Do not register directly with realDevice_ — aggregator_ was already registered in the constructor,
    // it automatically dispatches events from realDevice_ to all appCallbacks_
}

void HSharedCameraDevice::UnregisterAppCallback(pid_t pid)
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    appCallbacks_.erase(pid);
    MEDIA_INFO_LOG("HSharedCameraDevice::UnregisterAppCallback pid: %{public}d", pid);
}

std::string HSharedCameraDevice::GetCameraId() const
{
    return cameraId_;
}

sptr<HCameraDevice> HSharedCameraDevice::GetRealDevice() const
{
    return realDevice_;
}

int32_t HSharedCameraDevice::OnRealDeviceOpened()
{
    HCameraDeviceManager::GetInstance()->RemoveDevice(cameraId_);
    HCameraDeviceManager::GetInstance()->AddDevice(IPCSkeleton::GetCallingPid(), this);
    isOpened_.store(true);
    MEDIA_INFO_LOG("HSharedCameraDevice::OnRealDeviceOpened registered shared device, cameraId: %{public}s",
        cameraId_.c_str());
    return CAMERA_OK;
}

int32_t HSharedCameraDevice::Open()
{
    std::lock_guard<std::mutex> lifecycleLock(lifecycleMutex_);
    if (isOpened_.load()) {
        MEDIA_INFO_LOG("HSharedCameraDevice::Open already opened, cameraId: %{public}s", cameraId_.c_str());
        return CAMERA_OK;
    }
    if (realDevice_ != nullptr) {
        int32_t rc = realDevice_->Open();
        if (rc == CAMERA_OK) {
            OnRealDeviceOpened();
        }
        return rc;
    }
    MEDIA_ERR_LOG("HSharedCameraDevice::Open realDevice is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::OpenSecureCamera(uint64_t& secureSeqId)
{
    std::lock_guard<std::mutex> lifecycleLock(lifecycleMutex_);
    if (isOpened_.load()) {
        MEDIA_INFO_LOG("HSharedCameraDevice::OpenSecureCamera already opened, cameraId: %{public}s", cameraId_.c_str());
        return CAMERA_OK;
    }
    if (realDevice_ != nullptr) {
        int32_t rc = realDevice_->OpenSecureCamera(secureSeqId);
        if (rc == CAMERA_OK) {
            OnRealDeviceOpened();
        }
        return rc;
    }
    MEDIA_ERR_LOG("HSharedCameraDevice::OpenSecureCamera realDevice is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::Open(int32_t concurrentType)
{
    std::lock_guard<std::mutex> lifecycleLock(lifecycleMutex_);
    if (isOpened_.load()) {
        MEDIA_INFO_LOG("HSharedCameraDevice::Open(concurrentType) already opened, "
            "cameraId: %{public}s", cameraId_.c_str());
        return CAMERA_OK;
    }
    if (realDevice_ != nullptr) {
        int32_t rc = realDevice_->Open(concurrentType);
        if (rc == CAMERA_OK) {
            OnRealDeviceOpened();
        }
        return rc;
    }
    MEDIA_ERR_LOG("HSharedCameraDevice::Open(concurrentType) realDevice is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::Open(const CallerDeviceInfo& callerInfo)
{
    std::lock_guard<std::mutex> lifecycleLock(lifecycleMutex_);
    if (isOpened_.load()) {
        MEDIA_INFO_LOG("HSharedCameraDevice::Open(callerInfo) already opened, cameraId: %{public}s", cameraId_.c_str());
        return CAMERA_OK;
    }
    if (realDevice_ != nullptr) {
        int32_t rc = realDevice_->Open(callerInfo);
        if (rc == CAMERA_OK) {
            OnRealDeviceOpened();
        }
        return rc;
    }
    MEDIA_ERR_LOG("HSharedCameraDevice::Open(callerInfo) realDevice is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::Close()
{
    std::lock_guard<std::mutex> lifecycleLock(lifecycleMutex_);
    {
        std::lock_guard<std::mutex> lock(refMutex_);
        if (!refCount_.empty()) {
            MEDIA_INFO_LOG("HSharedCameraDevice::Close skipped, refCount not empty, cameraId: %{public}s",
                cameraId_.c_str());
            return CAMERA_OK;
        }
    }

    isOpened_.store(false);
    if (realDevice_ != nullptr) {
        MEDIA_INFO_LOG("HSharedCameraDevice::Close closing real device, cameraId: %{public}s",
            cameraId_.c_str());
        return realDevice_->Close();
    }
    MEDIA_ERR_LOG("HSharedCameraDevice::Close realDevice is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::closeDelayed()
{
    if (realDevice_ != nullptr) {
        return realDevice_->closeDelayed();
    }
    MEDIA_ERR_LOG("HSharedCameraDevice::closeDelayed realDevice is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::Release()
{
    return Close();
}

int32_t HSharedCameraDevice::UpdateSetting(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    if (realDevice_ != nullptr) {
        return realDevice_->UpdateSetting(settings);
    }
    MEDIA_ERR_LOG("HSharedCameraDevice::UpdateSetting realDevice is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::SetUsedAsPosition(uint8_t value)
{
    if (realDevice_ != nullptr) {
        return realDevice_->SetUsedAsPosition(value);
    }
    MEDIA_ERR_LOG("HSharedCameraDevice::SetUsedAsPosition realDevice is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::GetStatus(const std::shared_ptr<OHOS::Camera::CameraMetadata>& metaIn,
    std::shared_ptr<OHOS::Camera::CameraMetadata>& metaOut)
{
    if (realDevice_ != nullptr) {
        return realDevice_->GetStatus(metaIn, metaOut);
    }
    MEDIA_ERR_LOG("HSharedCameraDevice::GetStatus realDevice is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::GetEnabledResults(std::vector<int32_t>& results)
{
    if (realDevice_ != nullptr) {
        return realDevice_->GetEnabledResults(results);
    }
    MEDIA_ERR_LOG("HSharedCameraDevice::GetEnabledResults realDevice is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::EnableResult(const std::vector<int32_t>& results)
{
    if (realDevice_ != nullptr) {
        return realDevice_->EnableResult(results);
    }
    MEDIA_ERR_LOG("HSharedCameraDevice::EnableResult realDevice is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::DisableResult(const std::vector<int32_t>& results)
{
    if (realDevice_ != nullptr) {
        return realDevice_->DisableResult(results);
    }
    MEDIA_ERR_LOG("HSharedCameraDevice::DisableResult realDevice is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::SetDeviceRetryTime()
{
    if (realDevice_ != nullptr) {
        return realDevice_->SetDeviceRetryTime();
    }
    MEDIA_ERR_LOG("HSharedCameraDevice::SetDeviceRetryTime realDevice is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::SetCallback(const sptr<ICameraDeviceServiceCallback>& callback)
{
    MEDIA_WARNING_LOG("HSharedCameraDevice::SetCallback ignored, use RegisterAppCallback instead");
    return CAMERA_OK;
}

int32_t HSharedCameraDevice::UnSetCallback()
{
    MEDIA_WARNING_LOG("HSharedCameraDevice::UnSetCallback ignored, aggregator stays registered");
    return CAMERA_OK;
}

int32_t HSharedCameraDevice::SetMdmCheck(bool mdmCheck)
{
    if (realDevice_ != nullptr) {
        return realDevice_->SetMdmCheck(mdmCheck);
    }
    MEDIA_ERR_LOG("HSharedCameraDevice::SetMdmCheck realDevice is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::SetCameraIdTransform(const std::string& originCameraId)
{
    if (realDevice_ != nullptr) {
        return realDevice_->SetCameraIdTransform(originCameraId);
    }
    MEDIA_ERR_LOG("HSharedCameraDevice::SetCameraIdTransform realDevice is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::SetFirstCallerTokenID(uint32_t tokenId)
{
    if (realDevice_ != nullptr) {
        return realDevice_->SetFirstCallerTokenID(tokenId);
    }
    MEDIA_ERR_LOG("HSharedCameraDevice::SetFirstCallerTokenID realDevice is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::SetUsePhysicalCameraOrientation(bool isUsed)
{
    if (realDevice_ != nullptr) {
        return realDevice_->SetUsePhysicalCameraOrientation(isUsed);
    }
    MEDIA_ERR_LOG("HSharedCameraDevice::SetUsePhysicalCameraOrientation realDevice is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::GetNaturalDirectionCorrect(bool& isNaturalDirectionCorrect)
{
    if (realDevice_ != nullptr) {
        return realDevice_->GetNaturalDirectionCorrect(isNaturalDirectionCorrect);
    }
    MEDIA_ERR_LOG("HSharedCameraDevice::GetNaturalDirectionCorrect realDevice is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::CallbackEnter([[maybe_unused]] uint32_t code)
{
    DisableJeMalloc();
    int32_t errCode = OperatePermissionCheck(code);
    CHECK_RETURN_RET_ELOG(errCode != CAMERA_OK, errCode, "HSharedCameraDevice::OperatePermissionCheck fail");
    return CAMERA_OK;
}

int32_t HSharedCameraDevice::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    if (realDevice_ != nullptr) {
        return realDevice_->CallbackExit(code, result);
    }
    MEDIA_ERR_LOG("HSharedCameraDevice::CallbackExit realDevice is null");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::OnError(OHOS::HDI::Camera::V1_0::ErrorType type, int32_t errorMsg)
{
    MEDIA_WARNING_LOG("HSharedCameraDevice::OnError ignored, use SharedDeviceCallbackAggregator instead");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::OnResult(uint64_t timestamp, const std::vector<uint8_t>& result)
{
    MEDIA_WARNING_LOG("HSharedCameraDevice::OnResult ignored, use SharedDeviceCallbackAggregator instead");
    return CAMERA_INVALID_STATE;
}

int32_t HSharedCameraDevice::OperatePermissionCheck(uint32_t interfaceCode)
{
    // Shared device allows multiple callers, only checks basic camera permission, does not verify callerToken
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t errCode = CheckPermission(OHOS_PERMISSION_CAMERA, callerToken);
    CHECK_RETURN_RET(errCode != CAMERA_OK, errCode);
    return CAMERA_OK;
}

} // namespace CameraStandard
} // namespace OHOS
