/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "hcamera_device.h"

#include "camera_util.h"
#include "camera_log.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"

namespace OHOS {
namespace CameraStandard {
HCameraDevice::HCameraDevice(sptr<HCameraHostManager> &cameraHostManager,
                             std::string cameraID,
                             const uint32_t callingTokenId)
{
    cameraHostManager_ = cameraHostManager;
    cameraID_ = cameraID;
    streamOperator_ = nullptr;
    isReleaseCameraDevice_ = false;
    isOpenedCameraDevice_ = false;
    callerToken_ = callingTokenId;
}

HCameraDevice::~HCameraDevice()
{
    hdiCameraDevice_ = nullptr;
    streamOperator_ = nullptr;
    if (cameraHostManager_) {
        cameraHostManager_ = nullptr;
    }
    deviceHDICallback_ = nullptr;
    deviceSvcCallback_ = nullptr;
}

std::string HCameraDevice::GetCameraId()
{
    return cameraID_;
}

int32_t HCameraDevice::SetReleaseCameraDevice(bool isRelease)
{
    isReleaseCameraDevice_ = isRelease;
    return CAMERA_OK;
}

bool HCameraDevice::IsReleaseCameraDevice()
{
    return isReleaseCameraDevice_;
}

bool HCameraDevice::IsOpenedCameraDevice()
{
    return isOpenedCameraDevice_;
}

std::shared_ptr<OHOS::Camera::CameraMetadata> HCameraDevice::GetSettings()
{
    int32_t errCode;
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability = nullptr;
    errCode = cameraHostManager_->GetCameraAbility(cameraID_, ability);
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraDevice::GetSettings Failed to get Camera Ability: %{public}d", errCode);
        return nullptr;
    }

    if (!videoFrameRateRange_.empty() && ability != nullptr) {
        bool status = false;
        camera_metadata_item_t item;
        int ret = OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_CONTROL_FPS_RANGES, &item);
        if (ret == CAM_META_ITEM_NOT_FOUND) {
            status = ability->addEntry(OHOS_CONTROL_FPS_RANGES,
                videoFrameRateRange_.data(), videoFrameRateRange_.size());
        } else if (ret == CAM_META_SUCCESS) {
            status = ability->updateEntry(OHOS_CONTROL_FPS_RANGES,
                videoFrameRateRange_.data(), videoFrameRateRange_.size());
        }
        if (!status) {
            MEDIA_ERR_LOG("HCameraDevice::Set fps renges Failed");
        }
    }
    return ability;
}

int32_t HCameraDevice::Open()
{
    CAMERA_SYNC_TRACE;
    int32_t errorCode;
    if (isOpenedCameraDevice_) {
        MEDIA_ERR_LOG("HCameraDevice::Open failed, camera is busy");
    }
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    if (callerToken_ != callerToken) {
        MEDIA_ERR_LOG("Failed to Open camera, createCamera token is : %{public}d, now token is %{public}d",
            callerToken_, callerToken);
        return CAMERA_OPERATION_NOT_ALLOWED;
    }
    if (deviceHDICallback_ == nullptr) {
        deviceHDICallback_ = new(std::nothrow) CameraDeviceCallback(this);
        if (deviceHDICallback_ == nullptr) {
            MEDIA_ERR_LOG("HCameraDevice::Open CameraDeviceCallback allocation failed");
            return CAMERA_ALLOC_ERROR;
        }
    }
    bool isAllowed = true;
    if (IsValidTokenId(callerToken)) {
        isAllowed = Security::AccessToken::PrivacyKit::IsAllowedUsingPermission(callerToken, OHOS_PERMISSION_CAMERA);
    }
    if (!isAllowed) {
        MEDIA_ERR_LOG("HCameraDevice::Open IsAllowedUsingPermission failed");
        return CAMERA_ALLOC_ERROR;
    }

    auto conflictDevices = cameraHostManager_->CameraConflictDetection(cameraID_);
    // Destory conflict devices
    for (auto &i : conflictDevices) {
        i->Close();
    }
    MEDIA_INFO_LOG("HCameraDevice::Open Opening camera device: %{public}s", cameraID_.c_str());
    errorCode = cameraHostManager_->OpenCameraDevice(cameraID_, deviceHDICallback_, hdiCameraDevice_);
    if (errorCode == CAMERA_OK) {
        errorCode = OpenHdiCamera();
    } else {
        MEDIA_ERR_LOG("HCameraDevice::Open Failed to open camera");
    }
    return errorCode;
}

int32_t HCameraDevice::OpenHdiCamera()
{
    int32_t errorCode = CAMERA_OK;
    isOpenedCameraDevice_ = true;
    if (updateSettings_ != nullptr && hdiCameraDevice_ != nullptr) {
        std::vector<uint8_t> setting;
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(updateSettings_, setting);
        CamRetCode rc = (CamRetCode)(hdiCameraDevice_->UpdateSettings(setting));
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            MEDIA_ERR_LOG("HCameraDevice::Open Update setting failed with error Code: %{public}d", rc);
            return HdiToServiceError(rc);
        }
        updateSettings_ = nullptr;
        MEDIA_DEBUG_LOG("HCameraDevice::Open Updated device settings");
    }
    if (hdiCameraDevice_) {
        errorCode = HdiToServiceError((CamRetCode)(hdiCameraDevice_->SetResultMode(ON_CHANGED)));
        cameraHostManager_->AddCameraDevice(cameraID_, this);
        (void)OnCameraStatus(cameraID_, CAMERA_STATUS_UNAVAILABLE);
    }
    return errorCode;
}

int32_t HCameraDevice::Close()
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(deviceLock_);
    if (hdiCameraDevice_ != nullptr) {
        MEDIA_INFO_LOG("HCameraDevice::Close Closing camera device: %{public}s", cameraID_.c_str());
        hdiCameraDevice_->Close();
        (void)OnCameraStatus(cameraID_, CAMERA_STATUS_AVAILABLE);
    }
    isOpenedCameraDevice_ = false;
    hdiCameraDevice_ = nullptr;
    if (streamOperator_) {
        streamOperator_ = nullptr;
    }
    if (cameraHostManager_) {
        cameraHostManager_->RemoveCameraDevice(cameraID_);
    }
    deviceHDICallback_ = nullptr;
    deviceSvcCallback_ = nullptr;
    return CAMERA_OK;
}

int32_t HCameraDevice::Release()
{
    if (hdiCameraDevice_ != nullptr) {
        Close();
    }
    return CAMERA_OK;
}

int32_t HCameraDevice::GetEnabledResults(std::vector<int32_t> &results)
{
    if (hdiCameraDevice_) {
        CamRetCode rc = (CamRetCode)(hdiCameraDevice_->GetEnabledResults(results));
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            MEDIA_ERR_LOG("HCameraDevice::GetEnabledResults failed with error Code:%{public}d", rc);
            return HdiToServiceError(rc);
        }
    } else {
        MEDIA_ERR_LOG("HCameraDevice::GetEnabledResults GetEnabledResults hdiCameraDevice_ is nullptr");
        return CAMERA_UNKNOWN_ERROR;
    }
    return CAMERA_OK;
}

int32_t HCameraDevice::UpdateSetting(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings)
{
    CAMERA_SYNC_TRACE;
    if (settings == nullptr) {
        MEDIA_ERR_LOG("HCameraDevice::UpdateSetting settings is null");
        return CAMERA_INVALID_ARG;
    }

    uint32_t count = OHOS::Camera::GetCameraMetadataItemCount(settings->get());
    if (!count) {
        MEDIA_DEBUG_LOG("HCameraDevice::UpdateSetting Nothing to update");
        return CAMERA_OK;
    }
    if (updateSettings_) {
        camera_metadata_item_t metadataItem;
        for (uint32_t index = 0; index < count; index++) {
            int ret = OHOS::Camera::GetCameraMetadataItem(settings->get(), index, &metadataItem);
            if (ret != CAM_META_SUCCESS) {
                MEDIA_ERR_LOG("HCameraDevice::UpdateSetting Failed to get metadata item at index: %{public}d", index);
                return CAMERA_INVALID_ARG;
            }
            bool status = false;
            uint32_t currentIndex;
            ret = OHOS::Camera::FindCameraMetadataItemIndex(updateSettings_->get(), metadataItem.item, &currentIndex);
            if (ret == CAM_META_ITEM_NOT_FOUND) {
                status = updateSettings_->addEntry(metadataItem.item, metadataItem.data.u8, metadataItem.count);
            } else if (ret == CAM_META_SUCCESS) {
                status = updateSettings_->updateEntry(metadataItem.item, metadataItem.data.u8, metadataItem.count);
            }
            if (!status) {
                MEDIA_ERR_LOG("HCameraDevice::UpdateSetting Failed to update metadata item: %{public}d",
                              metadataItem.item);
                return CAMERA_UNKNOWN_ERROR;
            }
        }
    } else {
        updateSettings_ = settings;
    }
    if (hdiCameraDevice_ != nullptr) {
        std::vector<uint8_t> setting;
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(updateSettings_, setting);
        ReportMetadataDebugLog(updateSettings_);
        GetFrameRateSetting(updateSettings_);

        CamRetCode rc = (CamRetCode)(hdiCameraDevice_->UpdateSettings(setting));
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            MEDIA_ERR_LOG("HCameraDevice::UpdateSetting failed with error Code: %{public}d", rc);
            return HdiToServiceError(rc);
        }
        ReportFlashEvent(updateSettings_);
        updateSettings_ = nullptr;
    }
    MEDIA_DEBUG_LOG("HCameraDevice::UpdateSetting Updated device settings");
    return CAMERA_OK;
}

void HCameraDevice::ReportMetadataDebugLog(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings)
{
    // debug log for focus mode
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_FOCUS_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_FOCUS_MODE tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_FOCUS_MODE value = %{public}d", item.data.u8[0]);
    }

    // debug log for af regions
    ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_AF_REGIONS, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_AF_REGIONS tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_AF_REGIONS x = %{public}f, y = %{public}f",
            item.data.f[0], item.data.f[1]);
    }

    // debug log for af regions
    ret = OHOS::Camera::FindCameraMetadataItem(settings->get(),
        OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_VIDEO_STABILIZATION_MODE tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_VIDEO_STABILIZATION_MODE value = %{public}d",
            item.data.u8[0]);
    }

    // debug log for exposure mode
    ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_EXPOSURE_MODE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_EXPOSURE_MODE tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_EXPOSURE_MODE value = %{public}d", item.data.u8[0]);
    }

    // debug log for ae regions
    ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_AE_REGIONS, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_AE_REGIONS tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_AE_REGIONS x = %{public}f, y = %{public}f",
            item.data.f[0], item.data.f[1]);
    }

    // debug log for ae exposure compensation
    ret = OHOS::Camera::FindCameraMetadataItem(settings->get(),
        OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_AE_EXPOSURE_COMPENSATION tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_AE_EXPOSURE_COMPENSATION value = %{public}d",
            item.data.u8[0]);
    }
}

void HCameraDevice::GetFrameRateSetting(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings)
{
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_FPS_RANGES, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_FPS_RANGES tag");
    } else {
        videoFrameRateRange_ = {item.data.i32[0], item.data.i32[1]};
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_FPS_RANGES min = %{public}d, max = %{public}d",
            item.data.i32[0], item.data.i32[1]);
    }
}

void HCameraDevice::ReportFlashEvent(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings)
{
    camera_metadata_item_t item;
    camera_flash_mode_enum_t flashMode = OHOS_CAMERA_FLASH_MODE_ALWAYS_OPEN;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_FLASH_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        flashMode = static_cast<camera_flash_mode_enum_t>(item.data.u8[0]);
    } else {
        MEDIA_ERR_LOG("CameraInput::GetFlashMode Failed with return code %{public}d", ret);
    }

    if (flashMode == OHOS_CAMERA_FLASH_MODE_CLOSE) {
        POWERMGR_SYSEVENT_FLASH_OFF();
    } else {
        POWERMGR_SYSEVENT_FLASH_ON();
    }
}

int32_t HCameraDevice::EnableResult(std::vector<int32_t> &results)
{
    if (results.empty()) {
        MEDIA_ERR_LOG("HCameraDevice::EnableResult results vector empty");
        return CAMERA_INVALID_ARG;
    }

    if (hdiCameraDevice_ == nullptr) {
        MEDIA_ERR_LOG("HCameraDevice::hdiCameraDevice_ is null");
        return CAMERA_UNKNOWN_ERROR;
    }

    CamRetCode rc = (CamRetCode)(hdiCameraDevice_->EnableResult(results));
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        MEDIA_ERR_LOG("HCameraDevice::EnableResult failed with error Code:%{public}d", rc);
        return HdiToServiceError(rc);
    }

    return CAMERA_OK;
}

int32_t HCameraDevice::DisableResult(std::vector<int32_t> &results)
{
    if (results.empty()) {
        MEDIA_ERR_LOG("HCameraDevice::DisableResult results vector empty");
        return CAMERA_INVALID_ARG;
    }

    if (hdiCameraDevice_ == nullptr) {
        MEDIA_ERR_LOG("HCameraDevice::hdiCameraDevice_ is null");
        return CAMERA_UNKNOWN_ERROR;
    }

    CamRetCode rc = (CamRetCode)(hdiCameraDevice_->DisableResult(results));
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        MEDIA_ERR_LOG("HCameraDevice::DisableResult failed with error Code:%{public}d", rc);
        return HdiToServiceError(rc);
    }
    return CAMERA_OK;
}

int32_t HCameraDevice::SetCallback(sptr<ICameraDeviceServiceCallback> &callback)
{
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HCameraDevice::SetCallback callback is null");
        return CAMERA_INVALID_ARG;
    }
    deviceSvcCallback_ = callback;
    return CAMERA_OK;
}

int32_t HCameraDevice::SetStatusCallback(std::map<int32_t, sptr<ICameraServiceCallback>> &callbacks)
{
    std::lock_guard<std::mutex> lock(statusCbLock_);
    MEDIA_INFO_LOG("HCameraDevice::SetStatusCallback callbacks size = %{public}zu",
                   callbacks.size());
    if (!statusSvcCallbacks_.empty()) {
        MEDIA_ERR_LOG("HCameraDevice::SetStatusCallback statusSvcCallbacks_ is not empty, reset it");
        statusSvcCallbacks_.clear();
    }
    for (auto it : callbacks) {
        statusSvcCallbacks_[it.first] = it.second;
    }
    MEDIA_INFO_LOG("HCameraDevice::SetStatusCallback statusSvcCallbacks_ size = %{public}zu",
                   statusSvcCallbacks_.size());
    return CAMERA_OK;
}

int32_t HCameraDevice::GetStreamOperator(sptr<IStreamOperatorCallback> callback,
    sptr<IStreamOperator> &streamOperator)
{
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HCameraDevice::GetStreamOperator callback is null");
        return CAMERA_INVALID_ARG;
    }

    if (hdiCameraDevice_ == nullptr) {
        MEDIA_ERR_LOG("HCameraDevice::hdiCameraDevice_ is null");
        return CAMERA_UNKNOWN_ERROR;
    }

    CamRetCode rc = (CamRetCode)(hdiCameraDevice_->GetStreamOperator(callback, streamOperator));
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        MEDIA_ERR_LOG("HCameraDevice::GetStreamOperator failed with error Code:%{public}d", rc);
        return HdiToServiceError(rc);
    }
    streamOperator_ = streamOperator;
    return CAMERA_OK;
}

sptr<IStreamOperator> HCameraDevice::GetStreamOperator()
{
    return streamOperator_;
}

int32_t HCameraDevice::OnError(const ErrorType type, const int32_t errorMsg)
{
    if (deviceSvcCallback_ != nullptr) {
        int32_t errorType;
        if (type == REQUEST_TIMEOUT) {
            errorType = CAMERA_DEVICE_REQUEST_TIMEOUT;
        } else if (type == DEVICE_PREEMPT) {
            errorType = CAMERA_DEVICE_PREEMPTED;
        } else {
            errorType = CAMERA_UNKNOWN_ERROR;
        }
        deviceSvcCallback_->OnError(errorType, errorMsg);
        CAMERA_SYSEVENT_FAULT(CreateMsg("CameraDeviceServiceCallback::OnError() is called!, errorType: %d,"
                                        "errorMsg: %d", errorType, errorMsg));
    }
    return CAMERA_OK;
}

int32_t HCameraDevice::OnCameraStatus(const std::string& cameraId, CameraStatus status)
{
    std::lock_guard<std::mutex> lock(statusCbLock_);
    MEDIA_INFO_LOG("HCameraDevice::OnCameraStatus statusSvcCallbacks_ size = %{public}zu",
                   statusSvcCallbacks_.size());
    std::string callbackPids = "[";
    for (auto it : statusSvcCallbacks_) {
        auto item = it.second.promote();
        if (item != nullptr) {
            callbackPids += " " + std::to_string((int)it.first);
            item->OnCameraStatusChanged(cameraId, status);
        }
    }
    callbackPids += " ]";
    MEDIA_INFO_LOG("HCameraDevice::OnCameraStatus OnCameraStatusChanged callbackPids = %{public}s, "
                   "cameraId = %{public}s, cameraStatus = %{public}d",
                   callbackPids.c_str(), cameraId.c_str(), status);
    return CAMERA_OK;
}

int32_t HCameraDevice::OnResult(const uint64_t timestamp,
                                const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    if (deviceSvcCallback_ != nullptr) {
        deviceSvcCallback_->OnResult(timestamp, result);
    }
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FLASH_MODE, &item);
    if (ret == 0) {
        MEDIA_INFO_LOG("CameraDeviceServiceCallback::OnResult() OHOS_CONTROL_FLASH_MODE is %{public}d",
                       item.data.u8[0]);
    }
    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FLASH_STATE, &item);
    if (ret == 0) {
        MEDIA_INFO_LOG("CameraDeviceServiceCallback::OnResult() OHOS_CONTROL_FLASH_STATE is %{public}d",
                       item.data.u8[0]);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FOCUS_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("Focus mode: %{public}d", item.data.u8[0]);
    }
    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FOCUS_STATE, &item);
    if (ret == CAM_META_SUCCESS) {
        MEDIA_INFO_LOG("Focus state: %{public}d", item.data.u8[0]);
    }
    return CAMERA_OK;
}

CameraDeviceCallback::CameraDeviceCallback(sptr<HCameraDevice> hCameraDevice)
{
    hCameraDevice_ = hCameraDevice;
}

int32_t CameraDeviceCallback::OnError(const ErrorType type, const int32_t errorCode)
{
    auto item = hCameraDevice_.promote();
    if (item != nullptr) {
        item->OnError(type, errorCode);
    }
    return CAMERA_OK;
}

int32_t CameraDeviceCallback::OnResult(uint64_t timestamp, const std::vector<uint8_t>& result)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(result, cameraResult);
    auto item = hCameraDevice_.promote();
    if (item != nullptr) {
        item->OnResult(timestamp, cameraResult);
    }
    return CAMERA_OK;
}
} // namespace CameraStandard
} // namespace OHOS
