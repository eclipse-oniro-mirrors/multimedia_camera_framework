/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
    deviceOperatorsCallback_ = nullptr;
}

HCameraDevice::~HCameraDevice()
{
    hdiCameraDevice_ = nullptr;
    streamOperator_ = nullptr;
    if (cameraHostManager_) {
        cameraHostManager_ = nullptr;
    }
    deviceSvcCallback_ = nullptr;
    deviceOperatorsCallback_ = nullptr;
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
    int32_t* pos = nullptr;
    int32_t videoFrameRateRangeSize;
    {
        std::lock_guard<std::mutex> lock(videoFrameRangeMutex_);
        videoFrameRateRangeSize = videoFrameRateRange_.size();
        if (videoFrameRateRangeSize != 0) {
            pos = videoFrameRateRange_.data();
        }
    }
    if (videoFrameRateRangeSize != 0 && ability != nullptr) {
        bool status = false;
        camera_metadata_item_t item;
        int ret = OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_CONTROL_FPS_RANGES, &item);
        if (ret == CAM_META_ITEM_NOT_FOUND) {
            status = ability->addEntry(OHOS_CONTROL_FPS_RANGES, pos, videoFrameRateRangeSize);
        } else if (ret == CAM_META_SUCCESS) {
            status = ability->updateEntry(OHOS_CONTROL_FPS_RANGES, pos, videoFrameRateRangeSize);
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
    if (isOpenedCameraDevice_) {
        MEDIA_ERR_LOG("HCameraDevice::Open failed, camera is busy");
    }
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    if (callerToken_ != callerToken) {
        MEDIA_ERR_LOG("Failed to Open camera, createCamera token is : %{public}d, now token is %{public}d",
            callerToken_, callerToken);
        return CAMERA_OPERATION_NOT_ALLOWED;
    }
    bool isAllowed = true;
    if (IsValidTokenId(callerToken)) {
        isAllowed = Security::AccessToken::PrivacyKit::IsAllowedUsingPermission(callerToken, OHOS_PERMISSION_CAMERA);
    }
    if (!isAllowed) {
        MEDIA_ERR_LOG("HCameraDevice::Open IsAllowedUsingPermission failed");
        return CAMERA_ALLOC_ERROR;
    }

    if (deviceOperatorsCallback_.promote() == nullptr) {
        MEDIA_ERR_LOG("HCameraDevice::Close there is no device operator callback");
        return CAMERA_ALLOC_ERROR;
    }

    MEDIA_INFO_LOG("HCameraDevice::Open Camera:[%{public}s", cameraID_.c_str());
    return deviceOperatorsCallback_->DeviceOpen(cameraID_);
}

int32_t HCameraDevice::Close()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraDevice::Close Closing camera device: %{public}s", cameraID_.c_str());
    if (deviceOperatorsCallback_.promote() == nullptr) {
        MEDIA_ERR_LOG("HCameraDevice::Close there is no device operator callback");
        return CAMERA_OPERATION_NOT_ALLOWED;
    }
    return deviceOperatorsCallback_->DeviceClose(cameraID_);
}

int32_t HCameraDevice::OpenDevice()
{
    CAMERA_SYNC_TRACE;
    int32_t errorCode;
    MEDIA_INFO_LOG("HCameraDevice::OpenDevice Opening camera device: %{public}s", cameraID_.c_str());
    errorCode = cameraHostManager_->OpenCameraDevice(cameraID_, this, hdiCameraDevice_);
    if (errorCode == CAMERA_OK) {
        std::lock_guard<std::mutex> lock(settingsMutex_);
        isOpenedCameraDevice_ = true;
        if (updateSettings_ != nullptr && hdiCameraDevice_ != nullptr) {
            std::vector<uint8_t> setting;
            OHOS::Camera::MetadataUtils::ConvertMetadataToVec(updateSettings_, setting);
            CamRetCode rc = (CamRetCode)(hdiCameraDevice_->UpdateSettings(setting));
            if (rc != HDI::Camera::V1_0::NO_ERROR) {
                MEDIA_ERR_LOG("HCameraDevice::OpenDevice Update setting failed with error Code: %{public}d", rc);
                return HdiToServiceError(rc);
            }
            updateSettings_ = nullptr;
            MEDIA_DEBUG_LOG("HCameraDevice::Open Updated device settings");

            errorCode = HdiToServiceError((CamRetCode)(hdiCameraDevice_->SetResultMode(ON_CHANGED)));
            cameraHostManager_->AddCameraDevice(cameraID_, this);
        }
    } else {
        MEDIA_ERR_LOG("HCameraDevice::OpenDevice Failed to open camera");
    }
    return errorCode;
}

int32_t HCameraDevice::CloseDevice()
{
    CAMERA_SYNC_TRACE;
    if (hdiCameraDevice_ != nullptr) {
        MEDIA_INFO_LOG("HCameraDevice::CloseDevice Closing camera device: %{public}s", cameraID_.c_str());
        hdiCameraDevice_->Close();
        isOpenedCameraDevice_ = false;
        hdiCameraDevice_ = nullptr;
    }
    if (streamOperator_) {
        streamOperator_ = nullptr;
    }
    if (cameraHostManager_) {
        cameraHostManager_->RemoveCameraDevice(cameraID_);
    }
    std::lock_guard<std::mutex> lock(deviceSvcCbMutex_);
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
        MEDIA_ERR_LOG("settings is null");
        return CAMERA_INVALID_ARG;
    }

    uint32_t count = OHOS::Camera::GetCameraMetadataItemCount(settings->get());
    if (!count) {
        MEDIA_DEBUG_LOG("Nothing to update");
        return CAMERA_OK;
    }
    std::lock_guard<std::mutex> lock(settingsMutex_);
    if (updateSettings_) {
        camera_metadata_item_t metadataItem;
        for (uint32_t index = 0; index < count; index++) {
            int ret = OHOS::Camera::GetCameraMetadataItem(settings->get(), index, &metadataItem);
            if (ret != CAM_META_SUCCESS) {
                MEDIA_ERR_LOG("Failed to get metadata item at index: %{public}d", index);
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
                MEDIA_ERR_LOG("Failed to update metadata item: %{public}d", metadataItem.item);
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
            MEDIA_ERR_LOG("Failed with error Code: %{public}d", rc);
            return HdiToServiceError(rc);
        }
        ReportFlashEvent(updateSettings_);
        updateSettings_ = nullptr;
    }
    MEDIA_DEBUG_LOG("Updated device settings");
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
        std::lock_guard<std::mutex> lock(videoFrameRangeMutex_);
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
    std::lock_guard<std::mutex> lock(deviceSvcCbMutex_);
    deviceSvcCallback_ = callback;
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

int32_t HCameraDevice::SetDeviceOperatorsCallback(wptr<IDeviceOperatorsCallback> callback)
{
    if (callback.promote() == nullptr) {
        MEDIA_ERR_LOG("HCameraDevice::SetDeviceOperatorsCallback callback is null");
        return CAMERA_INVALID_ARG;
    }
    deviceOperatorsCallback_ = callback;
    return CAMERA_OK;
}

sptr<IStreamOperator> HCameraDevice::GetStreamOperator()
{
    return streamOperator_;
}

int32_t HCameraDevice::OnError(const ErrorType type, const int32_t errorMsg)
{
    std::lock_guard<std::mutex> lock(deviceSvcCbMutex_);
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

int32_t HCameraDevice::OnResult(const uint64_t timestamp, const std::vector<uint8_t>& result)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(result, cameraResult);

    std::lock_guard<std::mutex> lock(deviceSvcCbMutex_);
    if (deviceSvcCallback_ != nullptr) {
        deviceSvcCallback_->OnResult(timestamp, cameraResult);
    }
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = cameraResult->get();
    int ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FLASH_MODE, &item);
    if (ret == 0) {
        MEDIA_DEBUG_LOG("CameraDeviceServiceCallback::OnResult() OHOS_CONTROL_FLASH_MODE is %{public}d",
                        item.data.u8[0]);
    }
    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FLASH_STATE, &item);
    if (ret == 0) {
        MEDIA_DEBUG_LOG("CameraDeviceServiceCallback::OnResult() OHOS_CONTROL_FLASH_STATE is %{public}d",
                        item.data.u8[0]);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FOCUS_MODE, &item);
    if (ret == CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("Focus mode: %{public}d", item.data.u8[0]);
    }
    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FOCUS_STATE, &item);
    if (ret == CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("Focus state: %{public}d", item.data.u8[0]);
    }
    return CAMERA_OK;
}

int32_t HCameraDevice::GetCallerToken()
{
    return callerToken_;
}
} // namespace CameraStandard
} // namespace OHOS
