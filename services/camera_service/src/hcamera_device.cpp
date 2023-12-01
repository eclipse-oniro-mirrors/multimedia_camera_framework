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
#include <cstdint>
#include <memory>
#include <mutex>

#include "camera_log.h"
#include "camera_util.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "display_manager.h"
#include "hcamera_device_manager.h"

namespace OHOS {
namespace CameraStandard {
std::mutex HCameraDevice::deviceOpenMutex_;
namespace {
int32_t MergeMetadata(const std::shared_ptr<OHOS::Camera::CameraMetadata> srcMetadata,
    std::shared_ptr<OHOS::Camera::CameraMetadata> dstMetadata)
{
    if (srcMetadata == nullptr || dstMetadata == nullptr) {
        return CAMERA_INVALID_ARG;
    }
    auto srcHeader = srcMetadata->get();
    if (srcHeader == nullptr) {
        return CAMERA_INVALID_ARG;
    }
    auto dstHeader = dstMetadata->get();
    if (dstHeader == nullptr) {
        return CAMERA_INVALID_ARG;
    }
    auto srcItemCount = srcHeader->item_count;
    camera_metadata_item_t srcItem;
    for (uint32_t index = 0; index < srcItemCount; index++) {
        int ret = OHOS::Camera::GetCameraMetadataItem(srcHeader, index, &srcItem);
        if (ret != CAM_META_SUCCESS) {
            MEDIA_ERR_LOG("Failed to get metadata item at index: %{public}d", index);
            return CAMERA_INVALID_ARG;
        }
        bool status = false;
        uint32_t currentIndex;
        ret = OHOS::Camera::FindCameraMetadataItemIndex(dstHeader, srcItem.item, &currentIndex);
        if (ret == CAM_META_ITEM_NOT_FOUND) {
            status = dstMetadata->addEntry(srcItem.item, srcItem.data.u8, srcItem.count);
        } else if (ret == CAM_META_SUCCESS) {
            status = dstMetadata->updateEntry(srcItem.item, srcItem.data.u8, srcItem.count);
        }
        if (!status) {
            MEDIA_ERR_LOG("Failed to update metadata item: %{public}d", srcItem.item);
            return CAMERA_UNKNOWN_ERROR;
        }
    }
    return CAMERA_OK;
}
} // namespace
sptr<OHOS::Rosen::DisplayManager::IFoldStatusListener> listener;
class HCameraDevice::FoldScreenListener : public OHOS::Rosen::DisplayManager::IFoldStatusListener {
public:
    explicit FoldScreenListener(sptr<HCameraHostManager> &cameraHostManager, const std::string cameraId)
        : cameraHostManager_(cameraHostManager), cameraId_(cameraId)
    {
        MEDIA_DEBUG_LOG("FoldScreenListener enter");
    }

    virtual ~FoldScreenListener() = default;
    void OnFoldStatusChanged(OHOS::Rosen::FoldStatus foldStatus) override
    {
        FoldStatus currentFoldStatus = FoldStatus::UNKNOWN_FOLD;
        if (foldStatus == OHOS::Rosen::FoldStatus::HALF_FOLD) {
            currentFoldStatus = FoldStatus::EXPAND;
        }
        if (cameraHostManager_ == nullptr || mLastFoldStatus == currentFoldStatus) {
            MEDIA_DEBUG_LOG("no need set fold status");
            return;
        }
        mLastFoldStatus = currentFoldStatus;
        cameraHostManager_->NotifyDeviceStateChangeInfo(DeviceType::FOLD_TYPE, (int)currentFoldStatus);
    }
private:
    sptr<HCameraHostManager> cameraHostManager_;
    std::string cameraId_;
    FoldStatus mLastFoldStatus = FoldStatus::UNKNOWN_FOLD;
};

HCameraDevice::HCameraDevice(sptr<HCameraHostManager> &cameraHostManager,
                             std::string cameraID,
                             const uint32_t callingTokenId)
{
    MEDIA_INFO_LOG("HCameraDevice::HCameraDevice Contructor Camera: %{public}s", cameraID.c_str());
    cameraHostManager_ = cameraHostManager;
    cameraID_ = cameraID;
    streamOperator_ = nullptr;
    isReleaseCameraDevice_ = false;
    isOpenedCameraDevice_.store(false);
    callerToken_ = callingTokenId;
    deviceOperatorsCallback_ = nullptr;
}

HCameraDevice::~HCameraDevice()
{
    MEDIA_INFO_LOG("HCameraDevice::~HCameraDevice Destructor Camera: %{public}s", cameraID_.c_str());
    {
        std::lock_guard<std::mutex> lock(opMutex_);
        hdiCameraDevice_ = nullptr;
        streamOperator_ = nullptr;
    }

    if (cameraHostManager_) {
        cameraHostManager_ = nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(deviceSvcCbMutex_);
        deviceSvcCallback_ = nullptr;
    }
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
    return isOpenedCameraDevice_.load();
}

std::shared_ptr<OHOS::Camera::CameraMetadata> HCameraDevice::CloneCachedSettings()
{
    std::lock_guard<std::mutex> cachedLock(cachedSettingsMutex_);
    if (cachedSettings_ == nullptr) {
        return nullptr;
    }
    auto itemHeader = cachedSettings_->get();
    if (itemHeader == nullptr) {
        return nullptr;
    }
    auto returnSettings =
        std::make_shared<OHOS::Camera::CameraMetadata>(itemHeader->item_capacity, itemHeader->data_capacity);
    int32_t errCode = MergeMetadata(cachedSettings_, returnSettings);
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraDevice::CloneCachedSettings failed: %{public}d", errCode);
        return nullptr;
    }
    return returnSettings;
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
    return ability;
}

int32_t HCameraDevice::Open()
{
    CAMERA_SYNC_TRACE;
    if (isOpenedCameraDevice_.load()) {
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
    return OpenDevice();
}

int32_t HCameraDevice::Close()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraDevice::Close Closing camera device: %{public}s", cameraID_.c_str());
    if (deviceOperatorsCallback_.promote() == nullptr) {
        MEDIA_ERR_LOG("HCameraDevice::Close there is no device operator callback");
        return CAMERA_OPERATION_NOT_ALLOWED;
    }
    return CloseDevice();
}

int32_t HCameraDevice::OpenDevice()
{
    MEDIA_DEBUG_LOG("HCameraDevice::OpenDevice start");
    CAMERA_SYNC_TRACE;
    int32_t errorCode;
    MEDIA_INFO_LOG("HCameraDevice::OpenDevice Opening camera device: %{public}s", cameraID_.c_str());

    {
        std::lock_guard<std::mutex> lock(deviceOpenMutex_);
        sptr<HCameraDevice> cameraNeedEvict;
        bool canOpenCamera = HCameraDeviceManager::GetInstance()->GetConflictDevices(cameraNeedEvict, this);
        if (cameraNeedEvict != nullptr) {
            MEDIA_DEBUG_LOG("HCameraDevice::Open current device need to close other devices");
            // 关闭camerasNeedEvict里面的相机
            cameraNeedEvict->OnError(DEVICE_PREEMPT, 0);
            cameraNeedEvict->CloseDevice();  // 2
        }
        if (canOpenCamera) {
            errorCode = cameraHostManager_->OpenCameraDevice(cameraID_, this, hdiCameraDevice_);
        } else {
            return CAMERA_UNKNOWN_ERROR;
        }
        if (errorCode != CAMERA_OK) {
            MEDIA_ERR_LOG("HCameraDevice::OpenDevice Failed to open camera");
        }
        HCameraDeviceManager::GetInstance()->AddDevice(IPCSkeleton::GetCallingPid(), this);
    }

    std::lock_guard<std::mutex> lockSetting(opMutex_);
    isOpenedCameraDevice_.store(true);
    if (hdiCameraDevice_ != nullptr) {
        cameraHostManager_->AddCameraDevice(cameraID_, this);
        if (updateSettings_ != nullptr) {
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
        }
    }
    bool isFoldable = OHOS::Rosen::DisplayManager::GetInstance().IsFoldable();
    MEDIA_DEBUG_LOG("HCameraDevice::OpenDevice isFoldable is %d", isFoldable);
    if (isFoldable) {
        RegisterFoldStatusListener();
    }
    MEDIA_DEBUG_LOG("HCameraDevice::OpenDevice end");
    return errorCode;
}

int32_t HCameraDevice::CloseDevice()
{
    MEDIA_DEBUG_LOG("HCameraDevice::CloseDevice start");
    CAMERA_SYNC_TRACE;
    {
        std::lock_guard<std::mutex> lock(opMutex_);
        if (!isOpenedCameraDevice_.load()) {
            MEDIA_DEBUG_LOG("HCameraDevice::CloseDevice device has benn closed");
            return CAMERA_OK;
        }
        bool isFoldable = OHOS::Rosen::DisplayManager::GetInstance().IsFoldable();
        if (isFoldable) {
            UnRegisterFoldStatusListener();
        }
        if (hdiCameraDevice_ != nullptr) {
            isOpenedCameraDevice_.store(false);
            MEDIA_INFO_LOG("Closing camera device: %{public}s start", cameraID_.c_str());
            hdiCameraDevice_->Close();
            HCameraDeviceManager::GetInstance()->RemoveDevice();
            MEDIA_INFO_LOG("Closing camera device: %{public}s end", cameraID_.c_str());
            hdiCameraDevice_ = nullptr;
        }
        if (streamOperator_) {
            streamOperator_ = nullptr;
        }
    }
    if (cameraHostManager_) {
        cameraHostManager_->RemoveCameraDevice(cameraID_);
    }
    std::lock_guard<std::mutex> lock(deviceSvcCbMutex_);
    deviceSvcCallback_ = nullptr;
    MEDIA_DEBUG_LOG("HCameraDevice::CloseDevice end");
    return CAMERA_OK;
}

int32_t HCameraDevice::Release()
{
    Close();
    return CAMERA_OK;
}

int32_t HCameraDevice::GetEnabledResults(std::vector<int32_t> &results)
{
    std::lock_guard<std::mutex> lock(opMutex_);
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

int32_t HCameraDevice::UpdateSetting(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
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
    std::lock_guard<std::mutex> lock(opMutex_);
    if (updateSettings_ != nullptr) {
        int ret = MergeMetadata(settings, updateSettings_);
        if (ret != CAMERA_OK) {
            return ret;
        }
    } else {
        updateSettings_ = settings;
    }
    MEDIA_DEBUG_LOG("Updated device settings  hdiCameraDevice_(%{public}d)", hdiCameraDevice_ != nullptr);
    if (hdiCameraDevice_ != nullptr) {
        std::vector<uint8_t> hdiSettings;
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(updateSettings_, hdiSettings);
        ReportMetadataDebugLog(updateSettings_);
        CamRetCode rc = (CamRetCode)(hdiCameraDevice_->UpdateSettings(hdiSettings));
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            MEDIA_ERR_LOG("Failed with error Code: %{public}d", rc);
            return HdiToServiceError(rc);
        }
        ReportFlashEvent(updateSettings_);
        {
            std::lock_guard<std::mutex> cachedLock(cachedSettingsMutex_);
            if (cachedSettings_ == nullptr) {
                cachedSettings_ = updateSettings_;
            } else {
                MergeMetadata(settings, cachedSettings_);
            }
        }
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

    // debug log for exposure mode
    ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_MANUAL_EXPOSURE_TIME, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_MANUAL_EXPOSURE_TIME tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_MANUAL_EXPOSURE_TIME value = %{public}d", item.data.ui32[0]);
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

    // debug log for portrait Effect
    ret = OHOS::Camera::FindCameraMetadataItem(settings->get(),
        OHOS_CONTROL_PORTRAIT_EFFECT_TYPE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_PORTRAIT_EFFECT_TYPE portraitEffect tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_PORTRAIT_EFFECT_TYPE value = %{public}d portraitEffect",
            item.data.u8[0]);
    }

    // debug log for filter type
    ret = OHOS::Camera::FindCameraMetadataItem(settings->get(),
        OHOS_CONTROL_FILTER_TYPE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_FILTER_TYPE portraitEffect tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_FILTER_TYPE value = %{public}d portraitEffect",
            item.data.u8[0]);
    }

    // debug log for beauty auto value
    ret = OHOS::Camera::FindCameraMetadataItem(settings->get(),
        OHOS_CONTROL_BEAUTY_AUTO_VALUE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_BEAUTY_AUTO_VALUE portraitEffect tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_BEAUTY_AUTO_VALUE value = %{public}d portraitEffect",
            item.data.u8[0]);
    }

    // debug log for beauty skin smooth value
    ret = OHOS::Camera::FindCameraMetadataItem(settings->get(),
        OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE portraitEffect tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE value = %{public}d portraitEffect",
            item.data.u8[0]);
    }

    // debug log for beauty face slender value
    ret = OHOS::Camera::FindCameraMetadataItem(settings->get(),
        OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE portraitEffect tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE value = %{public}d portraitEffect",
            item.data.u8[0]);
    }

    // debug log for beauty skin tone value
    ret = OHOS::Camera::FindCameraMetadataItem(settings->get(),
        OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE portraitEffect tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE value = %{public}d portraitEffect",
            item.data.i32[0]);
    }
}

void HCameraDevice::RegisterFoldStatusListener()
{
    listener = new FoldScreenListener(cameraHostManager_, cameraID_);
    if (cameraHostManager_) {
        int foldStatus = (int)OHOS::Rosen::DisplayManager::GetInstance().GetFoldStatus();
        cameraHostManager_->NotifyDeviceStateChangeInfo(DeviceType::FOLD_TYPE, foldStatus);
    }
    auto ret = OHOS::Rosen::DisplayManager::GetInstance().RegisterFoldStatusListener(listener);
    if (ret != OHOS::Rosen::DMError::DM_OK) {
        MEDIA_DEBUG_LOG("HCameraDevice::RegisterFoldStatusListener failed");
        listener = nullptr;
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::RegisterFoldStatusListener success");
    }
}

void HCameraDevice::UnRegisterFoldStatusListener()
{
    if (listener == nullptr) {
        MEDIA_ERR_LOG("HCameraDevice::unRegisterFoldStatusListener  listener is null");
        return;
    }
    auto ret = OHOS::Rosen::DisplayManager::GetInstance().UnregisterFoldStatusListener(listener);
    if (ret != OHOS::Rosen::DMError::DM_OK) {
        MEDIA_DEBUG_LOG("HCameraDevice::UnRegisterFoldStatusListener failed");
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
    std::lock_guard<std::mutex> lock(opMutex_);
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
    std::lock_guard<std::mutex> lock(opMutex_);
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
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> &streamOperator)
{
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HCameraDevice::GetStreamOperator callback is null");
        return CAMERA_INVALID_ARG;
    }
    std::lock_guard<std::mutex> lock(opMutex_);
    if (hdiCameraDevice_ == nullptr) {
        MEDIA_ERR_LOG("HCameraDevice::hdiCameraDevice_ is null");
        return CAMERA_UNKNOWN_ERROR;
    }
    CamRetCode rc;
    sptr<OHOS::HDI::Camera::V1_1::ICameraDevice> hdiCameraDeviceV1_1;
    sptr<OHOS::HDI::Camera::V1_2::ICameraDevice> hdiCameraDeviceV1_2;
    if (cameraHostManager_->GetVersionByCamera(cameraID_) >= GetVersionId(HDI_VERSION_1, HDI_VERSION_2)) {
        MEDIA_DEBUG_LOG("HCameraDevice::GetStreamOperator ICameraDevice cast to V1_1");
        hdiCameraDeviceV1_2 = OHOS::HDI::Camera::V1_2::ICameraDevice::CastFrom(hdiCameraDevice_);
    } else if (cameraHostManager_->GetVersionByCamera(cameraID_) == GetVersionId(HDI_VERSION_1, HDI_VERSION_1)) {
        MEDIA_DEBUG_LOG("HCameraDevice::GetStreamOperator ICameraDevice cast to V1_1");
        hdiCameraDeviceV1_1 = OHOS::HDI::Camera::V1_1::ICameraDevice::CastFrom(hdiCameraDevice_);
        if (hdiCameraDeviceV1_1 == nullptr) {
            MEDIA_ERR_LOG("HCameraDevice::GetStreamOperator ICameraDevice cast to V1_1 error");
            hdiCameraDeviceV1_1 = static_cast<OHOS::HDI::Camera::V1_1::ICameraDevice *>(hdiCameraDevice_.GetRefPtr());
        }
    }
    if (hdiCameraDeviceV1_2 != nullptr &&
        cameraHostManager_->GetVersionByCamera(cameraID_) >= GetVersionId(HDI_VERSION_1, HDI_VERSION_2)) {
        MEDIA_DEBUG_LOG("HCameraDevice::GetStreamOperator ICameraDevice V1_2");
        sptr<OHOS::HDI::Camera::V1_2::IStreamOperator> streamOperator_v1_2;
        sptr<OHOS::HDI::Camera::V1_2::IStreamOperatorCallback> callback_v1_2 =
            static_cast<OHOS::HDI::Camera::V1_2::IStreamOperatorCallback *>(callback.GetRefPtr());
        rc = (CamRetCode)(hdiCameraDeviceV1_2->GetStreamOperator_V1_2(callback_v1_2, streamOperator_v1_2));
        streamOperator = static_cast<OHOS::HDI::Camera::V1_0::IStreamOperator *>(streamOperator_v1_2.GetRefPtr());
    } else if (hdiCameraDeviceV1_1 != nullptr &&
        cameraHostManager_->GetVersionByCamera(cameraID_) == GetVersionId(HDI_VERSION_1, HDI_VERSION_1)) {
        MEDIA_DEBUG_LOG("HCameraDevice::GetStreamOperator ICameraDevice V1_1");
        sptr<OHOS::HDI::Camera::V1_1::IStreamOperator> streamOperator_v1_1;
        rc = (CamRetCode)(hdiCameraDeviceV1_1->GetStreamOperator_V1_1(callback, streamOperator_v1_1));
        streamOperator = static_cast<OHOS::HDI::Camera::V1_0::IStreamOperator *>(streamOperator_v1_1.GetRefPtr());
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::GetStreamOperator ICameraDevice V1_0");
        rc = (CamRetCode)(hdiCameraDevice_->GetStreamOperator(callback, streamOperator));
    }

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

sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> HCameraDevice::GetStreamOperator()
{
    std::lock_guard<std::mutex> lock(opMutex_);
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
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult = nullptr;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(result, cameraResult);

    std::lock_guard<std::mutex> lock(deviceSvcCbMutex_);
    if (deviceSvcCallback_ != nullptr) {
        deviceSvcCallback_->OnResult(timestamp, cameraResult);
    }
    if (cameraResult != nullptr) {
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
        ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_STATISTICS_FACE_RECTANGLES, &item);
        if (ret != CAM_META_SUCCESS) {
            MEDIA_ERR_LOG("cannot find OHOS_STATISTICS_FACE_RECTANGLES: %{public}d", ret);
            return 0;
        }
        MEDIA_INFO_LOG("ProcessFaceRectangles: %{public}d count: %{public}d", item.item, item.count);
        constexpr int32_t rectangleUnitLen = 4;

        if (item.count % rectangleUnitLen) {
            MEDIA_ERR_LOG("Metadata item: %{public}d count: %{public}d is invalid", item.item, item.count);
            return CAM_META_SUCCESS;
        }
        const int32_t offsetX = 0;
        const int32_t offsetY = 1;
        const int32_t offsetW = 2;
        const int32_t offsetH = 3;
        float* start = item.data.f;
        float* end = item.data.f + item.count;
        for (; start < end; start += rectangleUnitLen) {
            MEDIA_INFO_LOG("Metadata item: %{public}f,%{public}f,%{public}f,%{public}f",
                           start[offsetX], start[offsetY], start[offsetW], start[offsetH]);
        }
    } else {
        MEDIA_ERR_LOG("HCameraDevice::OnResult cameraResult is nullptr");
    }
    return CAMERA_OK;
}

int32_t HCameraDevice::GetCallerToken()
{
    return callerToken_;
}
} // namespace CameraStandard
} // namespace OHOS
