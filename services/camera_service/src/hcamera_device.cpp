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
#include <vector>

#include "camera_device_ability_items.h"
#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_fwk_metadata_utils.h"
#include "camera_metadata_info.h"
#include "camera_metadata_operator.h"
#include "camera_service_ipc_interface_code.h"
#include "camera_util.h"
#include "display_manager.h"
#include "hcamera_device_manager.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "metadata_utils.h"
#include "v1_0/types.h"
#include "os_account_manager.h"
#include "deferred_processing_service.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "camera_timer.h"
#include "camera_report_uitls.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
std::mutex HCameraDevice::g_deviceOpenCloseMutex_;
static const int32_t DEFAULT_SETTING_ITEM_COUNT = 100;
static const int32_t DEFAULT_SETTING_ITEM_LENGTH = 100;
static const float SMOOTH_ZOOM_DIVISOR = 100.0f;
static const std::vector<camera_device_metadata_tag> DEVICE_OPEN_LIFECYCLE_TAGS = { OHOS_CONTROL_MUTE_MODE };
sptr<OHOS::Rosen::DisplayManager::IFoldStatusListener> listener;
CallerInfo caller_;
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

HCameraDevice::HCameraDevice(
    sptr<HCameraHostManager>& cameraHostManager, std::string cameraID, const uint32_t callingTokenId)
    : cachedSettings_(
          std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_SETTING_ITEM_COUNT, DEFAULT_SETTING_ITEM_LENGTH)),
      cameraHostManager_(cameraHostManager), cameraID_(cameraID), callerToken_(callingTokenId),
      deviceOpenLifeCycleSettings_(std::make_shared<OHOS::Camera::CameraMetadata>(
      DEVICE_OPEN_LIFECYCLE_TAGS.size(), DEFAULT_SETTING_ITEM_LENGTH)), clientUserId_(0), zoomTimerId_(0),
      deviceMuteMode_(false), isHasOpenSecure(false)
{
    MEDIA_INFO_LOG("HCameraDevice::HCameraDevice Contructor Camera: %{public}s", cameraID.c_str());
    isOpenedCameraDevice_.store(false);
    CameraTimer::GetInstance()->IncreaseUserCount();
}

HCameraDevice::~HCameraDevice()
{
    UnPrepareZoom();
    CameraTimer::GetInstance()->Unregister(zoomTimerId_);
    CameraTimer::GetInstance()->DecreaseUserCount();
    MEDIA_INFO_LOG("HCameraDevice::~HCameraDevice Destructor Camera: %{public}s", cameraID_.c_str());
}

std::string HCameraDevice::GetCameraId()
{
    return cameraID_;
}

bool HCameraDevice::IsOpenedCameraDevice()
{
    return isOpenedCameraDevice_.load();
}

void HCameraDevice::SetDeviceMuteMode(bool muteMode)
{
    deviceMuteMode_ = muteMode;
}

void HCameraDevice::UpdateMuteSetting()
{
    constexpr int32_t DEFAULT_ITEMS = 1;
    constexpr int32_t DEFAULT_DATA_LENGTH = 1;
    int32_t count = 1;
    uint8_t mode = OHOS_CAMERA_MUTE_MODE_SOLID_COLOR_BLACK;
    std::shared_ptr<OHOS::Camera::CameraMetadata> stashMetadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    stashMetadata->addEntry(OHOS_CONTROL_MUTE_MODE, &mode, count);
    UpdateSetting(stashMetadata);
}

int32_t HCameraDevice::ResetDeviceSettings()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraDevice::ResetDeviceSettings enter");
    {
        std::lock_guard<std::mutex> lock(opMutex_);
        if (hdiCameraDevice_ == nullptr) {
            return CAMERA_OK;
        }
    }
    auto hdiCameraDeviceV1_2 = HDI::Camera::V1_2::ICameraDevice::CastFrom(hdiCameraDevice_);
    if (hdiCameraDeviceV1_2 != nullptr) {
        int32_t errCode = hdiCameraDeviceV1_2->Reset();
        if (errCode != HDI::Camera::V1_0::CamRetCode::NO_ERROR) {
            MEDIA_ERR_LOG("HCameraDevice::ResetDeviceSettings occur error");
            return CAMERA_UNKNOWN_ERROR;
        } else {
            ResetCachedSettings();
            if (deviceMuteMode_) {
                UpdateMuteSetting();
            }
        }
    }
    MEDIA_INFO_LOG("HCameraDevice::ResetDeviceSettings end");
    return CAMERA_OK;
}

int32_t HCameraDevice::DispatchDefaultSettingToHdi()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraDevice::DispatchDefaultSettingToHdi enter");

    std::shared_ptr<OHOS::Camera::CameraMetadata> lifeCycleSettings;
    {
        std::lock_guard<std::mutex> lifeLock(deviceOpenLifeCycleMutex_);
        if (deviceOpenLifeCycleSettings_->get()->item_count == 0) {
            MEDIA_INFO_LOG("HCameraDevice::DispatchDefaultSettingToHdi skip, data is empty");
            return CAMERA_OK;
        }
        lifeCycleSettings = CameraFwkMetadataUtils::CopyMetadata(deviceOpenLifeCycleSettings_);
    }

    if (IsCameraDebugOn()) {
        auto metadataHeader = lifeCycleSettings->get();
        for (uint32_t index = 0; index < metadataHeader->item_count; index++) {
            camera_metadata_item_t item;
            int32_t result = OHOS::Camera::GetCameraMetadataItem(metadataHeader, index, &item);
            if (result == CAM_META_SUCCESS) {
                MEDIA_INFO_LOG("HCameraDevice::DispatchDefaultSettingToHdi tag:%{public}d", item.item);
            } else {
                MEDIA_ERR_LOG(
                    "HCameraDevice::DispatchDefaultSettingToHdi tag:%{public}d error:%{public}d", item.item, result);
            }
        }
    }

    std::lock_guard<std::mutex> lock(opMutex_);
    if (hdiCameraDevice_ == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    std::vector<uint8_t> hdiMetadata;
    bool isSuccess = OHOS::Camera::MetadataUtils::ConvertMetadataToVec(lifeCycleSettings, hdiMetadata);
    if (!isSuccess) {
        MEDIA_ERR_LOG("HCameraDevice::DispatchDefaultSettingToHdi metadata ConvertMetadataToVec fail");
        return CAMERA_UNKNOWN_ERROR;
    }
    ReportMetadataDebugLog(lifeCycleSettings);
    CamRetCode rc = (CamRetCode)hdiCameraDevice_->UpdateSettings(hdiMetadata);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        MEDIA_ERR_LOG("HCameraDevice::DispatchDefaultSettingToHdi UpdateSettings error: %{public}d", rc);
        CameraReportUtils::ReportCameraError(
            "HCameraDevice::DispatchDefaultSettingToHdi", rc, true, CameraReportUtils::GetCallerInfo());
        return HdiToServiceError(rc);
    }
    return CAMERA_OK;
}

void HCameraDevice::ResetCachedSettings()
{
    std::lock_guard<std::mutex> cachedLock(cachedSettingsMutex_);
    cachedSettings_ =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_SETTING_ITEM_COUNT, DEFAULT_SETTING_ITEM_LENGTH);
}

std::shared_ptr<OHOS::Camera::CameraMetadata> HCameraDevice::CloneCachedSettings()
{
    std::lock_guard<std::mutex> cachedLock(cachedSettingsMutex_);
    return CameraFwkMetadataUtils::CopyMetadata(cachedSettings_);
}

std::shared_ptr<OHOS::Camera::CameraMetadata> HCameraDevice::GetDeviceAbility()
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(deviceAbilityMutex_);
    if (deviceAbility_ != nullptr) {
        return deviceAbility_;
    }
    int32_t errCode = cameraHostManager_->GetCameraAbility(cameraID_, deviceAbility_);
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraDevice::GetSettings Failed to get Camera Ability: %{public}d", errCode);
        return nullptr;
    }
    return deviceAbility_;
}

int32_t HCameraDevice::Open()
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(g_deviceOpenCloseMutex_);
    if (isOpenedCameraDevice_.load()) {
        MEDIA_ERR_LOG("HCameraDevice::Open failed, camera is busy");
    }
    bool isAllowed = true;
    if (IsValidTokenId(callerToken_)) {
        isAllowed = Security::AccessToken::PrivacyKit::IsAllowedUsingPermission(callerToken_, OHOS_PERMISSION_CAMERA);
    }
    if (!isAllowed) {
        MEDIA_ERR_LOG("HCameraDevice::Open IsAllowedUsingPermission failed");
        return CAMERA_ALLOC_ERROR;
    }

    MEDIA_INFO_LOG("HCameraDevice::Open Camera:[%{public}s", cameraID_.c_str());
    int32_t result = OpenDevice();
    return result;
}

int32_t HCameraDevice::OpenSecureCamera(uint64_t* secureSeqId)
{
    CAMERA_SYNC_TRACE;
    if (isOpenedCameraDevice_.load()) {
        MEDIA_ERR_LOG("HCameraDevice::Open failed, camera is busy");
    }
    bool isAllowed = true;
    if (IsValidTokenId(callerToken_)) {
        isAllowed = Security::AccessToken::PrivacyKit::IsAllowedUsingPermission(callerToken_, OHOS_PERMISSION_CAMERA);
    }
    if (!isAllowed) {
        MEDIA_ERR_LOG("HCameraDevice::Open IsAllowedUsingPermission failed");
        return CAMERA_ALLOC_ERROR;
    }

    MEDIA_INFO_LOG("HCameraDevice::OpenSecureCamera Camera:[%{public}s", cameraID_.c_str());
    int32_t errCode = OpenDevice(true);
    auto hdiCameraDeviceV1_3 = HDI::Camera::V1_3::ICameraDevice::CastFrom(hdiCameraDevice_);
    if (hdiCameraDeviceV1_3 != nullptr) {
        errCode = hdiCameraDeviceV1_3->GetSecureCameraSeq(*secureSeqId);
        if (errCode != HDI::Camera::V1_0::CamRetCode::NO_ERROR) {
            MEDIA_ERR_LOG("HCameraDevice::GetSecureCameraSeq occur error");
            return CAMERA_UNKNOWN_ERROR;
        }
        mSecureCameraSeqId = *secureSeqId;
        isHasOpenSecure = true;
    }  else {
        MEDIA_INFO_LOG("V1_3::ICameraDevice::CastFrom failed");
    }
    MEDIA_INFO_LOG("CaptureSession::OpenSecureCamera secureSeqId = %{public}" PRIu64, *secureSeqId);
    return errCode;
}

int64_t HCameraDevice::GetSecureCameraSeq(uint64_t* secureSeqId)
{
    if (!isHasOpenSecure) {
        *secureSeqId = 0;
        return CAMERA_OK;
    }
    auto hdiCameraDeviceV1_3 = HDI::Camera::V1_3::ICameraDevice::CastFrom(hdiCameraDevice_);
    if (hdiCameraDeviceV1_3 != nullptr) {
        *secureSeqId = mSecureCameraSeqId;
        MEDIA_DEBUG_LOG("CaptureSession::GetSecureCameraSeq secureSeqId = %{public}" PRId64, *secureSeqId);
        return CAMERA_UNKNOWN_ERROR;
    }  else {
        MEDIA_INFO_LOG("V1_3::ICameraDevice::CastFrom failed");
    }
    return CAMERA_OK;
}

int32_t HCameraDevice::Close()
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(g_deviceOpenCloseMutex_);
    MEDIA_INFO_LOG("HCameraDevice::Close Closing camera device: %{public}s", cameraID_.c_str());
    int32_t result = CloseDevice();
    return result;
}

int32_t HCameraDevice::OpenDevice(bool isEnableSecCam)
{
    MEDIA_DEBUG_LOG("HCameraDevice::OpenDevice start");
    CAMERA_SYNC_TRACE;
    int32_t errorCode;
    MEDIA_INFO_LOG("HCameraDevice::OpenDevice Opening camera device: %{public}s", cameraID_.c_str());

    {
        bool canOpenDevice = CanOpenCamera();
        if (!canOpenDevice) {
            MEDIA_ERR_LOG("refuse to turning on the camera");
            return CAMERA_DEVICE_CONFLICT;
        }
        CameraReportUtils::GetInstance().SetOpenCamPerfStartInfo(cameraID_.c_str(), CameraReportUtils::GetCallerInfo());
        errorCode = cameraHostManager_->OpenCameraDevice(cameraID_, this, hdiCameraDevice_, isEnableSecCam);
        if (errorCode != CAMERA_OK) {
            MEDIA_ERR_LOG("HCameraDevice::OpenDevice Failed to open camera");
        } else {
            ResetHdiStreamId();
            isOpenedCameraDevice_.store(true);
            HCameraDeviceManager::GetInstance()->AddDevice(IPCSkeleton::GetCallingPid(), this);
        }
    }
    errorCode = InitStreamOperator();
    if (errorCode != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraDevice::OpenDevice InitStreamOperator fail err code is:%{public}d", errorCode);
    }
    std::lock_guard<std::mutex> lockSetting(opMutex_);
    if (hdiCameraDevice_ != nullptr) {
        cameraHostManager_->AddCameraDevice(cameraID_, this);
        if (updateSettings_ != nullptr) {
            std::vector<uint8_t> setting;
            OHOS::Camera::MetadataUtils::ConvertMetadataToVec(updateSettings_, setting);
            ReportMetadataDebugLog(updateSettings_);
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
    OpenDeviceNext();
    return errorCode;
}

void HCameraDevice::OpenDeviceNext()
{
    bool isFoldable = OHOS::Rosen::DisplayManager::GetInstance().IsFoldable();
    MEDIA_DEBUG_LOG("HCameraDevice::OpenDevice isFoldable is %d", isFoldable);
    if (isFoldable) {
        RegisterFoldStatusListener();
    }
    MEDIA_DEBUG_LOG("HCameraDevice::OpenDevice end");
    int pid = IPCSkeleton::GetCallingPid();
    int uid = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, clientUserId_);
    clientName_ = GetClientBundle(uid);
    POWERMGR_SYSEVENT_CAMERA_CONNECT(pid, uid, cameraID_.c_str(), clientName_);
    NotifyCameraSessionStatus(true);
}

int32_t HCameraDevice::CloseDevice()
{
    MEDIA_DEBUG_LOG("HCameraDevice::CloseDevice start");
    CAMERA_SYNC_TRACE;
    {
        std::lock_guard<std::mutex> lock(opMutex_);
        if (!isOpenedCameraDevice_.load()) {
            MEDIA_INFO_LOG("HCameraDevice::CloseDevice device has benn closed");
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
            ResetCachedSettings();
            ResetDeviceOpenLifeCycleSettings();
            HCameraDeviceManager::GetInstance()->RemoveDevice();
            MEDIA_INFO_LOG("Closing camera device: %{public}s end", cameraID_.c_str());
            hdiCameraDevice_ = nullptr;
        } else {
            MEDIA_INFO_LOG("hdiCameraDevice is null");
        }
        if (streamOperator_) {
            streamOperator_ = nullptr;
        }
        SetStreamOperatorCallback(nullptr);
    }
    if (cameraHostManager_) {
        cameraHostManager_->RemoveCameraDevice(cameraID_);
        cameraHostManager_->UpdateRestoreParamCloseTime(clientName_, cameraID_);
    }
    {
        std::lock_guard<std::mutex> lock(deviceSvcCbMutex_);
        deviceSvcCallback_ = nullptr;
    }
    POWERMGR_SYSEVENT_CAMERA_DISCONNECT(cameraID_.c_str());
    MEDIA_DEBUG_LOG("HCameraDevice::CloseDevice end");
    NotifyCameraSessionStatus(false);
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

void HCameraDevice::CheckZoomChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    int32_t ret;
    camera_metadata_item_t item;
    ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_PREPARE_ZOOM, &item);
    if (ret == CAM_META_SUCCESS) {
        if (item.data.u8[0] == OHOS_CAMERA_ZOOMSMOOTH_PREPARE_ENABLE) {
            MEDIA_ERR_LOG("OHOS_CAMERA_ZOOMSMOOTH_PREPARE_ENABLE");
            inPrepareZoom_ = true;
            ResetZoomTimer();
        } else if (item.data.u8[0] == OHOS_CAMERA_ZOOMSMOOTH_PREPARE_DISABLE) {
            MEDIA_ERR_LOG("OHOS_CAMERA_ZOOMSMOOTH_PREPARE_DISABLE");
            inPrepareZoom_ = false;
            ResetZoomTimer();
        }
        return;
    }
    ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_ZOOM_RATIO, &item);
    if (ret != CAM_META_SUCCESS) {
        ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_SMOOTH_ZOOM_RATIOS, &item);
    }
    if (ret == CAM_META_SUCCESS && inPrepareZoom_) {
        ResetZoomTimer();
    }
    return;
}

void HCameraDevice::ResetZoomTimer()
{
    CameraTimer::GetInstance()->Unregister(zoomTimerId_);
    if (!inPrepareZoom_) {
        return;
    }
    MEDIA_INFO_LOG("register zoom timer callback");
    uint32_t waitMs = 5 * 1000;
    zoomTimerId_ = CameraTimer::GetInstance()->Register([this]() { UnPrepareZoom(); }, waitMs, true);
}

void HCameraDevice::UnPrepareZoom()
{
    MEDIA_INFO_LOG("entered.");
    std::lock_guard<std::mutex> lock(unPrepareZoomMutex_);
    if (inPrepareZoom_) {
        inPrepareZoom_ = false;
        uint32_t count = 1;
        uint32_t prepareZoomType = OHOS_CAMERA_ZOOMSMOOTH_PREPARE_DISABLE;
        std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = std::make_shared<OHOS::Camera::CameraMetadata>(1, 1);
        metadata->addEntry(OHOS_CONTROL_PREPARE_ZOOM, &prepareZoomType, count);
        UpdateSetting(metadata);
    }
}

int32_t HCameraDevice::UpdateSetting(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraDevice::UpdateSetting prepare execute");
    if (settings == nullptr) {
        MEDIA_ERR_LOG("settings is null");
        return CAMERA_INVALID_ARG;
    }
    CheckZoomChange(settings);

    uint32_t count = OHOS::Camera::GetCameraMetadataItemCount(settings->get());
    if (!count) {
        MEDIA_DEBUG_LOG("Nothing to update");
        return CAMERA_OK;
    }
    std::lock_guard<std::mutex> lock(opMutex_);
    if (updateSettings_ != nullptr) {
        int ret = CameraFwkMetadataUtils::MergeMetadata(settings, updateSettings_);
        if (ret != CAMERA_OK) {
            return ret;
        }
    } else {
        updateSettings_ = settings;
    }
    MEDIA_INFO_LOG("Updated device settings  hdiCameraDevice_(%{public}d)", hdiCameraDevice_ != nullptr);
    if (hdiCameraDevice_ != nullptr) {
        std::vector<uint8_t> hdiSettings;
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(updateSettings_, hdiSettings);
        ReportMetadataDebugLog(updateSettings_);
        CamRetCode rc = (CamRetCode)(hdiCameraDevice_->UpdateSettings(hdiSettings));
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            MEDIA_ERR_LOG("Failed with error Code: %{public}d", rc);
            return HdiToServiceError(rc);
        }
        UpdateDeviceOpenLifeCycleSettings(updateSettings_);
        {
            std::lock_guard<std::mutex> cachedLock(cachedSettingsMutex_);
            CameraFwkMetadataUtils::MergeMetadata(settings, cachedSettings_);
        }
        updateSettings_ = nullptr;
    }
    MEDIA_INFO_LOG("HCameraDevice::UpdateSetting execute success");
    return CAMERA_OK;
}

int32_t HCameraDevice::UpdateSettingOnce(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraDevice::UpdateSettingOnce prepare execute");
    if (settings == nullptr) {
        MEDIA_ERR_LOG("settings is null");
        return CAMERA_INVALID_ARG;
    }
    CheckZoomChange(settings);

    uint32_t count = OHOS::Camera::GetCameraMetadataItemCount(settings->get());
    if (!count) {
        MEDIA_DEBUG_LOG("Nothing to update");
        return CAMERA_OK;
    }
    std::lock_guard<std::mutex> lock(opMutex_);
    MEDIA_INFO_LOG("Updated device settings once hdiCameraDevice_(%{public}d)", hdiCameraDevice_ != nullptr);
    if (hdiCameraDevice_ != nullptr) {
        std::vector<uint8_t> hdiSettings;
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(settings, hdiSettings);
        ReportMetadataDebugLog(settings);
        CamRetCode rc = (CamRetCode)(hdiCameraDevice_->UpdateSettings(hdiSettings));
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            MEDIA_ERR_LOG("Failed with error Code: %{public}d", rc);
            return HdiToServiceError(rc);
        }
    }
    MEDIA_INFO_LOG("HCameraDevice::UpdateSettingOnce execute success");
    return CAMERA_OK;
}

int32_t HCameraDevice::GetStatus(std::shared_ptr<OHOS::Camera::CameraMetadata> &metaIn,
    std::shared_ptr<OHOS::Camera::CameraMetadata> &metaOut)
{
    CAMERA_SYNC_TRACE;
    if (metaIn == nullptr) {
        MEDIA_ERR_LOG("HCameraDevice::GetStatus metaIn is null");
        return CAMERA_INVALID_ARG;
    }
    uint32_t count = OHOS::Camera::GetCameraMetadataItemCount(metaIn->get());
    if (!count) {
        MEDIA_DEBUG_LOG("HCameraDevice::GetStatus Nothing to query");
        return CAMERA_OK;
    }

    sptr<OHOS::HDI::Camera::V1_2::ICameraDevice> hdiCameraDeviceV1_2;
    if (cameraHostManager_->GetVersionByCamera(cameraID_) >= GetVersionId(HDI_VERSION_1, HDI_VERSION_2)) {
        MEDIA_DEBUG_LOG("HCameraDevice::GetStatus ICameraDevice cast to V1_2");
        hdiCameraDeviceV1_2 = OHOS::HDI::Camera::V1_2::ICameraDevice::CastFrom(hdiCameraDevice_);
        if (hdiCameraDeviceV1_2 == nullptr) {
            MEDIA_ERR_LOG("HCameraDevice::GetStatus ICameraDevice cast to V1_2 error");
            hdiCameraDeviceV1_2 = static_cast<OHOS::HDI::Camera::V1_2::ICameraDevice *>(hdiCameraDevice_.GetRefPtr());
        }
    }

    MEDIA_DEBUG_LOG("HCameraDevice::GetStatus hdiCameraDeviceV1_2(%{public}d)", hdiCameraDeviceV1_2 != nullptr);
    if (hdiCameraDeviceV1_2 != nullptr) {
        std::vector<uint8_t> hdiMetaIn;
        std::vector<uint8_t> hdiMetaOut;
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(metaIn, hdiMetaIn);
        CamRetCode rc = (CamRetCode)(hdiCameraDeviceV1_2->GetStatus(hdiMetaIn, hdiMetaOut));
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            MEDIA_ERR_LOG("HCameraDevice::GetStatus Failed with error Code: %{public}d", rc);
            return HdiToServiceError(rc);
        }
        if (hdiMetaOut.size() != 0) {
            OHOS::Camera::MetadataUtils::ConvertVecToMetadata(hdiMetaOut, metaOut);
        }
    }
    return CAMERA_OK;
}

void HCameraDevice::ReportMetadataDebugLog(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings)
{
    caller_ = CameraReportUtils::GetCallerInfo();
    DebugLogForZoom(settings, OHOS_CONTROL_ZOOM_RATIO);
    DebugLogForSmoothZoom(settings, OHOS_CONTROL_SMOOTH_ZOOM_RATIOS);
    DebugLogForVideoStabilizationMode(settings, OHOS_CONTROL_VIDEO_STABILIZATION_MODE);
    DebugLogForFilter(settings, OHOS_CONTROL_FILTER_TYPE);
    DebugLogForBeautySkinSmooth(settings, OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE);
    DebugLogForBeautyFaceSlender(settings, OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE);
    DebugLogForBeautySkinTone(settings, OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE);
    DebugLogForPortraitEffect(settings, OHOS_CONTROL_PORTRAIT_EFFECT_TYPE);
    DebugLogForFocusMode(settings, OHOS_CONTROL_FOCUS_MODE);
    DebugLogForAfRegions(settings, OHOS_CONTROL_AF_REGIONS);
    DebugLogForExposureMode(settings, OHOS_CONTROL_EXPOSURE_MODE);
    DebugLogForExposureTime(settings, OHOS_CONTROL_MANUAL_EXPOSURE_TIME);
    DebugLogForAeRegions(settings, OHOS_CONTROL_AE_REGIONS);
    DebugLogForAeExposureCompensation(settings, OHOS_CONTROL_AE_EXPOSURE_COMPENSATION);
    DebugLogForBeautyAuto(settings, OHOS_CONTROL_BEAUTY_AUTO_VALUE);
}

void HCameraDevice::DebugLogForZoom(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag)
{
    // debug log for zoom
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), tag, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_ZOOM_RATIO tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_ZOOM_RATIO value = %{public}f", item.data.f[0]);
        CameraReportUtils::GetInstance().ReportUserBehavior(DFX_UB_SET_ZOOMRATIO,
            std::to_string(item.data.f[0]), caller_);
    }
}

void HCameraDevice::DebugLogForSmoothZoom(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag)
{
    // debug log for smooth zoom
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), tag, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_SMOOTH_ZOOM_RATIOS tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_SMOOTH_ZOOM_RATIOS count = %{public}d", item.count);
        if (item.count > 1) {
            uint32_t targetZoom = item.data.ui32[item.count - 2];
            float zoomRatio = targetZoom / SMOOTH_ZOOM_DIVISOR;
            MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_SMOOTH_ZOOM_RATIOS value = %{public}f", zoomRatio);
            CameraReportUtils::GetInstance().ReportUserBehavior(DFX_UB_SET_SMOOTHZOOM,
                std::to_string(zoomRatio), caller_);
        }
    }
}

void HCameraDevice::DebugLogForVideoStabilizationMode(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
    uint32_t tag)
{
    // debug log for videoStabilization mode
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), tag, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_VIDEO_STABILIZATION_MODE tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_VIDEO_STABILIZATION_MODE value = %{public}d",
            item.data.u8[0]);
        CameraReportUtils::GetInstance().ReportUserBehavior(DFX_UB_SET_VIDEOSTABILIZATIONMODE,
            std::to_string(item.data.u8[0]), caller_);
    }
}

void HCameraDevice::DebugLogForFilter(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag)
{
    // debug log for filter
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), tag, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_FILTER_TYPE tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_FILTER_TYPE value = %{public}d", item.data.u8[0]);
        CameraReportUtils::GetInstance().ReportUserBehavior(DFX_UB_SET_FILTER,
            std::to_string(item.data.u8[0]), caller_);
    }
}

void HCameraDevice::DebugLogForBeautySkinSmooth(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
    uint32_t tag)
{
    // debug log for beauty skin smooth
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), tag, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE value = %{public}d",
            item.data.i32[0]);
        CameraReportUtils::GetInstance().ReportUserBehavior(DFX_UB_SET_BEAUTY_SKINSMOOTH,
            std::to_string(item.data.i32[0]), caller_);
    }
}

void HCameraDevice::DebugLogForBeautyFaceSlender(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
    uint32_t tag)
{
    // debug log for beauty face slender
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), tag, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE value = %{public}d",
            item.data.i32[0]);
        CameraReportUtils::GetInstance().ReportUserBehavior(DFX_UB_SET_BEAUTY_FACESLENDER,
            std::to_string(item.data.i32[0]), caller_);
    }
}

void HCameraDevice::DebugLogForBeautySkinTone(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
    uint32_t tag)
{
    // debug log for beauty skin tone
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), tag, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE value=%{public}d", item.data.i32[0]);
        CameraReportUtils::GetInstance().ReportUserBehavior(DFX_UB_SET_BEAUTY_SKINTONE,
            std::to_string(item.data.i32[0]), caller_);
    }
}

void HCameraDevice::DebugLogForPortraitEffect(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
    uint32_t tag)
{
    // debug log for portrait effect
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), tag, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_PORTRAIT_EFFECT_TYPE tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_PORTRAIT_EFFECT_TYPE value = %{public}d", item.data.u8[0]);
        CameraReportUtils::GetInstance().ReportUserBehavior(DFX_UB_SET_PORTRAITEFFECT,
            std::to_string(item.data.u8[0]), caller_);
    }
}

void HCameraDevice::DebugLogForFocusMode(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag)
{
    // debug log for focus mode
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), tag, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_FOCUS_MODE tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_FOCUS_MODE value = %{public}d", item.data.u8[0]);
        CameraReportUtils::GetInstance().ReportUserBehavior(DFX_UB_SET_FOCUSMODE,
            std::to_string(item.data.u8[0]), caller_);
    }
}

void HCameraDevice::DebugLogForAfRegions(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag)
{
    // debug log for af regions
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), tag, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_AF_REGIONS tag");
    } else {
        std::stringstream ss;
        ss << "x=" << item.data.f[0] << " y=" << item.data.f[1];
        std::string str = ss.str();
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_AF_REGIONS %{public}s", str.c_str());
        CameraReportUtils::GetInstance().ReportUserBehavior(DFX_UB_SET_FOCUSPOINT, str, caller_);
    }
}

void HCameraDevice::DebugLogForExposureMode(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
    uint32_t tag)
{
    // debug log for exposure mode
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), tag, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_EXPOSURE_MODE tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_EXPOSURE_MODE value = %{public}d", item.data.u8[0]);
        CameraReportUtils::GetInstance().ReportUserBehavior(DFX_UB_SET_EXPOSUREMODE,
            std::to_string(item.data.u8[0]), caller_);
    }
}

void HCameraDevice::DebugLogForExposureTime(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
    uint32_t tag)
{
    // debug log for exposure mode
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), tag, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_MANUAL_EXPOSURE_TIME tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_MANUAL_EXPOSURE_TIME value = %{public}d", item.data.ui32[0]);
    }
}

void HCameraDevice::DebugLogForAeRegions(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag)
{
    // debug log for ae regions
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), tag, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_AE_REGIONS tag");
    } else {
        std::stringstream ss;
        ss << "x=" << item.data.f[0] << " y=" << item.data.f[1];
        std::string str = ss.str();
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_AE_REGIONS %{public}s", str.c_str());
        CameraReportUtils::GetInstance().ReportUserBehavior(DFX_UB_SET_METERINGPOINT, str, caller_);
    }
}

void HCameraDevice::DebugLogForAeExposureCompensation(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
    uint32_t tag)
{
    // debug log for ae exposure compensation
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), tag, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_AE_EXPOSURE_COMPENSATION tag");
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::find OHOS_CONTROL_AE_EXPOSURE_COMPENSATION value = %{public}d",
            item.data.u8[0]);
        CameraReportUtils::GetInstance().ReportUserBehavior(DFX_UB_SET_EXPOSUREBIAS,
            std::to_string(item.data.u8[0]), caller_);
    }
}

void HCameraDevice::DebugLogForBeautyAuto(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag)
{
    // debug log for beauty auto value
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), tag, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_DEBUG_LOG("HCameraDevice::Failed to find OHOS_CONTROL_BEAUTY_AUTO_VALUE portraitEffect tag");
    } else {
        CameraReportUtils::GetInstance().ReportUserBehavior(DFX_UB_SET_BEAUTY_AUTOVALUE,
            std::to_string(item.data.i32[0]), caller_);
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

int32_t HCameraDevice::SetCallback(sptr<ICameraDeviceServiceCallback>& callback)
{
    if (callback == nullptr) {
        MEDIA_WARNING_LOG("HCameraDevice::SetCallback callback is null");
    }
    std::lock_guard<std::mutex> lock(deviceSvcCbMutex_);
    deviceSvcCallback_ = callback;
    return CAMERA_OK;
}

sptr<ICameraDeviceServiceCallback> HCameraDevice::GetDeviceServiceCallback()
{
    std::lock_guard<std::mutex> lock(deviceSvcCbMutex_);
    return deviceSvcCallback_;
}

void HCameraDevice::UpdateDeviceOpenLifeCycleSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> changedSettings)
{
    if (changedSettings == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(deviceOpenLifeCycleMutex_);
    for (auto itemTag : DEVICE_OPEN_LIFECYCLE_TAGS) {
        camera_metadata_item_t item;
        int32_t result = OHOS::Camera::FindCameraMetadataItem(changedSettings->get(), itemTag, &item);
        if (result != CAM_META_SUCCESS) {
            continue;
        }
        bool updateSuccess = CameraFwkMetadataUtils::UpdateMetadataTag(item, deviceOpenLifeCycleSettings_);
        if (!updateSuccess) {
            MEDIA_ERR_LOG("HCameraDevice::UpdateDeviceOpenLifeCycleSettings tag:%{public}d fail", itemTag);
        } else {
            MEDIA_INFO_LOG("HCameraDevice::UpdateDeviceOpenLifeCycleSettings tag:%{public}d success", itemTag);
        }
    }
}

void HCameraDevice::ResetDeviceOpenLifeCycleSettings()
{
    MEDIA_INFO_LOG("HCameraDevice::ResetDeviceOpenLifeCycleSettings");
    std::lock_guard<std::mutex> lock(deviceOpenLifeCycleMutex_);
    deviceOpenLifeCycleSettings_ =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEVICE_OPEN_LIFECYCLE_TAGS.size(), DEFAULT_SETTING_ITEM_LENGTH);
}

int32_t HCameraDevice::InitStreamOperator()
{
    std::lock_guard<std::mutex> lock(opMutex_);
    if (hdiCameraDevice_ == nullptr) {
        MEDIA_ERR_LOG("HCameraDevice::InitStreamOperator hdiCameraDevice_ is null");
        return CAMERA_UNKNOWN_ERROR;
    }
    CamRetCode rc;
    sptr<OHOS::HDI::Camera::V1_1::ICameraDevice> hdiCameraDeviceV1_1;
    sptr<OHOS::HDI::Camera::V1_2::ICameraDevice> hdiCameraDeviceV1_2;
    sptr<OHOS::HDI::Camera::V1_3::ICameraDevice> hdiCameraDeviceV1_3;
    int32_t versionRes = cameraHostManager_->GetVersionByCamera(cameraID_);
    if (versionRes >= GetVersionId(HDI_VERSION_1, HDI_VERSION_3)) {
        MEDIA_DEBUG_LOG("HCameraDevice::InitStreamOperator ICameraDevice cast to V1_3");
        hdiCameraDeviceV1_3 = OHOS::HDI::Camera::V1_3::ICameraDevice::CastFrom(hdiCameraDevice_);
    } else if (versionRes >= GetVersionId(HDI_VERSION_1, HDI_VERSION_2)) {
        MEDIA_DEBUG_LOG("HCameraDevice::InitStreamOperator ICameraDevice cast to V1_2");
        hdiCameraDeviceV1_2 = OHOS::HDI::Camera::V1_2::ICameraDevice::CastFrom(hdiCameraDevice_);
    } else if (versionRes == GetVersionId(HDI_VERSION_1, HDI_VERSION_1)) {
        MEDIA_DEBUG_LOG("HCameraDevice::InitStreamOperator ICameraDevice cast to V1_1");
        hdiCameraDeviceV1_1 = OHOS::HDI::Camera::V1_1::ICameraDevice::CastFrom(hdiCameraDevice_);
        if (hdiCameraDeviceV1_1 == nullptr) {
            MEDIA_ERR_LOG("HCameraDevice::InitStreamOperator ICameraDevice cast to V1_1 error");
            hdiCameraDeviceV1_1 = static_cast<OHOS::HDI::Camera::V1_1::ICameraDevice*>(hdiCameraDevice_.GetRefPtr());
        }
    }

    if (hdiCameraDeviceV1_3 != nullptr && versionRes >= GetVersionId(HDI_VERSION_1, HDI_VERSION_3)) {
        sptr<OHOS::HDI::Camera::V1_2::IStreamOperator> streamOperator_v1_2;
        rc = (CamRetCode)(hdiCameraDeviceV1_3->GetStreamOperator_V1_3(this, streamOperator_v1_2));
        streamOperator_ = streamOperator_v1_2;
    } else if (hdiCameraDeviceV1_2 != nullptr && versionRes >= GetVersionId(HDI_VERSION_1, HDI_VERSION_2)) {
        MEDIA_DEBUG_LOG("HCameraDevice::InitStreamOperator ICameraDevice V1_2");
        sptr<OHOS::HDI::Camera::V1_2::IStreamOperator> streamOperator_v1_2;
        rc = (CamRetCode)(hdiCameraDeviceV1_2->GetStreamOperator_V1_2(this, streamOperator_v1_2));
        streamOperator_ = streamOperator_v1_2;
    } else if (hdiCameraDeviceV1_1 != nullptr && versionRes == GetVersionId(HDI_VERSION_1, HDI_VERSION_1)) {
        MEDIA_DEBUG_LOG("HCameraDevice::InitStreamOperator ICameraDevice V1_1");
        sptr<OHOS::HDI::Camera::V1_1::IStreamOperator> streamOperator_v1_1;
        rc = (CamRetCode)(hdiCameraDeviceV1_1->GetStreamOperator_V1_1(this, streamOperator_v1_1));
        streamOperator_ = streamOperator_v1_1;
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::InitStreamOperator ICameraDevice V1_0");
        rc = (CamRetCode)(hdiCameraDevice_->GetStreamOperator(this, streamOperator_));
    }
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        MEDIA_ERR_LOG("HCameraDevice::InitStreamOperator failed with error Code:%{public}d", rc);
        CameraReportUtils::ReportCameraError(
            "HCameraDevice::InitStreamOperator", rc, true, CameraReportUtils::GetCallerInfo());
        streamOperator_ = nullptr;
        return HdiToServiceError(rc);
    }
    return CAMERA_OK;
}

int32_t HCameraDevice::ReleaseStreams(std::vector<int32_t>& releaseStreamIds)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(opMutex_);
    if (streamOperator_ != nullptr && !releaseStreamIds.empty()) {
        MEDIA_INFO_LOG("HCameraDevice::ReleaseStreams %{public}s",
            Container2String(releaseStreamIds.begin(), releaseStreamIds.end()).c_str());
        int32_t rc = streamOperator_->ReleaseStreams(releaseStreamIds);
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            MEDIA_ERR_LOG("HCameraDevice::ClearStreamOperator ReleaseStreams fail, error Code:%{public}d", rc);
            CameraReportUtils::ReportCameraError(
                "HCameraDevice::ReleaseStreams", rc, true, CameraReportUtils::GetCallerInfo());
        }
    }
    return CAMERA_OK;
}

sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> HCameraDevice::GetStreamOperator()
{
    std::lock_guard<std::mutex> lock(opMutex_);
    return streamOperator_;
}

int32_t HCameraDevice::OnError(const OHOS::HDI::Camera::V1_0::ErrorType type, const int32_t errorMsg)
{
    auto callback = GetDeviceServiceCallback();
    if (callback != nullptr) {
        int32_t errorType;
        if (type == OHOS::HDI::Camera::V1_0::REQUEST_TIMEOUT) {
            errorType = CAMERA_DEVICE_REQUEST_TIMEOUT;
        } else if (type == OHOS::HDI::Camera::V1_0::DEVICE_PREEMPT) {
            errorType = CAMERA_DEVICE_PREEMPTED;
        } else {
            errorType = CAMERA_UNKNOWN_ERROR;
        }
        callback->OnError(errorType, errorMsg);
        CAMERA_SYSEVENT_FAULT(CreateMsg("CameraDeviceServiceCallback::OnError() is called!, errorType: %d,"
                                        "errorMsg: %d",
            errorType, errorMsg));
    }
    return CAMERA_OK;
}

void HCameraDevice::CheckOnResultData(std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult)
{
    if (cameraResult != nullptr) {
        camera_metadata_item_t item;
        common_metadata_header_t* metadata = cameraResult->get();
        int ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FLASH_MODE, &item);
        if (ret == 0) {
            MEDIA_DEBUG_LOG(
                "CameraDeviceServiceCallback::OnResult() OHOS_CONTROL_FLASH_MODE is %{public}d", item.data.u8[0]);
        }
        ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FLASH_STATE, &item);
        if (ret == 0) {
            MEDIA_DEBUG_LOG(
                "CameraDeviceServiceCallback::OnResult() OHOS_CONTROL_FLASH_STATE is %{public}d", item.data.u8[0]);
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
        }
        MEDIA_DEBUG_LOG("ProcessFaceRectangles: %{public}d count: %{public}d", item.item, item.count);
        constexpr int32_t rectangleUnitLen = 4;

        if (item.count % rectangleUnitLen) {
            MEDIA_DEBUG_LOG("Metadata item: %{public}d count: %{public}d is invalid", item.item, item.count);
        }
        const int32_t offsetX = 0;
        const int32_t offsetY = 1;
        const int32_t offsetW = 2;
        const int32_t offsetH = 3;
        float* start = item.data.f;
        float* end = item.data.f + item.count;
        for (; start < end; start += rectangleUnitLen) {
            MEDIA_DEBUG_LOG("Metadata item: %{public}f,%{public}f,%{public}f,%{public}f", start[offsetX],
                start[offsetY], start[offsetW], start[offsetH]);
        }
    } else {
        MEDIA_ERR_LOG("HCameraDevice::OnResult cameraResult is nullptr");
    }
}

int32_t HCameraDevice::OnResult(const uint64_t timestamp, const std::vector<uint8_t>& result)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult = nullptr;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(result, cameraResult);
    if (IsCameraDebugOn()) {
        CameraFwkMetadataUtils::DumpMetadataInfo(cameraResult);
    }
    auto callback = GetDeviceServiceCallback();
    if (callback != nullptr) {
        callback->OnResult(timestamp, cameraResult);
    }
    if (IsCameraDebugOn()) {
        CheckOnResultData(cameraResult);
    }
    return CAMERA_OK;
}

int32_t HCameraDevice::GetCallerToken()
{
    return callerToken_;
}

int32_t HCameraDevice::CreateStreams(std::vector<HDI::Camera::V1_1::StreamInfo_V1_1>& streamInfos)
{
    CamRetCode hdiRc = HDI::Camera::V1_0::NO_ERROR;
    uint32_t major;
    uint32_t minor;
    if (streamInfos.empty()) {
        MEDIA_WARNING_LOG("HCameraDevice::CreateStreams streamInfos is empty!");
        return CAMERA_OK;
    }
    std::lock_guard<std::mutex> lock(opMutex_);
    sptr<OHOS::HDI::Camera::V1_1::IStreamOperator> streamOperatorV1_1;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator = streamOperator_;
    if (streamOperator == nullptr) {
        MEDIA_ERR_LOG("HCameraDevice::CreateStreams GetStreamOperator is null!");
        return CAMERA_UNKNOWN_ERROR;
    }
    // get higher streamOperator version
    streamOperator->GetVersion(major, minor);
    MEDIA_INFO_LOG("streamOperator GetVersion major:%{public}d, minor:%{public}d", major, minor);
    if (major >= HDI_VERSION_1 && minor >= HDI_VERSION_1) {
        streamOperatorV1_1 = OHOS::HDI::Camera::V1_1::IStreamOperator::CastFrom(streamOperator);
        if (streamOperatorV1_1 == nullptr) {
            MEDIA_ERR_LOG("HCameraDevice::CreateStreams IStreamOperator cast to V1_1 error");
            streamOperatorV1_1 = static_cast<OHOS::HDI::Camera::V1_1::IStreamOperator*>(streamOperator.GetRefPtr());
        }
    }
    if (streamOperatorV1_1 != nullptr) {
        MEDIA_INFO_LOG("HCameraDevice::CreateStreams streamOperator V1_1");
        for (auto streamInfo : streamInfos) {
            if (streamInfo.extendedStreamInfos.size() > 0) {
                MEDIA_INFO_LOG("HCameraDevice::CreateStreams streamOperator V1_1 type %{public}d",
                    streamInfo.extendedStreamInfos[0].type);
            }
        }
        hdiRc = (CamRetCode)(streamOperatorV1_1->CreateStreams_V1_1(streamInfos));
    } else {
        MEDIA_INFO_LOG("HCameraDevice::CreateStreams streamOperator V1_0");
        std::vector<StreamInfo> streamInfos_V1_0;
        for (auto streamInfo : streamInfos) {
            streamInfos_V1_0.emplace_back(streamInfo.v1_0);
        }
        hdiRc = (CamRetCode)(streamOperator->CreateStreams(streamInfos_V1_0));
    }
    if (hdiRc != HDI::Camera::V1_0::NO_ERROR) {
        MEDIA_ERR_LOG("HCameraDevice::CreateStreams(), Failed to commit %{public}d", hdiRc);
        CameraReportUtils::ReportCameraError(
            "HCameraDevice::CreateStreams", hdiRc, true, CameraReportUtils::GetCallerInfo());
        std::vector<int32_t> streamIds;
        for (auto& streamInfo : streamInfos) {
            streamIds.emplace_back(streamInfo.v1_0.streamId_);
        }
        if (!streamIds.empty() && streamOperator->ReleaseStreams(streamIds) != HDI::Camera::V1_0::NO_ERROR) {
            MEDIA_ERR_LOG("HCameraDevice::CreateStreams(), Failed to release streams");
        }
    }
    for (auto& info : streamInfos) {
        MEDIA_INFO_LOG("HCameraDevice::CreateStreams stream id is:%{public}d", info.v1_0.streamId_);
    }
    return HdiToServiceError(hdiRc);
}

int32_t HCameraDevice::CommitStreams(
    std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceSettings, int32_t operationMode)
{
    CamRetCode hdiRc = HDI::Camera::V1_0::NO_ERROR;
    uint32_t major;
    uint32_t minor;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator;
    sptr<OHOS::HDI::Camera::V1_1::IStreamOperator> streamOperatorV1_1;
    std::lock_guard<std::mutex> lock(opMutex_);
    streamOperator = streamOperator_;
    if (streamOperator == nullptr) {
        MEDIA_ERR_LOG("HCameraDevice::CommitStreams GetStreamOperator is null!");
        return CAMERA_UNKNOWN_ERROR;
    }
    // get higher streamOperator version
    streamOperator->GetVersion(major, minor);
    MEDIA_INFO_LOG(
        "HCameraDevice::CommitStreams streamOperator GetVersion major:%{public}d, minor:%{public}d", major, minor);
    if (major >= HDI_VERSION_1 && minor >= HDI_VERSION_1) {
        MEDIA_DEBUG_LOG("HCameraDevice::CommitStreams IStreamOperator cast to V1_1");
        streamOperatorV1_1 = OHOS::HDI::Camera::V1_1::IStreamOperator::CastFrom(streamOperator);
        if (streamOperatorV1_1 == nullptr) {
            MEDIA_ERR_LOG("HCameraDevice::CommitStreams IStreamOperator cast to V1_1 error");
            streamOperatorV1_1 = static_cast<OHOS::HDI::Camera::V1_1::IStreamOperator*>(streamOperator.GetRefPtr());
        }
    }

    std::vector<uint8_t> setting;
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(deviceSettings, setting);
    MEDIA_INFO_LOG("HCameraDevice::CommitStreams, commit mode %{public}d", operationMode);
    if (streamOperatorV1_1 != nullptr) {
        MEDIA_DEBUG_LOG("HCameraDevice::CommitStreams IStreamOperator V1_1");
        hdiRc = (CamRetCode)(streamOperatorV1_1->CommitStreams_V1_1(
            static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(operationMode), setting));
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::CommitStreams IStreamOperator V1_0");
        OperationMode opMode = OperationMode::NORMAL;
        hdiRc = (CamRetCode)(streamOperator->CommitStreams(opMode, setting));
    }
    if (hdiRc != HDI::Camera::V1_0::NO_ERROR) {
        MEDIA_ERR_LOG("HCameraDevice::CommitStreams failed with error Code:%d", hdiRc);
        CameraReportUtils::ReportCameraError(
            "HCameraDevice::CommitStreams", hdiRc, true, CameraReportUtils::GetCallerInfo());
    }
    MEDIA_DEBUG_LOG("HCameraDevice::CommitStreams end");
    return HdiToServiceError(hdiRc);
}

int32_t HCameraDevice::CreateAndCommitStreams(std::vector<HDI::Camera::V1_1::StreamInfo_V1_1>& streamInfos,
    std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceSettings, int32_t operationMode)
{
    int retCode = CreateStreams(streamInfos);
    if (retCode != CAMERA_OK) {
        return retCode;
    }
    return CommitStreams(deviceSettings, operationMode);
}

bool HCameraDevice::CanOpenCamera()
{
    sptr<HCameraDevice> cameraNeedEvict;
    bool ret = HCameraDeviceManager::GetInstance()->GetConflictDevices(cameraNeedEvict, this);
    if (cameraNeedEvict != nullptr) {
        MEDIA_DEBUG_LOG("HCameraDevice::CanOpenCamera open current device need to close other devices");
        cameraNeedEvict->OnError(DEVICE_PREEMPT, 0);
        cameraNeedEvict->CloseDevice();
    }
    return ret;
}

int32_t HCameraDevice::UpdateStreams(std::vector<StreamInfo_V1_1>& streamInfos)
{
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator;
    sptr<OHOS::HDI::Camera::V1_2::IStreamOperator> streamOperatorV1_2;
    streamOperator = GetStreamOperator();
    if (streamOperator == nullptr) {
        MEDIA_ERR_LOG("HCaptureSession::UpdateStreamInfos GetStreamOperator is null!");
        return CAMERA_UNKNOWN_ERROR;
    }

    uint32_t major;
    uint32_t minor;
    streamOperator->GetVersion(major, minor);
    MEDIA_INFO_LOG("UpdateStreamInfos: streamOperator GetVersion major:%{public}d, minor:%{public}d", major, minor);
    if (major >= HDI_VERSION_1 && minor >= HDI_VERSION_2) {
        streamOperatorV1_2 = OHOS::HDI::Camera::V1_2::IStreamOperator::CastFrom(streamOperator);
        if (streamOperatorV1_2 == nullptr) {
            MEDIA_ERR_LOG("HCaptureSession::UpdateStreamInfos IStreamOperator cast to V1_2 error");
            streamOperatorV1_2 = static_cast<OHOS::HDI::Camera::V1_2::IStreamOperator*>(streamOperator.GetRefPtr());
        }
    }
    CamRetCode hdiRc = HDI::Camera::V1_0::CamRetCode::NO_ERROR;
    if (streamOperatorV1_2 != nullptr) {
        MEDIA_DEBUG_LOG("HCaptureSession::UpdateStreamInfos streamOperator V1_2");
        hdiRc = (CamRetCode)(streamOperatorV1_2->UpdateStreams(streamInfos));
    } else {
        MEDIA_DEBUG_LOG("HCaptureSession::UpdateStreamInfos failed, streamOperator V1_2 is null.");
        return CAMERA_UNKNOWN_ERROR;
    }
    return HdiToServiceError(hdiRc);
}

int32_t HCameraDevice::OperatePermissionCheck(uint32_t interfaceCode)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t errCode = CheckPermission(OHOS_PERMISSION_CAMERA, callerToken);
    if (errCode != CAMERA_OK) {
        return errCode;
    }
    switch (static_cast<CameraDeviceInterfaceCode>(interfaceCode)) {
        case CameraDeviceInterfaceCode::CAMERA_DEVICE_OPEN:
        case CameraDeviceInterfaceCode::CAMERA_DEVICE_CLOSE:
        case CameraDeviceInterfaceCode::CAMERA_DEVICE_RELEASE:
        case CameraDeviceInterfaceCode::CAMERA_DEVICE_SET_CALLBACK:
        case CameraDeviceInterfaceCode::CAMERA_DEVICE_UPDATE_SETTNGS:
        case CameraDeviceInterfaceCode::CAMERA_DEVICE_GET_ENABLED_RESULT:
        case CameraDeviceInterfaceCode::CAMERA_DEVICE_ENABLED_RESULT:
        case CameraDeviceInterfaceCode::CAMERA_DEVICE_DISABLED_RESULT: {
            if (callerToken_ != callerToken) {
                MEDIA_ERR_LOG("HCameraDevice::OperatePermissionCheck fail, callerToken_ is : %{public}d, now token "
                              "is %{public}d",
                    callerToken_, callerToken);
                return CAMERA_OPERATION_NOT_ALLOWED;
            }
            break;
        }
        default:
            break;
    }
    return CAMERA_OK;
}

int32_t HCameraDevice::OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds)
{
    auto streamOperatorCallback = GetStreamOperatorCallback();
    if (streamOperatorCallback == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    return streamOperatorCallback->OnCaptureStarted(captureId, streamIds);
}

int32_t HCameraDevice::OnCaptureStarted_V1_2(
    int32_t captureId, const std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo>& infos)
{
    auto streamOperatorCallback = GetStreamOperatorCallback();
    if (streamOperatorCallback == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    return streamOperatorCallback->OnCaptureStarted_V1_2(captureId, infos);
}

int32_t HCameraDevice::OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos)
{
    auto streamOperatorCallback = GetStreamOperatorCallback();
    if (streamOperatorCallback == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    return streamOperatorCallback->OnCaptureEnded(captureId, infos);
}

int32_t HCameraDevice::OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos)
{
    auto streamOperatorCallback = GetStreamOperatorCallback();
    if (streamOperatorCallback == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    return streamOperatorCallback->OnCaptureError(captureId, infos);
}

int32_t HCameraDevice::OnFrameShutter(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp)
{
    auto streamOperatorCallback = GetStreamOperatorCallback();
    if (streamOperatorCallback == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    return streamOperatorCallback->OnFrameShutter(captureId, streamIds, timestamp);
}

int32_t HCameraDevice::OnFrameShutterEnd(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp)
{
    auto streamOperatorCallback = GetStreamOperatorCallback();
    if (streamOperatorCallback == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    return streamOperatorCallback->OnFrameShutterEnd(captureId, streamIds, timestamp);
}

int32_t HCameraDevice::OnCaptureReady(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp)
{
    auto streamOperatorCallback = GetStreamOperatorCallback();
    if (streamOperatorCallback == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    return streamOperatorCallback->OnCaptureReady(captureId, streamIds, timestamp);
}

void HCameraDevice::NotifyCameraSessionStatus(bool running)
{
    bool isSystemCamera = (clientName_ == "com.huawei.hmos.camera") ? true : false;
    DeferredProcessing::DeferredProcessingService::GetInstance().NotifyCameraSessionStatus(clientUserId_, cameraID_,
        running, isSystemCamera);
    return;
}

void HCameraDevice::RemoveResourceWhenHostDied()
{
    MEDIA_DEBUG_LOG("HCameraDevice::RemoveResourceWhenHostDied start");
    CAMERA_SYNC_TRACE;
    bool isFoldable = OHOS::Rosen::DisplayManager::GetInstance().IsFoldable();
    if (isFoldable) {
        UnRegisterFoldStatusListener();
    }
    HCameraDeviceManager::GetInstance()->RemoveDevice();
    if (cameraHostManager_) {
        cameraHostManager_->RemoveCameraDevice(cameraID_);
        cameraHostManager_->UpdateRestoreParamCloseTime(clientName_, cameraID_);
    }
    POWERMGR_SYSEVENT_CAMERA_DISCONNECT(cameraID_.c_str());
    NotifyCameraSessionStatus(false);
    MEDIA_DEBUG_LOG("HCameraDevice::RemoveResourceWhenHostDied end");
}
} // namespace CameraStandard
} // namespace OHOS
