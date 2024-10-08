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
#include "common_event_manager.h"
#include "common_event_support.h"
#include "common_event_data.h"
#include "want.h"

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

const std::vector<std::tuple<uint32_t, std::string, std::string>> HCameraDevice::reportTagInfos_ = {
    {OHOS_CONTROL_FLASH_MODE, "OHOS_CONTROL_FLASH_MODE", DFX_UB_SET_FLASHMODE},
    {OHOS_CONTROL_FOCUS_MODE, "OHOS_CONTROL_FOCUS_MODE", DFX_UB_SET_FOCUSMODE},
    {OHOS_CONTROL_EXPOSURE_MODE, "OHOS_CONTROL_EXPOSURE_MODE", DFX_UB_SET_EXPOSUREMODE},
    {OHOS_CONTROL_VIDEO_STABILIZATION_MODE, "OHOS_CONTROL_VIDEO_STABILIZATION_MODE", DFX_UB_SET_VIDEOSTABILIZATIONMODE},
    {OHOS_CONTROL_FILTER_TYPE, "OHOS_CONTROL_FILTER_TYPE", DFX_UB_SET_FILTER},
    {OHOS_CONTROL_PORTRAIT_EFFECT_TYPE, "OHOS_CONTROL_PORTRAIT_EFFECT_TYPE", DFX_UB_SET_PORTRAITEFFECT},
    {OHOS_CONTROL_BEAUTY_AUTO_VALUE, "OHOS_CONTROL_BEAUTY_AUTO_VALUE", DFX_UB_SET_BEAUTY_AUTOVALUE},
    {OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE, "OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE", DFX_UB_SET_BEAUTY_SKINSMOOTH},
    {OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE, "OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE", DFX_UB_SET_BEAUTY_FACESLENDER},
    {OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE, "OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE", DFX_UB_SET_BEAUTY_SKINTONE},
    {OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, "OHOS_CONTROL_AE_EXPOSURE_COMPENSATION", DFX_UB_SET_EXPOSUREBIAS},
    {OHOS_CONTROL_FPS_RANGES, "OHOS_CONTROL_FPS_RANGES", DFX_UB_SET_FRAMERATERANGE},
    {OHOS_CONTROL_ZOOM_RATIO, "OHOS_CONTROL_ZOOM_RATIO", DFX_UB_SET_ZOOMRATIO},
    {OHOS_CONTROL_BEAUTY_TYPE, "OHOS_CONTROL_BEAUTY_TYPE", DFX_UB_NOT_REPORT},
    {OHOS_CONTROL_LIGHT_PAINTING_TYPE, "OHOS_CONTROL_LIGHT_PAINTING_TYPE", DFX_UB_NOT_REPORT},
    {OHOS_CONTROL_LIGHT_PAINTING_FLASH, "OHOS_CONTROL_LIGHT_PAINTING_FLASH", DFX_UB_NOT_REPORT},
    {OHOS_CONTROL_MANUAL_EXPOSURE_TIME, "OHOS_CONTROL_MANUAL_EXPOSURE_TIME", DFX_UB_NOT_REPORT},
<<<<<<< HEAD
=======
    {OHOS_CONTROL_CAMERA_USED_AS_POSITION, "OHOS_CONTROL_CAMERA_USED_AS_POSITION", DFX_UB_NOT_REPORT},
>>>>>>> be4e4526 (后置自拍预览未镜像)
};

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
    sptr<CameraPrivacy> cameraPrivacy = new CameraPrivacy(this, callingTokenId, IPCSkeleton::GetCallingPid());
    SetCameraPrivacy(cameraPrivacy);
}

HCameraDevice::~HCameraDevice()
{
    UnPrepareZoom();
    CameraTimer::GetInstance()->Unregister(zoomTimerId_);
    CameraTimer::GetInstance()->DecreaseUserCount();
    SetCameraPrivacy(nullptr);
    MEDIA_INFO_LOG("HCameraDevice::~HCameraDevice Destructor Camera: %{public}s", cameraID_.c_str());
}

std::string HCameraDevice::GetCameraId()
{
    return cameraID_;
}

int32_t HCameraDevice::GetCameraType()
{
    if (clientName_ == SYSTEM_CAMERA) {
        return SYSTEM;
    }
    return OTHER;
}

bool HCameraDevice::IsOpenedCameraDevice()
{
    return isOpenedCameraDevice_.load();
}

void HCameraDevice::SetDeviceMuteMode(bool muteMode)
{
    deviceMuteMode_ = muteMode;
}

bool HCameraDevice::GetDeviceMuteMode()
{
    return deviceMuteMode_;
}

void HCameraDevice::CreateMuteSetting(std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    constexpr int32_t DEFAULT_ITEMS = 1;
    constexpr int32_t DEFAULT_DATA_LENGTH = 1;
    int32_t count = 1;
    uint8_t mode = OHOS_CAMERA_MUTE_MODE_SOLID_COLOR_BLACK;
    settings = std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    settings->addEntry(OHOS_CONTROL_MUTE_MODE, &mode, count);
}

int32_t HCameraDevice::ResetDeviceSettings()
{
    CAMERA_SYNC_TRACE;
    sptr<OHOS::HDI::Camera::V1_2::ICameraDevice> hdiCameraDeviceV1_2;
    MEDIA_INFO_LOG("HCameraDevice::ResetDeviceSettings enter");
    {
        std::lock_guard<std::mutex> lock(opMutex_);
        CHECK_ERROR_RETURN_RET(hdiCameraDevice_ == nullptr, CAMERA_OK);
        hdiCameraDeviceV1_2 = HDI::Camera::V1_2::ICameraDevice::CastFrom(hdiCameraDevice_);
    }
    if (hdiCameraDeviceV1_2 != nullptr) {
        int32_t errCode = hdiCameraDeviceV1_2->Reset();
        CHECK_ERROR_RETURN_RET_LOG(errCode != HDI::Camera::V1_0::CamRetCode::NO_ERROR, CAMERA_UNKNOWN_ERROR,
            "HCameraDevice::ResetDeviceSettings occur error");
        ResetCachedSettings();
        if (deviceMuteMode_) {
            std::shared_ptr<OHOS::Camera::CameraMetadata> settings = nullptr;
            CreateMuteSetting(settings);
            UpdateSetting(settings);
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
    CHECK_ERROR_RETURN_RET(hdiCameraDevice_ == nullptr, CAMERA_INVALID_STATE);
    std::vector<uint8_t> hdiMetadata;
    bool isSuccess = OHOS::Camera::MetadataUtils::ConvertMetadataToVec(lifeCycleSettings, hdiMetadata);
    CHECK_ERROR_RETURN_RET_LOG(!isSuccess, CAMERA_UNKNOWN_ERROR,
        "HCameraDevice::DispatchDefaultSettingToHdi metadata ConvertMetadataToVec fail");
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
    CHECK_ERROR_RETURN_RET(deviceAbility_ != nullptr, deviceAbility_);
    int32_t errCode = cameraHostManager_->GetCameraAbility(cameraID_, deviceAbility_);
    CHECK_ERROR_RETURN_RET_LOG(errCode != CAMERA_OK, nullptr,
        "HCameraDevice::GetSettings Failed to get Camera Ability: %{public}d", errCode);
    return deviceAbility_;
}

int32_t HCameraDevice::Open()
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(g_deviceOpenCloseMutex_);
    CHECK_ERROR_PRINT_LOG(isOpenedCameraDevice_.load(), "HCameraDevice::Open failed, camera is busy");
    CHECK_ERROR_RETURN_RET_LOG(!IsInForeGround(callerToken_), CAMERA_ALLOC_ERROR,
        "HCameraDevice::Open IsAllowedUsingPermission failed");
    MEDIA_INFO_LOG("HCameraDevice::Open Camera:[%{public}s", cameraID_.c_str());
    int32_t result = OpenDevice();
    return result;
}

int32_t HCameraDevice::OpenSecureCamera(uint64_t* secureSeqId)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(g_deviceOpenCloseMutex_);
    CHECK_ERROR_PRINT_LOG(isOpenedCameraDevice_.load(), "HCameraDevice::Open failed, camera is busy");
    CHECK_ERROR_RETURN_RET_LOG(!IsInForeGround(callerToken_), CAMERA_ALLOC_ERROR,
        "HCameraDevice::Open IsAllowedUsingPermission failed");
    MEDIA_INFO_LOG("HCameraDevice::OpenSecureCamera Camera:[%{public}s", cameraID_.c_str());
    int32_t errCode = OpenDevice(true);
    auto hdiCameraDeviceV1_3 = HDI::Camera::V1_3::ICameraDevice::CastFrom(hdiCameraDevice_);
    if (hdiCameraDeviceV1_3 != nullptr) {
        errCode = hdiCameraDeviceV1_3->GetSecureCameraSeq(*secureSeqId);
        CHECK_ERROR_RETURN_RET_LOG(errCode != HDI::Camera::V1_0::CamRetCode::NO_ERROR, CAMERA_UNKNOWN_ERROR,
            "HCameraDevice::GetSecureCameraSeq occur error");
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
    MEDIA_INFO_LOG("HCameraDevice::OpenDevice start cameraId: %{public}s", cameraID_.c_str());
    CAMERA_SYNC_TRACE;
    int32_t errorCode = CheckPermissionBeforeOpenDevice();
    CHECK_AND_RETURN_RET(errorCode == CAMERA_OK, errorCode);
    bool canOpenDevice = CanOpenCamera();
    CHECK_ERROR_RETURN_RET_LOG(!canOpenDevice, CAMERA_DEVICE_CONFLICT, "HCameraDevice::Refuse to turn on the camera");
    CHECK_ERROR_RETURN_RET_LOG(!HandlePrivacyBeforeOpenDevice(), CAMERA_OPERATION_NOT_ALLOWED, "privacy not allow!");
    CameraReportUtils::GetInstance().SetOpenCamPerfStartInfo(cameraID_.c_str(), CameraReportUtils::GetCallerInfo());
    errorCode = cameraHostManager_->OpenCameraDevice(cameraID_, this, hdiCameraDevice_, isEnableSecCam);
    if (errorCode != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraDevice::OpenDevice Failed to open camera");
    } else {
        ResetHdiStreamId();
        isOpenedCameraDevice_.store(true);
        HCameraDeviceManager::GetInstance()->AddDevice(IPCSkeleton::GetCallingPid(), this);
    }
    errorCode = InitStreamOperator();
    CHECK_ERROR_PRINT_LOG(errorCode != CAMERA_OK,
        "HCameraDevice::OpenDevice InitStreamOperator fail err code is:%{public}d", errorCode);
    std::lock_guard<std::mutex> lockSetting(opMutex_);
    if (hdiCameraDevice_ != nullptr) {
        cameraHostManager_->AddCameraDevice(cameraID_, this);
        if (updateSettings_ != nullptr || deviceMuteMode_) {
            if (deviceMuteMode_) {
                CreateMuteSetting(updateSettings_);
            }
            errorCode = UpdateDeviceSetting();
            CHECK_AND_RETURN_RET(errorCode == CAMERA_OK, errorCode);
            errorCode = HdiToServiceError((CamRetCode)(hdiCameraDevice_->SetResultMode(ON_CHANGED)));
        }
    }
    HandleFoldableDevice();
    int pid = IPCSkeleton::GetCallingPid();
    int uid = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, clientUserId_);
    clientName_ = GetClientBundle(uid);
    POWERMGR_SYSEVENT_CAMERA_CONNECT(pid, uid, cameraID_.c_str(), clientName_);
    NotifyCameraSessionStatus(true);
    NotifyCameraStatus(CAMERA_OPEN);
    MEDIA_INFO_LOG("HCameraDevice::OpenDevice end cameraId: %{public}s", cameraID_.c_str());
    return errorCode;
}

int32_t HCameraDevice::CheckPermissionBeforeOpenDevice()
{
    MEDIA_DEBUG_LOG("enter checkPermissionBeforeOpenDevice");
    if (IsHapTokenId(callerToken_)) {
        auto cameraPrivacy = GetCameraPrivacy();
        CHECK_ERROR_RETURN_RET_LOG(cameraPrivacy == nullptr, CAMERA_OPERATION_NOT_ALLOWED, "cameraPrivacy is null");
        CHECK_ERROR_RETURN_RET_LOG(!cameraPrivacy->IsAllowUsingCamera(), CAMERA_OPERATION_NOT_ALLOWED,
            "OpenDevice is not allowed!");
    }
    return CAMERA_OK;
}

bool HCameraDevice::HandlePrivacyBeforeOpenDevice()
{
    MEDIA_DEBUG_LOG("enter HandlePrivacyBeforeOpenDevice");
    CHECK_ERROR_RETURN_RET_LOG(!IsHapTokenId(callerToken_), true, "system ability called not need privacy");
    auto cameraPrivacy = GetCameraPrivacy();
    CHECK_ERROR_RETURN_RET_LOG(cameraPrivacy == nullptr, false, "cameraPrivacy is null");
    CHECK_ERROR_RETURN_RET_LOG(!cameraPrivacy->StartUsingPermissionCallback(), false, "start using permission failed");
    CHECK_ERROR_RETURN_RET_LOG(!cameraPrivacy->RegisterPermissionCallback(), false, "register permission failed");
    CHECK_ERROR_RETURN_RET_LOG(!cameraPrivacy->AddCameraPermissionUsedRecord(), false, "add permission record failed");
    return true;
}

void HCameraDevice::HandlePrivacyAfterCloseDevice()
{
    MEDIA_DEBUG_LOG("enter handlePrivacyAfterCloseDevice");
    auto cameraPrivacy = GetCameraPrivacy();
    if (cameraPrivacy != nullptr) {
        cameraPrivacy->StopUsingPermissionCallback();
        cameraPrivacy->UnregisterPermissionCallback();
    }
}

int32_t HCameraDevice::UpdateDeviceSetting()
{
    std::vector<uint8_t> setting;
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(updateSettings_, setting);
    ReportMetadataDebugLog(updateSettings_);
    CamRetCode rc = (CamRetCode)(hdiCameraDevice_->UpdateSettings(setting));
    CHECK_ERROR_RETURN_RET_LOG(rc != HDI::Camera::V1_0::NO_ERROR, HdiToServiceError(rc),
        "HCameraDevice::OpenDevice Update setting failed with error Code: %{public}d", rc);
    updateSettings_ = nullptr;
    MEDIA_DEBUG_LOG("HCameraDevice::Open Updated device settings");
    return CAMERA_OK;
}

void HCameraDevice::HandleFoldableDevice()
{
    bool isFoldable = OHOS::Rosen::DisplayManager::GetInstance().IsFoldable();
    MEDIA_DEBUG_LOG("HCameraDevice::OpenDevice isFoldable is %d", isFoldable);
    if (isFoldable) {
        RegisterFoldStatusListener();
    }
}

int32_t HCameraDevice::CloseDevice()
{
    MEDIA_DEBUG_LOG("HCameraDevice::CloseDevice start");
    CAMERA_SYNC_TRACE;
    {
        std::lock_guard<std::mutex> lock(opMutex_);
        CHECK_ERROR_RETURN_RET_LOG(!isOpenedCameraDevice_.load(), CAMERA_OK,
            "HCameraDevice::CloseDevice device has benn closed");
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
            HandlePrivacyAfterCloseDevice();
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
    NotifyCameraStatus(CAMERA_CLOSE);
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
    CHECK_ERROR_RETURN_RET_LOG(!hdiCameraDevice_, CAMERA_UNKNOWN_ERROR,
        "HCameraDevice::GetEnabledResults GetEnabledResults hdiCameraDevice_ is nullptr");
    CamRetCode rc = (CamRetCode)(hdiCameraDevice_->GetEnabledResults(results));
    CHECK_ERROR_RETURN_RET_LOG(rc != HDI::Camera::V1_0::NO_ERROR, HdiToServiceError(rc),
        "HCameraDevice::GetEnabledResults failed with error Code:%{public}d", rc);
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

bool HCameraDevice::CheckMovingPhotoSupported(int32_t mode)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    int32_t ret = cameraHostManager_->GetCameraAbility(cameraID_, cameraAbility);
    CHECK_AND_RETURN_RET(cameraAbility != nullptr, false);
    camera_metadata_item_t metadataItem;
    std::vector<int32_t> modes = {};
    ret = OHOS::Camera::FindCameraMetadataItem(cameraAbility->get(), OHOS_ABILITY_MOVING_PHOTO,
        &metadataItem);
    if (ret == CAM_META_SUCCESS && metadataItem.count > 0) {
        uint32_t step = 3;
        for (uint32_t index = 0; index < metadataItem.count - 1;) {
            if (metadataItem.data.i32[index + 1] == 1) {
                modes.push_back(metadataItem.data.i32[index]);
            }
            MEDIA_DEBUG_LOG("IsMovingPhotoSupported mode:%{public}d", metadataItem.data.i32[index]);
            index += step;
        }
    }
    return std::find(modes.begin(), modes.end(), mode) != modes.end();
}

void HCameraDevice::ResetZoomTimer()
{
    CameraTimer::GetInstance()->Unregister(zoomTimerId_);
    if (!inPrepareZoom_) {
        return;
    }
    MEDIA_INFO_LOG("register zoom timer callback");
    uint32_t waitMs = 5 * 1000;
    auto thisPtr = wptr<HCameraDevice>(this);
    zoomTimerId_ = CameraTimer::GetInstance()->Register([thisPtr]() {
        auto devicePtr = thisPtr.promote();
        if (devicePtr != nullptr) {
            devicePtr->UnPrepareZoom();
        }
    }, waitMs, true);
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
    CHECK_ERROR_RETURN_RET_LOG(settings == nullptr, CAMERA_INVALID_ARG, "settings is null");
    CheckZoomChange(settings);

    uint32_t count = OHOS::Camera::GetCameraMetadataItemCount(settings->get());
    CHECK_ERROR_RETURN_RET_LOG(!count, CAMERA_OK, "Nothing to update");
    std::lock_guard<std::mutex> lock(opMutex_);
    if (updateSettings_ == nullptr || !CameraFwkMetadataUtils::MergeMetadata(settings, updateSettings_)) {
        updateSettings_ = settings;
    }
    MEDIA_INFO_LOG("Updated device settings  hdiCameraDevice_(%{public}d)", hdiCameraDevice_ != nullptr);
    if (hdiCameraDevice_ != nullptr) {
        std::vector<uint8_t> hdiSettings;
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(updateSettings_, hdiSettings);
        ReportMetadataDebugLog(updateSettings_);
        CamRetCode rc = (CamRetCode)(hdiCameraDevice_->UpdateSettings(hdiSettings));
        CHECK_ERROR_RETURN_RET_LOG(rc != HDI::Camera::V1_0::NO_ERROR, HdiToServiceError(rc),
            "Failed with error Code: %{public}d", rc);
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

int32_t HCameraDevice::SetUsedAsPosition(uint8_t value)
{
    MEDIA_INFO_LOG("HCameraDevice::SetUsedAsPosition as %{public}d", value);
    usedAsPosition_ = value;
    // lockforcontrol
    return CAMERA_OK;
}

int8_t HCameraDevice::GetUsedAsPosition()
{
    MEDIA_INFO_LOG("HCameraDevice::GetUsedAsPosition success");
    return usedAsPosition_;
}

int32_t HCameraDevice::UpdateSettingOnce(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraDevice::UpdateSettingOnce prepare execute");
    CHECK_ERROR_RETURN_RET_LOG(settings == nullptr, CAMERA_INVALID_ARG, "settings is null");
    CheckZoomChange(settings);

    uint32_t count = OHOS::Camera::GetCameraMetadataItemCount(settings->get());
    CHECK_ERROR_RETURN_RET_LOG(!count, CAMERA_OK, "Nothing to update");
    std::lock_guard<std::mutex> lock(opMutex_);
    MEDIA_INFO_LOG("Updated device settings once hdiCameraDevice_(%{public}d)", hdiCameraDevice_ != nullptr);
    if (hdiCameraDevice_ != nullptr) {
        std::vector<uint8_t> hdiSettings;
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(settings, hdiSettings);
        ReportMetadataDebugLog(settings);
        CamRetCode rc = (CamRetCode)(hdiCameraDevice_->UpdateSettings(hdiSettings));
        CHECK_ERROR_RETURN_RET_LOG(rc != HDI::Camera::V1_0::NO_ERROR, HdiToServiceError(rc),
            "Failed with error Code: %{public}d", rc);
    }
    MEDIA_INFO_LOG("HCameraDevice::UpdateSettingOnce execute success");
    return CAMERA_OK;
}

int32_t HCameraDevice::GetStatus(std::shared_ptr<OHOS::Camera::CameraMetadata> &metaIn,
    std::shared_ptr<OHOS::Camera::CameraMetadata> &metaOut)
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_RET_LOG(metaIn == nullptr, CAMERA_INVALID_ARG, "HCameraDevice::GetStatus metaIn is null");
    uint32_t count = OHOS::Camera::GetCameraMetadataItemCount(metaIn->get());
    CHECK_ERROR_RETURN_RET_LOG(!count, CAMERA_OK, "HCameraDevice::GetStatus Nothing to query");

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
        CHECK_ERROR_RETURN_RET_LOG(rc != HDI::Camera::V1_0::NO_ERROR, HdiToServiceError(rc),
            "HCameraDevice::GetStatus Failed with error Code: %{public}d", rc);
        if (hdiMetaOut.size() != 0) {
            OHOS::Camera::MetadataUtils::ConvertVecToMetadata(hdiMetaOut, metaOut);
        }
    }
    return CAMERA_OK;
}

void HCameraDevice::ReportMetadataDebugLog(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings)
{
    caller_ = CameraReportUtils::GetCallerInfo();
    for (const auto &tagInfo : reportTagInfos_) {
        std::string tagName, dfxUbStr;
        uint32_t tag;
        std::tie(tag, tagName, dfxUbStr) = tagInfo;
        DebugLogTag(settings, tag, tagName, dfxUbStr);
    }

    DebugLogForSmoothZoom(settings, OHOS_CONTROL_SMOOTH_ZOOM_RATIOS);
    DebugLogForAfRegions(settings, OHOS_CONTROL_AF_REGIONS);
    DebugLogForAeRegions(settings, OHOS_CONTROL_AE_REGIONS);
}

void HCameraDevice::DebugLogTag(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
                                uint32_t tag, std::string tagName, std::string dfxUbStr)
{
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), tag, &item);
    if (ret != CAM_META_SUCCESS || item.count <= 0) {
        MEDIA_DEBUG_LOG("Failed to find %{public}s tag", tagName.c_str());
        return;
    }
    uint32_t dataType = item.data_type;
    std::string valueStr;
    if (dataType == META_TYPE_BYTE) {
        valueStr = std::to_string(item.data.u8[0]);
    } else if (dataType == META_TYPE_INT32) {
        valueStr = std::to_string(item.data.i32[0]);
    } else if (dataType == META_TYPE_UINT32) {
        valueStr = std::to_string(item.data.ui32[0]);
    } else if (dataType == META_TYPE_FLOAT) {
        valueStr = std::to_string(item.data.f[0]);
    } else if (dataType == META_TYPE_INT64) {
        valueStr = std::to_string(item.data.i64[0]);
    } else if (dataType == META_TYPE_DOUBLE) {
        valueStr = std::to_string(item.data.d[0]);
    } else {
        MEDIA_ERR_LOG("unknown dataType");
        return;
    }
    MEDIA_DEBUG_LOG("Find %{public}s value = %{public}s", tagName.c_str(), valueStr.c_str());

    if (dfxUbStr != DFX_UB_NOT_REPORT) {
        CameraReportUtils::GetInstance().ReportUserBehavior(dfxUbStr, valueStr, caller_);
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
    CHECK_ERROR_RETURN_RET_LOG(results.empty(), CAMERA_INVALID_ARG, "HCameraDevice::EnableResult results is empty");
    std::lock_guard<std::mutex> lock(opMutex_);
    CHECK_ERROR_RETURN_RET_LOG(hdiCameraDevice_ == nullptr, CAMERA_UNKNOWN_ERROR,
        "HCameraDevice::hdiCameraDevice_ is null");

    CamRetCode rc = (CamRetCode)(hdiCameraDevice_->EnableResult(results));
    CHECK_ERROR_RETURN_RET_LOG(rc != HDI::Camera::V1_0::NO_ERROR, HdiToServiceError(rc),
        "HCameraDevice::EnableResult failed with error Code:%{public}d", rc);
    return CAMERA_OK;
}

int32_t HCameraDevice::DisableResult(std::vector<int32_t> &results)
{
    CHECK_ERROR_RETURN_RET_LOG(results.empty(), CAMERA_INVALID_ARG, "HCameraDevice::DisableResult results is empty");
    std::lock_guard<std::mutex> lock(opMutex_);
    CHECK_ERROR_RETURN_RET_LOG(hdiCameraDevice_ == nullptr, CAMERA_UNKNOWN_ERROR,
        "HCameraDevice::hdiCameraDevice_ is null");

    CamRetCode rc = (CamRetCode)(hdiCameraDevice_->DisableResult(results));
    CHECK_ERROR_RETURN_RET_LOG(rc != HDI::Camera::V1_0::NO_ERROR, HdiToServiceError(rc),
        "HCameraDevice::DisableResult failed with error Code:%{public}d", rc);
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
    CHECK_ERROR_RETURN_RET_LOG(hdiCameraDevice_ == nullptr, CAMERA_UNKNOWN_ERROR,
        "HCameraDevice::InitStreamOperator hdiCameraDevice_ is null");
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
        sptr<OHOS::HDI::Camera::V1_3::IStreamOperator> streamOperator_v1_3;
        rc = (CamRetCode)(hdiCameraDeviceV1_3->GetStreamOperator_V1_3(this, streamOperator_v1_3));
        streamOperator_ = streamOperator_v1_3;
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
    auto errType = static_cast<OHOS::HDI::Camera::V1_3::ErrorType>(type);
    NotifyCameraStatus(HdiToCameraErrorType(errType));
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
    if (cameraResult == nullptr) {
        MEDIA_ERR_LOG("HCameraDevice::OnResult cameraResult is nullptr");
        return;
    }
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = cameraResult->get();
    int ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FLASH_MODE, &item);
    if (ret == 0) {
        MEDIA_DEBUG_LOG("Flash mode: %{public}d", item.data.u8[0]);
    }
    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FLASH_STATE, &item);
    if (ret == 0) {
        MEDIA_DEBUG_LOG("Flash state: %{public}d", item.data.u8[0]);
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
        MEDIA_DEBUG_LOG("Metadata item: %{public}f, %{public}f, %{public}f, %{public}f", start[offsetX], start[offsetY],
            start[offsetW], start[offsetH]);
    }
}

int32_t HCameraDevice::OnResult(const uint64_t timestamp, const std::vector<uint8_t>& result)
{
    CHECK_ERROR_RETURN_RET_LOG(result.size() == 0, CAMERA_INVALID_ARG, "onResult get null meta from HAL");
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

int32_t HCameraDevice::OnResult(int32_t streamId, const std::vector<uint8_t>& result)
{
    CHECK_ERROR_RETURN_RET_LOG(result.size() == 0, CAMERA_INVALID_ARG, "onResult get null meta from HAL");
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult = nullptr;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(result, cameraResult);
    auto streamOperatorCallback = GetStreamOperatorCallback();
    if (streamOperatorCallback != nullptr) {
        streamOperatorCallback->OnResult(streamId, result);
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
    CHECK_ERROR_RETURN_RET_LOG(streamInfos.empty(), CAMERA_OK, "HCameraDevice::CreateStreams streamInfos is empty!");
    std::lock_guard<std::mutex> lock(opMutex_);
    sptr<OHOS::HDI::Camera::V1_1::IStreamOperator> streamOperatorV1_1;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator = streamOperator_;
    CHECK_ERROR_RETURN_RET_LOG(streamOperator == nullptr, CAMERA_UNKNOWN_ERROR,
        "HCameraDevice::CreateStreams GetStreamOperator is null!");
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
        CHECK_ERROR_PRINT_LOG(!streamIds.empty() &&
            streamOperator->ReleaseStreams(streamIds) != HDI::Camera::V1_0::NO_ERROR,
            "HCameraDevice::CreateStreams(), Failed to release streams");
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
    CHECK_ERROR_RETURN_RET_LOG(streamOperator == nullptr, CAMERA_UNKNOWN_ERROR,
        "HCameraDevice::CommitStreams GetStreamOperator is null!");
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
    CHECK_AND_RETURN_RET(retCode == CAMERA_OK, retCode);
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
    CHECK_ERROR_RETURN_RET_LOG(streamOperator == nullptr, CAMERA_UNKNOWN_ERROR,
        "HCameraDevice::UpdateStreamInfos GetStreamOperator is null!");
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
        case CameraDeviceInterfaceCode::CAMERA_DEVICE_SET_USED_POS:
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
    CHECK_AND_RETURN_RET(streamOperatorCallback != nullptr, CAMERA_INVALID_STATE);
    return streamOperatorCallback->OnCaptureStarted(captureId, streamIds);
}

int32_t HCameraDevice::OnCaptureStarted_V1_2(
    int32_t captureId, const std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo>& infos)
{
    auto streamOperatorCallback = GetStreamOperatorCallback();
    CHECK_AND_RETURN_RET(streamOperatorCallback != nullptr, CAMERA_INVALID_STATE);
    return streamOperatorCallback->OnCaptureStarted_V1_2(captureId, infos);
}

int32_t HCameraDevice::OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos)
{
    auto streamOperatorCallback = GetStreamOperatorCallback();
    CHECK_AND_RETURN_RET(streamOperatorCallback != nullptr, CAMERA_INVALID_STATE);
    return streamOperatorCallback->OnCaptureEnded(captureId, infos);
}

int32_t HCameraDevice::OnCaptureEndedExt(int32_t captureId,
    const std::vector<OHOS::HDI::Camera::V1_3::CaptureEndedInfoExt>& infos)
{
    auto streamOperatorCallback = GetStreamOperatorCallback();
    CHECK_AND_RETURN_RET(streamOperatorCallback != nullptr, CAMERA_INVALID_STATE);
    return streamOperatorCallback->OnCaptureEndedExt(captureId, infos);
}

int32_t HCameraDevice::OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos)
{
    auto streamOperatorCallback = GetStreamOperatorCallback();
    CHECK_AND_RETURN_RET(streamOperatorCallback != nullptr, CAMERA_INVALID_STATE);
    return streamOperatorCallback->OnCaptureError(captureId, infos);
}

int32_t HCameraDevice::OnFrameShutter(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp)
{
    auto streamOperatorCallback = GetStreamOperatorCallback();
    CHECK_AND_RETURN_RET(streamOperatorCallback != nullptr, CAMERA_INVALID_STATE);
    return streamOperatorCallback->OnFrameShutter(captureId, streamIds, timestamp);
}

int32_t HCameraDevice::OnFrameShutterEnd(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp)
{
    auto streamOperatorCallback = GetStreamOperatorCallback();
    CHECK_AND_RETURN_RET(streamOperatorCallback != nullptr, CAMERA_INVALID_STATE);
    return streamOperatorCallback->OnFrameShutterEnd(captureId, streamIds, timestamp);
}

int32_t HCameraDevice::OnCaptureReady(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp)
{
    auto streamOperatorCallback = GetStreamOperatorCallback();
    CHECK_AND_RETURN_RET(streamOperatorCallback != nullptr, CAMERA_INVALID_STATE);
    return streamOperatorCallback->OnCaptureReady(captureId, streamIds, timestamp);
}

void HCameraDevice::NotifyCameraSessionStatus(bool running)
{
    bool isSystemCamera = (clientName_ == SYSTEM_CAMERA);
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
    NotifyCameraStatus(CAMERA_CLOSE);
    MEDIA_DEBUG_LOG("HCameraDevice::RemoveResourceWhenHostDied end");
}

void HCameraDevice::NotifyCameraStatus(int32_t state)
{
    OHOS::AAFwk::Want want;
    MEDIA_DEBUG_LOG("HCameraDevice::NotifyCameraStatus strat");
    want.SetAction(COMMON_EVENT_CAMERA_STATUS);
    want.SetParam(CLIENT_USER_ID, clientUserId_);
    want.SetParam(CAMERA_ID, cameraID_);
    want.SetParam(CAMERA_STATE, state);
    int32_t type = GetCameraType();
    want.SetParam(IS_SYSTEM_CAMERA, type);
    MEDIA_DEBUG_LOG(
        "OnCameraStatusChanged userId: %{public}d, cameraId: %{public}s, state: %{public}d, cameraType: %{public}d: ",
        clientUserId_, cameraID_.c_str(), state, type);
    EventFwk::CommonEventData CommonEventData { want };
    EventFwk::CommonEventPublishInfo publishInfo;
    std::vector<std::string> permissionVec { OHOS_PERMISSION_MANAGE_CAMERA_CONFIG };
    publishInfo.SetSubscriberPermissions(permissionVec);
    EventFwk::CommonEventManager::PublishCommonEvent(CommonEventData, publishInfo);
    MEDIA_DEBUG_LOG("HCameraDevice::NotifyCameraStatus end");
}
} // namespace CameraStandard
} // namespace OHOS
