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
#include <nlohmann/json.hpp>
#include <vector>
#include <parameters.h>
#include <parameter.h>

#include "bms_adapter.h"
#include "camera_common_event_manager.h"
#include "camera_device_ability_items.h"
#include "camera_log.h"
#include "camera_fwk_metadata_utils.h"
#include "camera_metadata_info.h"
#include "camera_metadata_operator.h"
#include "camera_util.h"
#include "device_protection_ability_connection.h"
#include "display_manager.h"
#include "extension_manager_client.h"
#include "hcamera_device_manager.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#ifdef MEMMGR_OVERRID
#include "mem_mgr_client.h"
#include "mem_mgr_constant.h"
#endif
#include "metadata_utils.h"
#include "v1_0/types.h"
#include "os_account_manager.h"
#include "deferred_processing_service.h"
#include "camera_timer.h"
#include "camera_report_uitls.h"
#include "common_event_manager.h"
#include "common_event_data.h"
#include "want.h"
#include "parameters.h"
#include "res_type.h"
#include "res_sched_client.h"
#include "camera_xcollie.h"
#ifdef HOOK_CAMERA_OPERATOR
#include "camera_rotate_plugin.h"
#endif
#include "camera_dialog_manager.h"
#include "tokenid_kit.h"
#ifdef CAMERA_LIVE_SCENE_RECOGNITION
#include "camera_metadata.h"
#endif

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
std::mutex HCameraDevice::g_deviceOpenCloseMutex_;
static const int32_t DEFAULT_SETTING_ITEM_COUNT = 100;
static const int32_t DEFAULT_SETTING_ITEM_LENGTH = 100;
static const int32_t CAMERA_QOS_LEVEL = 7;
static const float SMOOTH_ZOOM_DIVISOR = 100.0f;
static const std::vector<camera_device_metadata_tag> DEVICE_OPEN_LIFECYCLE_TAGS = { OHOS_CONTROL_MUTE_MODE };
constexpr int32_t DEFAULT_USER_ID = -1;
static const uint32_t DEVICE_EJECT_LIMIT = 5;
static const uint32_t DEVICE_EJECT_INTERVAL = 1000;
static const uint32_t SYSDIALOG_ZORDER_UPPER = 2;
static const uint32_t DEVICE_DROP_INTERVAL = 600000;
static std::mutex g_cameraHostManagerMutex;
static sptr<HCameraHostManager> g_cameraHostManager = nullptr;
static int64_t g_lastDeviceDropTime = 0;
CallerInfo caller_;
constexpr int32_t BASE_DEGREE = 360;

const std::vector<std::tuple<uint32_t, std::string, DFX_UB_NAME>> HCameraDevice::reportTagInfos_ = {
    {OHOS_CONTROL_FLASH_MODE, "OHOS_CONTROL_FLASH_MODE", DFX_UB_SET_FLASHMODE},
    {OHOS_CONTROL_FOCUS_MODE, "OHOS_CONTROL_FOCUS_MODE", DFX_UB_SET_FOCUSMODE},
    {OHOS_CONTROL_QUALITY_PRIORITIZATION, "OHOS_CONTROL_QUALITY_PRIORITIZATION", DFX_UB_SET_QUALITY_PRIORITIZATION},
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
    {OHOS_CONTROL_CAMERA_USED_AS_POSITION, "OHOS_CONTROL_CAMERA_USED_AS_POSITION", DFX_UB_NOT_REPORT},
    {OHOS_CONTROL_CHANGETO_OFFLINE_STREAM_OPEATOR, "OHOS_CONTROL_CHANGETO_OFFLINE_STREAM_OPEATOR", DFX_UB_NOT_REPORT},
    {OHOS_CONTROL_ROTATE_ANGLE, "OHOS_CONTROL_ROTATE_ANGLE", DFX_UB_NOT_REPORT},
};

const std::unordered_map<DeviceProtectionStatus, CamServiceError> g_deviceProtectionToServiceError_ = {
    {OHOS_DEVICE_SWITCH_FREQUENT, CAMERA_DEVICE_SWITCH_FREQUENT},
    {OHOS_DEVICE_FALL_PROTECTION, CAMERA_DEVICE_LENS_RETRACTED}
};

const std::unordered_map<DeviceProtectionStatus, DeviceProtectionAbilityCallBack> g_deviceProtectionToCallBack_ = {
    {OHOS_DEVICE_EXTERNAL_PRESS, HCameraDevice::DeviceFaultCallBack},
    {OHOS_DEVICE_EJECT_BLOCK, HCameraDevice::DeviceEjectCallBack}
};

class HCameraDevice::FoldScreenListener : public OHOS::Rosen::DisplayManager::IFoldStatusListener {
public:
    explicit FoldScreenListener(sptr<HCameraDevice> cameraDevice, sptr<HCameraHostManager> &cameraHostManager,
        const std::string cameraId, const bool isSystemApp)
        : cameraDevice_(cameraDevice), cameraHostManager_(cameraHostManager), cameraId_(cameraId),
        isSystemApp_(isSystemApp)
    {
        MEDIA_DEBUG_LOG("FoldScreenListener enter, cameraID: %{public}s", cameraId_.c_str());
    }

    virtual ~FoldScreenListener() = default;
    using FoldStatusRosen = OHOS::Rosen::FoldStatus;
    void OnFoldStatusChanged(FoldStatusRosen foldStatus) override
    {
        FoldStatusRosen currentFoldStatus = foldStatus;
        auto foldScreenType = system::GetParameter("const.window.foldscreen.type", "");
        CHECK_EXECUTE(currentFoldStatus == FoldStatusRosen::HALF_FOLD && foldScreenType[0] != '6',
            currentFoldStatus = FoldStatusRosen::EXPAND);
        CHECK_RETURN_ELOG((cameraHostManager_ == nullptr || mLastFoldStatus == currentFoldStatus ||
            cameraDevice_ == nullptr), "no need set fold status");
        position = cameraDevice_->GetCameraPosition();
        MEDIA_INFO_LOG("HCameraDevice::OnFoldStatusChanged %{public}s, %{public}d, %{public}d, %{public}d,",
            foldScreenType.c_str(), position, mLastFoldStatus, currentFoldStatus);
        if (foldScreenType[0] == '6' && position == OHOS_CAMERA_POSITION_FRONT &&
            ((currentFoldStatus == FoldStatusRosen::EXPAND &&
            (mLastFoldStatus == FoldStatusRosen::HALF_FOLD || mLastFoldStatus == FoldStatusRosen::FOLDED)) ||
            (currentFoldStatus == FoldStatusRosen::EXPAND &&
            mLastFoldStatus == FoldStatusRosen::FOLD_STATE_EXPAND_WITH_SECOND_HALF_FOLDED)) && !isSystemApp_) {
            MEDIA_DEBUG_LOG("HCameraDevice::OnFoldStatusChanged dialog start");
            NoFrontCameraDialog::GetInstance()->ShowCameraDialog();
        }
        mLastFoldStatus = currentFoldStatus;
        MEDIA_INFO_LOG("OnFoldStatusChanged, foldStatus: %{public}d", foldStatus);
        cameraHostManager_->NotifyDeviceStateChangeInfo(DeviceType::FOLD_TYPE, (int)currentFoldStatus);
    }
private:
    sptr<HCameraDevice> cameraDevice_;
    sptr<HCameraHostManager> cameraHostManager_;
    std::string cameraId_;
    bool isSystemApp_ = false;
    FoldStatusRosen mLastFoldStatus = OHOS::Rosen::DisplayManager::GetInstance().GetFoldStatus();
    int32_t position = OHOS_CAMERA_POSITION_BACK;
};

class HCameraDevice::DisplayModeListener : public OHOS::Rosen::DisplayManager::IDisplayModeListener {
public:
    explicit DisplayModeListener(sptr<HCameraDevice> cameraDevice, sptr<HCameraHostManager> &cameraHostManager,
        const std::string cameraId)
        : cameraDevice_(cameraDevice), cameraHostManager_(cameraHostManager), cameraId_(cameraId)
    {
        MEDIA_DEBUG_LOG("DisplayModeListener enter, cameraID: %{public}s", cameraId_.c_str());
    }

    virtual ~DisplayModeListener() = default;
    using DisplayModeRosen = OHOS::Rosen::FoldDisplayMode;
    // LCOV_EXCL_START
    void OnDisplayModeChanged(DisplayModeRosen displayMode) override
    {
        DisplayModeRosen curDisplayMode = displayMode;
        CHECK_RETURN_ELOG((cameraHostManager_ == nullptr || mLastDisplayMode == curDisplayMode ||
            cameraDevice_ == nullptr), "no need set display status");
        cameraDevice_->UpdateCameraRotateAngle();
        mLastDisplayMode = curDisplayMode;
        MEDIA_INFO_LOG("OnDisplayModeChanged, displayMode: %{public}d", displayMode);
    }
    // LCOV_EXCL_STOP
private:
    sptr<HCameraDevice> cameraDevice_;
    sptr<HCameraHostManager> cameraHostManager_;
    std::string cameraId_;
    DisplayModeRosen mLastDisplayMode = DisplayModeRosen::UNKNOWN;
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
    sptr<CameraPrivacy> cameraPrivacy = new CameraPrivacy(callingTokenId, IPCSkeleton::GetCallingPid());
    SetCameraPrivacy(cameraPrivacy);
    cameraPid_ = IPCSkeleton::GetCallingPid();

    {
        std::lock_guard<std::mutex> lock(dataShareHelperMutex_);
        CameraApplistManager::GetInstance()->InitApplistConfigures();
    }

    {
        std::lock_guard<std::mutex> lock(g_cameraHostManagerMutex);
        g_cameraHostManager = cameraHostManager;
    }
}

HCameraDevice::~HCameraDevice()
{
    UnPrepareZoom();
    CameraTimer::GetInstance().Unregister(zoomTimerId_);
    SetCameraPrivacy(nullptr);
    {
        std::lock_guard<std::mutex> lock(movingPhotoStartTimeCallbackLock_);
        movingPhotoStartTimeCallback_ = nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(movingPhotoEndTimeCallbackLock_);
        movingPhotoEndTimeCallback_ = nullptr;
    }
    MEDIA_INFO_LOG("HCameraDevice::~HCameraDevice Destructor Camera: %{public}s", cameraID_.c_str());
}

std::string HCameraDevice::GetCameraId()
{
    return cameraID_;
}

int32_t HCameraDevice::GetCameraType()
{
    CHECK_RETURN_RET(clientName_ == SYSTEM_CAMERA, SYSTEM);
    return OTHER;
}

int32_t HCameraDevice::GetCameraConnectType()
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability = GetDeviceAbility();
    CHECK_RETURN_RET(ability == nullptr, 0);
    camera_metadata_item_t item;
    int32_t ret = OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &item);
    uint32_t connectionType = 0;
    if (ret == CAM_META_SUCCESS && item.count > 0) {
        connectionType = static_cast<uint32_t>(item.data.u8[0]);
    }
    return connectionType;
}

std::string HCameraDevice::GetClientName()
{
    return clientName_;
}

int32_t HCameraDevice::GetCameraPosition()
{
    camera_metadata_item_t item;
    auto ability = GetDeviceAbility();
    CHECK_RETURN_RET_ELOG(ability == nullptr, 0,
        "HCameraDevice::GetCameraPosition deviceAbility_ is nullptr");
    int ret = OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_ABILITY_CAMERA_POSITION, &item);
    CHECK_RETURN_RET_ELOG(
        ret != CAM_META_SUCCESS || item.count <= 0, 0, "HCameraDevice::GetCameraPosition failed");
    return static_cast<int32_t>(item.data.u8[0]);
}

int32_t HCameraDevice::GetSensorOrientation()
{
    camera_metadata_item_t item;
    auto ability = GetDeviceAbility();
    CHECK_RETURN_RET_ELOG(ability == nullptr, 0,
        "HCameraDevice::GetSensorOrientation deviceAbility_ is nullptr");
    int ret = OHOS::Camera::FindCameraMetadataItem(deviceAbility_->get(), OHOS_SENSOR_ORIENTATION, &item);
    CHECK_RETURN_RET_ELOG(
        ret != CAM_META_SUCCESS || item.count <= 0, 0, "HCameraDevice::GetSensorOrientation failed");
    return item.data.i32[0];
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

float HCameraDevice::GetZoomRatio()
{
    return zoomRatio_;
}

int32_t HCameraDevice::GetFocusMode()
{
    return focusMode_;
}

int32_t HCameraDevice::GetVideoStabilizationMode()
{
    return videoStabilizationMode_;
}

void HCameraDevice::EnableMovingPhoto(bool isMovingPhotoEnabled)
{
    isMovingPhotoEnabled_ = isMovingPhotoEnabled;
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
        CHECK_RETURN_RET(hdiCameraDevice_ == nullptr, CAMERA_OK);
        hdiCameraDeviceV1_2 = HDI::Camera::V1_2::ICameraDevice::CastFrom(hdiCameraDevice_);
    }
    if (hdiCameraDeviceV1_2 != nullptr) {
        int32_t errCode = hdiCameraDeviceV1_2->Reset();
        CHECK_RETURN_RET_ELOG(errCode != HDI::Camera::V1_0::CamRetCode::NO_ERROR, CAMERA_UNKNOWN_ERROR,
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
    CHECK_RETURN_RET(hdiCameraDevice_ == nullptr, CAMERA_INVALID_STATE);
    std::vector<uint8_t> hdiMetadata;
    bool isSuccess = OHOS::Camera::MetadataUtils::ConvertMetadataToVec(lifeCycleSettings, hdiMetadata);
    CHECK_RETURN_RET_ELOG(!isSuccess, CAMERA_UNKNOWN_ERROR,
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
    CHECK_RETURN_RET(deviceAbility_ != nullptr, deviceAbility_);
    int32_t errCode = cameraHostManager_->GetCameraAbility(cameraID_, deviceAbility_);
    CHECK_RETURN_RET_ELOG(errCode != CAMERA_OK, nullptr,
        "HCameraDevice::GetSettings Failed to get Camera Ability: %{public}d", errCode);
    return deviceAbility_;
}

int32_t HCameraDevice::Open()
{
    CAMERA_SYNC_TRACE;
    CameraXCollie cameraXCollie("HandleOpenSecureCameraResults");
    std::lock_guard<std::mutex> lock(g_deviceOpenCloseMutex_);
    CHECK_PRINT_ELOG(isOpenedCameraDevice_.load(), "HCameraDevice::Open failed, camera is busy");
    CHECK_RETURN_RET_ELOG(!IsInForeGround(callerToken_), CAMERA_ALLOC_ERROR,
        "HCameraDevice::Open IsAllowedUsingPermission failed");
    MEDIA_INFO_LOG("HCameraDevice::Open Camera:[%{public}s]", cameraID_.c_str());
    int32_t result = OpenDevice();
    int32_t position = GetCameraPosition();
    auto foldStatus = OHOS::Rosen::DisplayManager::GetInstance().GetFoldStatus();
    auto foldScreenType = system::GetParameter("const.window.foldscreen.type", "");
    MEDIA_INFO_LOG("HCameraDevice::Open %{public}d, %{public}d", position, foldStatus);
    if (foldScreenType[0] == '6' && position == OHOS_CAMERA_POSITION_FRONT &&
        foldStatus == OHOS::Rosen::FoldStatus::EXPAND) {
        MEDIA_DEBUG_LOG("HCameraDevice::Open dialog start");
        NoFrontCameraDialog::GetInstance()->ShowCameraDialog();
    }
    std::unordered_map<std::string, std::string> mapPayload;
    pidForLiveScene_ = std::to_string(IPCSkeleton::GetCallingPid());
    uidForLiveScene_ = std::to_string(IPCSkeleton::GetCallingUid());
    bundleNameForLiveScene_ = BmsAdapter::GetInstance()->GetBundleName(IPCSkeleton::GetCallingUid());

    mapPayload["camId"] = cameraID_;
    mapPayload["pid"] = pidForLiveScene_;
    mapPayload["uid"] = uidForLiveScene_;
    mapPayload["bundleName"] = bundleNameForLiveScene_;
    MEDIA_DEBUG_LOG("camera lens report: camId: %{public}s. pid: %{public}s. uid: %{public}s, bundleName: %{public}s",
        cameraID_.c_str(), pidForLiveScene_.c_str(), uidForLiveScene_.c_str(), bundleNameForLiveScene_.c_str());
    OHOS::ResourceSchedule::ResSchedClient::GetInstance().ReportData(
        OHOS::ResourceSchedule::ResType::RES_TYPE_CAMERA_LENS_STATUS_CHANGED,
        static_cast<int64_t>(OHOS::ResourceSchedule::ResType::CameraLensState ::CAMERA_LEN_OPENED), mapPayload);
    return result;
}

int32_t HCameraDevice::OpenSecureCamera(uint64_t& secureSeqId)
{
    CAMERA_SYNC_TRACE;
    CameraXCollie cameraXCollie("HandleOpenSecureCameraResults");
    CHECK_PRINT_ELOG(isOpenedCameraDevice_.load(), "HCameraDevice::Open failed, camera is busy");
    CHECK_RETURN_RET_ELOG(!IsInForeGround(callerToken_), CAMERA_ALLOC_ERROR,
        "HCameraDevice::Open IsAllowedUsingPermission failed");
    MEDIA_INFO_LOG("HCameraDevice::OpenSecureCamera Camera:[%{public}s]", cameraID_.c_str());
    int32_t errCode = OpenDevice(true);
    CHECK_RETURN_RET_ELOG(hdiCameraDevice_ == nullptr, CAMERA_INVALID_ARG,
        "HCameraDevice::OpenSecureCamera hdiCameraDevice_ is nullptr.");
    auto hdiCameraDeviceV1_3 = HDI::Camera::V1_3::ICameraDevice::CastFrom(hdiCameraDevice_);
    // LCOV_EXCL_START
    if (hdiCameraDeviceV1_3 != nullptr) {
        errCode = hdiCameraDeviceV1_3->GetSecureCameraSeq(secureSeqId);
        CHECK_RETURN_RET_ELOG(errCode != HDI::Camera::V1_0::CamRetCode::NO_ERROR, CAMERA_UNKNOWN_ERROR,
            "HCameraDevice::GetSecureCameraSeq occur error");
        mSecureCameraSeqId = secureSeqId;
        isHasOpenSecure = true;
    }  else {
        MEDIA_INFO_LOG("V1_3::ICameraDevice::CastFrom failed");
    }
    // LCOV_EXCL_STOP
    MEDIA_INFO_LOG("HCameraDevice::OpenSecureCamera secureSeqId = %{public}" PRIu64, secureSeqId);
    return errCode;
}

int32_t HCameraDevice::SetUsePhysicalCameraOrientation(bool isUsed)
{
    std::lock_guard<std::mutex> lock(usePhysicalCameraOrientationMutex_);
    usePhysicalCameraOrientation_ = isUsed;
    MEDIA_INFO_LOG("HCameraDevice::SetUsePhysicalCameraOrientation isUsed %{public}d", isUsed);
    return CAMERA_OK;
}

bool HCameraDevice::GetUsePhysicalCameraOrientation()
{
    std::lock_guard<std::mutex> lock(usePhysicalCameraOrientationMutex_);
    return usePhysicalCameraOrientation_;
}

int64_t HCameraDevice::GetSecureCameraSeq(uint64_t* secureSeqId)
{
    // LCOV_EXCL_START
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
    // LCOV_EXCL_STOP
    return CAMERA_OK;
}

int32_t HCameraDevice::Close()
{
    CAMERA_SYNC_TRACE;
    CameraXCollie cameraXCollie("HCameraDeviceStub::Close");
    std::lock_guard<std::mutex> lock(g_deviceOpenCloseMutex_);
    MEDIA_INFO_LOG("HCameraDevice::Close Closing camera device: %{public}s", cameraID_.c_str());
    if (isOpenedCameraDevice_.load()) {
        std::unordered_map<std::string, std::string> mapPayload;
        mapPayload["camId"] = cameraID_;
        mapPayload["pid"] = pidForLiveScene_;
        mapPayload["uid"] = uidForLiveScene_;
        mapPayload["bundleName"] = bundleNameForLiveScene_;
        MEDIA_DEBUG_LOG("camera lens report:camId: %{public}s, pid: %{public}s, uid: %{public}s, bundleName:%{public}s",
            cameraID_.c_str(), pidForLiveScene_.c_str(), uidForLiveScene_.c_str(), bundleNameForLiveScene_.c_str());
        OHOS::ResourceSchedule::ResSchedClient::GetInstance().ReportData(
            OHOS::ResourceSchedule::ResType::RES_TYPE_CAMERA_LENS_STATUS_CHANGED,
            static_cast<int64_t>(OHOS::ResourceSchedule::ResType::CameraLensState::CAMERA_LEN_CLOSED), mapPayload);
#ifdef CAMERA_LIVE_SCENE_RECOGNITION
        if (HCameraDeviceManager::GetInstance()->IsLiveScene()) {
            UpdateLiveStreamSceneMetadata(OHOS_CAMERA_APP_HINT_NONE);
            MEDIA_DEBUG_LOG("HCameraDevice::Close UpdateLiveStreamSceneMetadata complete");
        }
#endif
    }
    int32_t result = CloseDevice();
    return result;
}

int32_t HCameraDevice::closeDelayed()
{
    CAMERA_SYNC_TRACE;
    CameraXCollie cameraXCollie("HCameraDeviceStub::delayedClose");
    CHECK_RETURN_RET_ELOG(
        !CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraDevice::closeDelayed:SystemApi is called");
    std::lock_guard<std::mutex> lock(g_deviceOpenCloseMutex_);
    MEDIA_INFO_LOG("HCameraDevice::closeDelayed Closing camera device: %{public}s", cameraID_.c_str());
    int32_t result = closeDelayedDevice();
    return result;
}

void HCameraDevice::ConfigQosParam(const char *bundleName, int32_t qosLevel,
    std::unordered_map<std::string, std::string> &qosParamMap)
{
    std::string strBundleName = bundleName;
    std::string strPid = std::to_string(getpid());
    std::string strTid = std::to_string(gettid());
    std::string strQos = std::to_string(qosLevel);

    qosParamMap["pid"] = strPid;
    qosParamMap[strTid] = strQos;
    qosParamMap["bundleName"] = strBundleName;
    MEDIA_INFO_LOG("camera service qosParam: pid: %{public}s. tid: %{public}s, qos: %{public}s",
        strPid.c_str(), strTid.c_str(), strQos.c_str());
}

int32_t HCameraDevice::CameraHostMgrOpenCamera(bool isEnableSecCam)
{
    CameraReportUtils::GetInstance().SetOpenCamPerfStartInfo(cameraID_.c_str(), CameraReportUtils::GetCallerInfo());
    int32_t errorCode = cameraHostManager_->OpenCameraDevice(cameraID_, this, hdiCameraDevice_, isEnableSecCam);
    if (errorCode != CAMERA_OK) {
        MEDIA_ERR_LOG("HCameraDevice::OpenDevice Failed to open camera");
#ifdef MEMMGR_OVERRID
    RequireMemory(Memory::CAMERA_END);
#endif
        HandlePrivacyWhenOpenDeviceFail();
        return CAMERA_UNKNOWN_ERROR;
    } else {
        isOpenedCameraDevice_.store(true);
        HCameraDeviceManager::GetInstance()->AddDevice(IPCSkeleton::GetCallingPid(), this);
        g_lastDeviceDropTime = 0;
        RegisterSensorCallback();
        return CAMERA_OK;
    }
}

int32_t HCameraDevice::OpenDevice(bool isEnableSecCam)
{
    std::unordered_map<std::string, std::string> qosParamMap;
    ConfigQosParam("camera_service", CAMERA_QOS_LEVEL, qosParamMap);
    OHOS::ResourceSchedule::ResSchedClient::GetInstance().ReportData(
        OHOS::ResourceSchedule::ResType::RES_TYPE_THREAD_QOS_CHANGE, 0, qosParamMap);

    MEDIA_INFO_LOG("HCameraDevice::OpenDevice start cameraId: %{public}s", cameraID_.c_str());
    CAMERA_SYNC_TRACE;
    int32_t errorCode = CheckPermissionBeforeOpenDevice();
    CHECK_RETURN_RET(errorCode != CAMERA_OK, errorCode);
    bool canOpenDevice = CanOpenCamera();
    CHECK_RETURN_RET_ELOG(!canOpenDevice, CAMERA_DEVICE_CONFLICT, "HCameraDevice::Refuse to turn on the camera");
    CHECK_RETURN_RET_ELOG(!HandlePrivacyBeforeOpenDevice(), CAMERA_OPERATION_NOT_ALLOWED, "privacy not allow!");
    int pid = IPCSkeleton::GetCallingPid();
    int uid = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, clientUserId_);
    int tokenId = static_cast<int32_t>(IPCSkeleton::GetCallingTokenID());
    clientName_ = GetClientNameByToken(tokenId);
    cameraPrivacy_->SetClientName(clientName_);
#ifdef MEMMGR_OVERRID
    RequireMemory(Memory::CAMERA_START);
#endif
    errorCode = CameraHostMgrOpenCamera(isEnableSecCam);
    CHECK_RETURN_RET_ELOG(errorCode != CAMERA_OK, errorCode,
        "HCameraDevice::OpenDevice InitStreamOperator fail err code is:%{public}d", errorCode);
    std::lock_guard<std::mutex> lockSetting(opMutex_);
    if (hdiCameraDevice_ != nullptr) {
        cameraHostManager_->AddCameraDevice(cameraID_, this);
        if (updateSettings_ != nullptr || deviceMuteMode_) {
            CHECK_EXECUTE(deviceMuteMode_, CreateMuteSetting(updateSettings_));
            errorCode = UpdateDeviceSetting();
            CHECK_RETURN_RET(errorCode != CAMERA_OK, errorCode);
            errorCode = HdiToServiceError((CamRetCode)(hdiCameraDevice_->SetResultMode(ON_CHANGED)));
        }
    }
    HandleFoldableDevice();
    POWERMGR_SYSEVENT_CAMERA_CONNECT(pid, uid, cameraID_.c_str(), clientName_);
    NotifyCameraStatus(CAMERA_OPEN);
#ifdef HOOK_CAMERA_OPERATOR
    if (!CameraRotatePlugin::GetInstance()->HookOpenDeviceForRotate(clientName_, GetDeviceAbility(), cameraID_)) {
        MEDIA_ERR_LOG("HCameraDevice::OpenDevice HookOpenDevice is failed");
    }
#endif
    MEDIA_INFO_LOG("HCameraDevice::OpenDevice end cameraId: %{public}s", cameraID_.c_str());
    return errorCode;
}

#ifdef MEMMGR_OVERRID
int32_t HCameraDevice::RequireMemory(const std::string& reason)
{
    int32_t pid = getpid();
    int32_t requiredMemSizeKB = 0;
    int32_t ret = Memory::MemMgrClient::GetInstance().RequireBigMem(pid, reason,
        requiredMemSizeKB, clientName_);
    MEDIA_INFO_LOG("HCameraDevice::RequireMemory reason:%{public}s, clientName:%{public}s, ret:%{public}d",
        reason.c_str(), clientName_.c_str(), ret);
    return ret;
}
#endif

int32_t HCameraDevice::CheckPermissionBeforeOpenDevice()
{
    MEDIA_DEBUG_LOG("enter checkPermissionBeforeOpenDevice");
    if (IsHapTokenId(callerToken_)) {
        auto cameraPrivacy = GetCameraPrivacy();
        CHECK_RETURN_RET_ELOG(cameraPrivacy == nullptr, CAMERA_OPERATION_NOT_ALLOWED, "cameraPrivacy is null");
        CHECK_RETURN_RET_ELOG(!cameraPrivacy->IsAllowUsingCamera(), CAMERA_OPERATION_NOT_ALLOWED,
            "OpenDevice is not allowed!");
    }
    return CAMERA_OK;
}

bool HCameraDevice::HandlePrivacyBeforeOpenDevice()
{
    MEDIA_INFO_LOG("enter HandlePrivacyBeforeOpenDevice");
    auto cameraPrivacy = GetCameraPrivacy();
    CHECK_RETURN_RET_ELOG(cameraPrivacy == nullptr, false, "cameraPrivacy is null");
    CHECK_RETURN_RET_ELOG(cameraPrivacy->GetDisablePolicy(), false, "policy disabled");
    CHECK_RETURN_RET_ELOG(!cameraPrivacy->RegisterPermDisablePolicyCallback(), false, "register Disable failed");
    CHECK_RETURN_RET_ELOG(!IsHapTokenId(callerToken_), true, "system ability called not need privacy");
    std::vector<sptr<HCameraDeviceHolder>> holders =
        HCameraDeviceManager::GetInstance()->GetCameraHolderByPid(cameraPid_);
    CHECK_RETURN_RET_ELOG(!holders.empty(), true, "current pid has active clients, no action is required");
    if (HCameraDeviceManager::GetInstance()->IsMultiCameraActive(cameraPid_) == false) {
        MEDIA_INFO_LOG("do StartUsingPermissionCallback");
        CHECK_RETURN_RET_ELOG(!cameraPrivacy->StartUsingPermissionCallback(), false,
            "start using permission failed");
    }
    CHECK_RETURN_RET_ELOG(!cameraPrivacy->RegisterPermissionCallback(), false, "register permission failed");
    CHECK_RETURN_RET_ELOG(!cameraPrivacy->AddCameraPermissionUsedRecord(), false, "add permission record failed");
    return true;
}

void HCameraDevice::HandlePrivacyWhenOpenDeviceFail()
{
    MEDIA_INFO_LOG("enter HandlePrivacyWhenOpenDeviceFail");
    auto cameraPrivacy = GetCameraPrivacy();
    CHECK_RETURN(cameraPrivacy == nullptr);
    if (HCameraDeviceManager::GetInstance()->IsMultiCameraActive(cameraPid_) == false) {
        MEDIA_INFO_LOG("do StopUsingPermissionCallback");
        cameraPrivacy->StopUsingPermissionCallback();
    }
        cameraPrivacy->UnregisterPermissionCallback();
        cameraPrivacy->UnRegisterPermDisablePolicyCallback();
}

void HCameraDevice::HandlePrivacyAfterCloseDevice()
{
    MEDIA_INFO_LOG("enter HandlePrivacyAfterCloseDevice");
    std::vector<sptr<HCameraDeviceHolder>> holders =
        HCameraDeviceManager::GetInstance()->GetCameraHolderByPid(cameraPid_);
    CHECK_PRINT_ELOG(!holders.empty(), "current pid has active clients, no action is required");
    auto cameraPrivacy = GetCameraPrivacy();
    if (cameraPrivacy != nullptr) {
        if (HCameraDeviceManager::GetInstance()->IsMultiCameraActive(cameraPid_) == false) {
            MEDIA_INFO_LOG("do StopUsingPermissionCallback");
            cameraPrivacy->StopUsingPermissionCallback();
        }
        cameraPrivacy->UnregisterPermissionCallback();
        cameraPrivacy->UnRegisterPermDisablePolicyCallback();
    }
}

int32_t HCameraDevice::UpdateDeviceSetting()
{
    std::vector<uint8_t> setting;
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(updateSettings_, setting);
    ReportMetadataDebugLog(updateSettings_);
    CamRetCode rc = (CamRetCode)(hdiCameraDevice_->UpdateSettings(setting));
    CHECK_RETURN_RET_ELOG(rc != HDI::Camera::V1_0::NO_ERROR, HdiToServiceError(rc),
        "HCameraDevice::OpenDevice Update setting failed with error Code: %{public}d", rc);
    updateSettings_ = nullptr;
    MEDIA_DEBUG_LOG("HCameraDevice::Open Updated device settings");
    return CAMERA_OK;
}

void HCameraDevice::ReportDeviceProtectionStatus(const std::shared_ptr<OHOS::Camera::CameraMetadata> &metadata)
{
    CHECK_RETURN_ELOG(metadata == nullptr, "metadata is null");
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(metadata->get(), OHOS_DEVICE_PROTECTION_STATE, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS || item.count == 0);
    int32_t status = item.data.i32[0];
    MEDIA_INFO_LOG("HCameraDevice::ReportDeviceProtectionStatus status: %{public}d", status);
    CHECK_RETURN(!CanReportDeviceProtectionStatus(status));
    if (clientName_ == SYSTEM_CAMERA) {
        auto callback = GetDeviceServiceCallback();
        auto itr = g_deviceProtectionToServiceError_.find(static_cast<DeviceProtectionStatus>(status));
        if (itr != g_deviceProtectionToServiceError_.end()) {
            callback->OnError(itr->second, 0);
        }
    }
    if (CameraCommonEventManager::GetInstance()->IsScreenLocked()) {
        return;
    }
    ShowDeviceProtectionDialog(static_cast<DeviceProtectionStatus>(status));
}

bool HCameraDevice::CanReportDeviceProtectionStatus(int32_t status)
{
    std::lock_guard<std::mutex> lock(deviceProtectionStatusMutex_);
    bool ret = (status != lastDeviceProtectionStatus_);
    lastDeviceProtectionStatus_ = status;
    return ret;
}

void HCameraDevice::DeviceEjectCallBack()
{
    MEDIA_INFO_LOG("HCameraDevice::DeviceEjectCallBack enter");
    uint8_t value = 1;
    uint32_t count = 1;
    constexpr int32_t DEFAULT_ITEMS = 1;
    constexpr int32_t DEFAULT_DATA_LENGTH = 1;
    std::shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    bool status = changedMetadata->addEntry(OHOS_CONTROL_EJECT_RETRY, &value, count);
    CHECK_RETURN_ELOG(!status, "HCameraDevice::DropDetectionCallback Failed to set fall protection");

    std::vector<sptr<HCameraDeviceHolder>> deviceHolderVector =
        HCameraDeviceManager::GetInstance()->GetActiveCameraHolders();
    for (sptr<HCameraDeviceHolder> activeDeviceHolder : deviceHolderVector) {
        sptr<HCameraDevice> activeDevice = activeDeviceHolder->GetDevice();
        if (activeDevice != nullptr && activeDevice->IsOpenedCameraDevice()) {
            activeDevice->lastDeviceEjectTime_ = GetTimestamp();
            activeDevice->UpdateSetting(changedMetadata);
            MEDIA_INFO_LOG("HCameraService::DeviceEjectCallBack UpdateSetting");
        }
    }
}

void HCameraDevice::DeviceFaultCallBack()
{
    MEDIA_INFO_LOG("HCameraDevice::DeviceFaultCallBack enter");
}

bool HCameraDevice::ShowDeviceProtectionDialog(DeviceProtectionStatus status)
{
    if (status == OHOS_DEVICE_EJECT_BLOCK) {
        int64_t timestamp = GetTimestamp();
        if (timestamp - lastDeviceEjectTime_ < DEVICE_EJECT_INTERVAL) {
            deviceEjectTimes_.operator++();
        } else {
            deviceEjectTimes_.store(0);
        }
        if (deviceEjectTimes_ >= DEVICE_EJECT_LIMIT) {
            status = OHOS_DEVICE_EXTERNAL_PRESS;
            deviceEjectTimes_.store(0);
        }
    }
    
    AAFwk::Want want;
    std::string bundleName = "com.ohos.sceneboard";
    std::string abilityName = "com.ohos.sceneboard.systemdialog";
    want.SetElementName(bundleName, abilityName);

    const int32_t code = 4;
    std::string commandStr = BuildDeviceProtectionDialogCommand(status);
    auto itr = g_deviceProtectionToCallBack_.find(static_cast<DeviceProtectionStatus>(status));
    CHECK_RETURN_RET(itr == g_deviceProtectionToCallBack_.end(), false);
    DeviceProtectionAbilityCallBack callback = itr->second;

    sptr<DeviceProtectionAbilityConnection> connection = sptr<DeviceProtectionAbilityConnection> (new (std::nothrow)
    DeviceProtectionAbilityConnection(commandStr, code, callback));
    CHECK_RETURN_RET_ELOG(connection == nullptr, false, "connection is nullptr");
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    auto connectResult = AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(want,
        connection, nullptr, DEFAULT_USER_ID);
    IPCSkeleton::SetCallingIdentity(identity);
    CHECK_RETURN_RET_ELOG(connectResult != 0, false, "ConnectServiceExtensionAbility Failed!");
    return true;
}

std::string HCameraDevice::BuildDeviceProtectionDialogCommand(DeviceProtectionStatus status)
{
    nlohmann::json extraInfo;
    switch (static_cast<int32_t>(status)) {
        // 按压受阻
        case OHOS_DEVICE_EJECT_BLOCK:
            extraInfo["title"] = "camera_device_eject_lab";
            extraInfo["content"] = "camera_device_eject_desc";
            extraInfo["button"] = "camera_use_continue";
            break;
        // 故障上报弹窗
        case OHOS_DEVICE_EXTERNAL_PRESS:
            extraInfo["title"] = "camera_device_block_lab";
            extraInfo["content"] = "camera_device_block_desc";
            extraInfo["button"] = "camera_device_block_confirm";
            break;
    }
    nlohmann::json dialogInfo;
    dialogInfo["sysDialogZOrder"] = SYSDIALOG_ZORDER_UPPER;
    dialogInfo["extraInfo"] = extraInfo;
    std::string commandStr = dialogInfo.dump();
    MEDIA_INFO_LOG("BuildDeviceProtectionDialogCommand, commandStr = %{public}s", commandStr.c_str());
    return commandStr;
}

void HCameraDevice::RegisterSensorCallback()
{
    std::lock_guard<std::mutex> lock(sensorLock_);
    MEDIA_INFO_LOG("HCameraDevice::RegisterDropDetectionListener start");
    CHECK_RETURN_ELOG(!OHOS::Rosen::LoadMotionSensor(), "RegisterDropDetectionListener LoadMotionSensor fail");
    CHECK_RETURN_ELOG(!OHOS::Rosen::SubscribeCallback(OHOS::Rosen::MOTION_TYPE_DROP_DETECTION,
        DropDetectionDataCallbackImpl), "RegisterDropDetectionListener SubscribeCallback fail");
}

void HCameraDevice::UnRegisterSensorCallback()
{
    std::lock_guard<std::mutex> lock(sensorLock_);
    CHECK_RETURN_ELOG(!UnsubscribeCallback(OHOS::Rosen::MOTION_TYPE_DROP_DETECTION, DropDetectionDataCallbackImpl),
        "UnRegisterDropDetectionListener fail");
}

void HCameraDevice::DropDetectionDataCallbackImpl(const OHOS::Rosen::MotionSensorEvent &motionData)
{
    MEDIA_INFO_LOG("HCameraDevice::DropDetectionCallback type = %{public}d, status = %{public}d",
        motionData.type, motionData.status);
    {
        if ((GetTimestamp() - g_lastDeviceDropTime < DEVICE_DROP_INTERVAL) ||
            (g_cameraHostManager == nullptr)) {
            return;
        }
        g_cameraHostManager->NotifyDeviceStateChangeInfo(
            DeviceType::FALLING_TYPE, FallingState::FALLING_STATE);
    }
}

void HCameraDevice::HandleFoldableDevice()
{
    bool isFoldable = OHOS::Rosen::DisplayManager::GetInstance().IsFoldable();
    MEDIA_DEBUG_LOG("HCameraDevice::OpenDevice isFoldable is %d", isFoldable);
    CHECK_RETURN(!isFoldable);
    RegisterFoldStatusListener();
    RegisterDisplayModeListener();
}

void HCameraDevice::ReleaseSessionBeforeCloseDevice()
{
    std::lock_guard<std::mutex> lock(cameraCloseListenerMutex_);
    for (wptr<IHCameraCloseListener> cameraCloseListener : cameraCloseListenerVec_) {
        auto cameraCloseListenerTemp = cameraCloseListener.promote();
        if (cameraCloseListenerTemp == nullptr) {
            continue;
        }
        cameraCloseListenerTemp->BeforeDeviceClose();
    }
}

int32_t HCameraDevice::CloseDevice()
{
    MEDIA_INFO_LOG("HCameraDevice::CloseDevice start");
    CAMERA_SYNC_TRACE;
    ReleaseSessionBeforeCloseDevice();
    bool isFoldable = OHOS::Rosen::DisplayManager::GetInstance().IsFoldable();
    CHECK_EXECUTE(isFoldable, UnregisterFoldStatusListener());
    CHECK_EXECUTE(isFoldable, UnregisterDisplayModeListener());
    {
        std::lock_guard<std::mutex> lock(opMutex_);
        CHECK_RETURN_RET_ELOG(!isOpenedCameraDevice_.load(), CAMERA_OK,
            "HCameraDevice::CloseDevice device has benn closed");
        if (hdiCameraDevice_ != nullptr) {
            isOpenedCameraDevice_.store(false);
            MEDIA_INFO_LOG("Closing camera device: %{public}s start", cameraID_.c_str());
            hdiCameraDevice_->Close();
            ResetCachedSettings();
            ResetDeviceOpenLifeCycleSettings();
            HCameraDeviceManager::GetInstance()->RemoveDevice(cameraID_);
            MEDIA_INFO_LOG("Closing camera device: %{public}s end", cameraID_.c_str());
            hdiCameraDevice_ = nullptr;
            HandlePrivacyAfterCloseDevice();
        } else {
            MEDIA_INFO_LOG("hdiCameraDevice is null");
        }
        SetStreamOperatorCallback(nullptr);
        EnableDeviceOpenedByConcurrent(false);
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
    NotifyCameraStatus(CAMERA_CLOSE);
#ifdef MEMMGR_OVERRID
    RequireMemory(Memory::CAMERA_END);
#endif
    UnRegisterSensorCallback();
#ifdef HOOK_CAMERA_OPERATOR
    if (!CameraRotatePlugin::GetInstance()->HookCloseDeviceForRotate(clientName_, deviceAbility_, cameraID_)) {
        MEDIA_ERR_LOG("HCameraDevice::CloseDevice HookCloseDevice is failed");
    }
#endif
    return CAMERA_OK;
}

// LCOV_EXCL_STAR
int32_t HCameraDevice::closeDelayedDevice()
{
    MEDIA_INFO_LOG("HCameraDevice::closeDelayedDevice start");
    CAMERA_SYNC_TRACE;
    sptr<OHOS::HDI::Camera::V1_2::ICameraDevice> hdiCameraDeviceV1_2;
    {
        std::lock_guard<std::mutex> lock(opMutex_);
        CHECK_RETURN_RET(hdiCameraDevice_ == nullptr, CAMERA_OK);
        hdiCameraDeviceV1_2 = HDI::Camera::V1_2::ICameraDevice::CastFrom(hdiCameraDevice_);
    }
    if (hdiCameraDeviceV1_2 != nullptr) {
        int32_t errCode = hdiCameraDeviceV1_2->Reset();
        CHECK_RETURN_RET_ELOG(errCode != HDI::Camera::V1_0::CamRetCode::NO_ERROR, CAMERA_UNKNOWN_ERROR,
            "HCameraDevice::closeDelayedDevice ResetDevice error");
        ResetCachedSettings();
    }
    MEDIA_INFO_LOG("HCameraDevice::closeDelayedDevice end");
    return CAMERA_OK;
}
// LCOV_EXCL_STOP

int32_t HCameraDevice::Release()
{
    CameraXCollie cameraXCollie("HCameraDeviceStub::Release");
    Close();
    return CAMERA_OK;
}

int32_t HCameraDevice::GetEnabledResults(std::vector<int32_t> &results)
{
    std::lock_guard<std::mutex> lock(opMutex_);
    CHECK_RETURN_RET_ELOG(!hdiCameraDevice_, CAMERA_UNKNOWN_ERROR,
        "HCameraDevice::GetEnabledResults GetEnabledResults hdiCameraDevice_ is nullptr");
    CamRetCode rc = (CamRetCode)(hdiCameraDevice_->GetEnabledResults(results));
    CHECK_RETURN_RET_ELOG(rc != HDI::Camera::V1_0::NO_ERROR, HdiToServiceError(rc),
        "HCameraDevice::GetEnabledResults failed with error Code:%{public}d", rc);
    return CAMERA_OK;
}

void HCameraDevice::CheckZoomChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    int32_t ret;
    camera_metadata_item_t item;
    ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_PREPARE_ZOOM, &item);
    if (ret == CAM_META_SUCCESS && item.count > 0) {
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
    CHECK_EXECUTE(ret == CAM_META_SUCCESS && inPrepareZoom_, ResetZoomTimer());
    return;
}

void HCameraDevice::CheckFocusChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    std::unique_lock<std::shared_mutex> lock(zoomInfoCallbackLock_);
    CHECK_RETURN(!zoomInfoCallback_);
    int32_t ret;
    camera_metadata_item_t item;
    ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_AF_REGIONS, &item);
    bool focusStatus = (ret == CAM_META_SUCCESS);

    int32_t focusMode = focusMode_;
    ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_FOCUS_MODE, &item);
    if (ret == CAM_META_SUCCESS &&  item.count != 0) {
        focusMode = static_cast<int32_t>(item.data.u8[0]);
    }

    if (focusMode_!= focusMode || focusStatus_ != focusStatus) {
        ZoomInfo zoomInfo;
        zoomInfo.zoomValue = zoomRatio_;
        zoomInfo.focusStatus = focusStatus;
        zoomInfo.focusMode = focusMode;
        zoomInfo.videoStabilizationMode = videoStabilizationMode_;
        zoomInfoCallback_(zoomInfo);
    }

    focusMode_ = focusMode;
    focusStatus_ = focusStatus;
}

void HCameraDevice::CheckVideoStabilizationChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    std::shared_lock<std::shared_mutex> lock(zoomInfoCallbackLock_);
    CHECK_RETURN(!zoomInfoCallback_);
    camera_metadata_item_t item;

    int32_t ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS || item.count == 0);
    int32_t videoStabilizationMode = static_cast<int32_t>(item.data.u8[0]);

    if (videoStabilizationMode_ != videoStabilizationMode) {
        ZoomInfo zoomInfo;
        zoomInfo.zoomValue = zoomRatio_;
        zoomInfo.focusStatus = focusStatus_;
        zoomInfo.focusMode = focusMode_;
        zoomInfo.videoStabilizationMode = videoStabilizationMode;
        zoomInfoCallback_(zoomInfo);
    }
    videoStabilizationMode_ = videoStabilizationMode;
}

bool HCameraDevice::CheckMovingPhotoSupported(int32_t mode)
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility;
    int32_t ret = cameraHostManager_->GetCameraAbility(cameraID_, cameraAbility);
    CHECK_RETURN_RET(cameraAbility == nullptr, false);
    camera_metadata_item_t metadataItem;
    std::vector<int32_t> modes = {};
    ret = OHOS::Camera::FindCameraMetadataItem(cameraAbility->get(), OHOS_ABILITY_MOVING_PHOTO,
        &metadataItem);
    if (ret == CAM_META_SUCCESS && metadataItem.count > 0) {
        uint32_t step = 3;
        for (uint32_t index = 0; index < metadataItem.count - 1;) {
            CHECK_EXECUTE(metadataItem.data.i32[index + 1] == 1, modes.push_back(metadataItem.data.i32[index]));
            MEDIA_DEBUG_LOG("CheckMovingPhotoSupported mode:%{public}d", metadataItem.data.i32[index]);
            index += step;
        }
    }
    return std::find(modes.begin(), modes.end(), mode) != modes.end();
}

void HCameraDevice::ResetZoomTimer()
{
    CameraTimer::GetInstance().Unregister(zoomTimerId_);
    CHECK_RETURN(!inPrepareZoom_);
    MEDIA_INFO_LOG("register zoom timer callback");
    uint32_t waitMs = 5 * 1000;
    auto thisPtr = wptr<HCameraDevice>(this);
    zoomTimerId_ = CameraTimer::GetInstance().Register([thisPtr]() {
        auto devicePtr = thisPtr.promote();
        CHECK_EXECUTE(devicePtr != nullptr, devicePtr->UnPrepareZoom());
    }, waitMs, true);
}

void HCameraDevice::UnPrepareZoom()
{
    MEDIA_INFO_LOG("entered.");
    std::lock_guard<std::mutex> lock(unPrepareZoomMutex_);
    CHECK_RETURN(!inPrepareZoom_);
    inPrepareZoom_ = false;
    uint32_t count = 1;
    uint32_t prepareZoomType = OHOS_CAMERA_ZOOMSMOOTH_PREPARE_DISABLE;
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = std::make_shared<OHOS::Camera::CameraMetadata>(1, 1);
    metadata->addEntry(OHOS_CONTROL_PREPARE_ZOOM, &prepareZoomType, count);
    UpdateSetting(metadata);
}

void HCameraDevice::SetFrameRateRange(const std::vector<int32_t>& frameRateRange)
{
    std::lock_guard<std::mutex> lock(fpsRangeLock_);
    frameRateRange_ = frameRateRange;
}

std::vector<int32_t> HCameraDevice::GetFrameRateRange()
{
    std::lock_guard<std::mutex> lock(fpsRangeLock_);
    return frameRateRange_;
}

void HCameraDevice::UpdateCameraRotateAngleAndZoom(std::vector<int32_t> &frameRateRange, bool isResetDegree)
{
    CameraRotateStrategyInfo strategyInfo;
    CHECK_RETURN_ELOG(!GetSigleStrategyInfo(strategyInfo), "Update roteta angle not supported");
    auto flag = false;
    CHECK_EXECUTE(strategyInfo.fps <= 0, flag = true);
    CHECK_EXECUTE(strategyInfo.fps > 0 && frameRateRange.size() > 1 &&
                  strategyInfo.fps == frameRateRange[1], flag = true);
    CHECK_RETURN(!flag);
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings = std::make_shared<OHOS::Camera::CameraMetadata>(1, 1);
    int32_t rotateDegree = GetCameraPosition() == OHOS_CAMERA_POSITION_BACK ?
        BASE_DEGREE - strategyInfo.rotateDegree : strategyInfo.rotateDegree;
    CHECK_EXECUTE(isResetDegree, rotateDegree = 0);
    MEDIA_DEBUG_LOG("HCameraDevice::UpdateCameraRotateAngleAndZoom rotateDegree: %{public}d.", rotateDegree);
    CHECK_EXECUTE(rotateDegree >= 0, settings->addEntry(OHOS_CONTROL_ROTATE_ANGLE, &rotateDegree, 1));
    float zoom = strategyInfo.wideValue;
    MEDIA_DEBUG_LOG("HCameraDevice::UpdateCameraRotateAngleAndZoom zoom: %{public}f.", zoom);
    CHECK_EXECUTE(zoom >= 0, settings->addEntry(OHOS_CONTROL_ZOOM_RATIO, &zoom, 1));
    UpdateSettingOnce(settings);
    MEDIA_INFO_LOG("UpdateCameraRotateAngleAndZoom success.");
}

int32_t HCameraDevice::GetCameraOrientation()
{
    int32_t truthCameraOrientation = -1;
    GetCorrectedCameraOrientation(usePhysicalCameraOrientation_, deviceAbility_, truthCameraOrientation);
    return truthCameraOrientation;
}

int32_t HCameraDevice::GetOriginalCameraOrientation()
{
    int32_t ret = CAM_META_FAILURE;
    int32_t sensorOrientation = -1;
    CHECK_RETURN_RET(deviceAbility_ == nullptr, sensorOrientation);
    camera_metadata_item item;
    ret = OHOS::Camera::FindCameraMetadataItem(deviceAbility_->get(), OHOS_SENSOR_ORIENTATION, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count <= 0, sensorOrientation,
        "GetOriginalCameraOrientation get sensor orientation failed");
    sensorOrientation = item.data.i32[0];
    return sensorOrientation;
}

// LCOV_EXCL_START
int32_t HCameraDevice::GetNaturalDirectionCorrect(bool& isNaturalDirectionCorrect)
{
    if (clientName_ == "") {
        int tokenId = static_cast<int32_t>(IPCSkeleton::GetCallingTokenID());
        clientName_ = GetClientNameByToken(tokenId);
    }
    std::lock_guard<std::mutex> lock(dataShareHelperMutex_);
    isNaturalDirectionCorrect = false;
    if (!CameraApplistManager::GetInstance()->GetNaturalDirectionCorrectByBundleName(clientName_,
        isNaturalDirectionCorrect)) {
        MEDIA_ERR_LOG("HCameraDevice::GetNaturalDirectionCorrect failed");
        return CAMERA_INVALID_ARG;
    }
    return CAMERA_OK;
}
// LCOV_EXCL_STOP

bool HCameraDevice::IsPhysicalCameraOrientationVariable()
{
    bool isVariable = false;
    camera_metadata_item_t item;
    CHECK_RETURN_RET(deviceAbility_ == nullptr, false);
    int ret = OHOS::Camera::FindCameraMetadataItem(deviceAbility_->get(), OHOS_ABILITY_SENSOR_ORIENTATION_VARIABLE,
        &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, 0, "HCameraDevice::GetSensorOrientation failed");
    isVariable =  item.count > 0 && item.data.u8[0];
    bool isNaturalDirectionCorrect = false;
    GetNaturalDirectionCorrect(isNaturalDirectionCorrect);
    CHECK_EXECUTE(isNaturalDirectionCorrect, isVariable = false);
    return isVariable;
}

void HCameraDevice::UpdateCameraRotateAngle()
{
    bool isFoldable = OHOS::Rosen::DisplayManager::GetInstance().IsFoldable();
    int32_t curDisplayMode = static_cast<int32_t>(OHOS::Rosen::DisplayManager::GetInstance().GetFoldDisplayMode());
    MEDIA_INFO_LOG("HCameraDevice::UpdateCameraRotateAngle lastDisplayMode: %{public}d, curDisplayMode: %{public}d",
        lastDisplayMode_, curDisplayMode);
    CHECK_RETURN(!isFoldable || deviceAbility_ == nullptr || lastDisplayMode_ == curDisplayMode);
    lastDisplayMode_ = curDisplayMode;
    if (system::GetParameter("const.system.sensor_correction_enable", "0") != "1"
        || !IsPhysicalCameraOrientationVariable()) {
        MEDIA_DEBUG_LOG("HCameraDevice::UpdateCameraRotateAngle variable orientation is closed");
        std::vector<int32_t> frameRateRange = GetFrameRateRange();
        MEDIA_INFO_LOG("HCameraDevice::UpdateCameraRotateAngle, frameRateRange size: %{public}zu, "
            "frameRateRange: %{public}s", frameRateRange.size(),
            Container2String(frameRateRange.begin(), frameRateRange.end()).c_str());
        UpdateCameraRotateAngleAndZoom(frameRateRange,
            curDisplayMode != static_cast<int32_t>(OHOS::Rosen::FoldDisplayMode::GLOBAL_FULL));
        return;
    }
    int cameraOrientation = GetOriginalCameraOrientation();
    CHECK_RETURN(cameraOrientation == -1);
    int32_t truthCameraOrientation = -1;
    int32_t ret = GetCorrectedCameraOrientation(!usePhysicalCameraOrientation_, deviceAbility_,
        truthCameraOrientation, curDisplayMode);
    CHECK_RETURN(ret != CAM_META_SUCCESS || truthCameraOrientation == -1);
    int32_t rotateDegree = (truthCameraOrientation - cameraOrientation + BASE_DEGREE) % BASE_DEGREE;
    MEDIA_INFO_LOG("HCameraDevice::UpdateCameraRotateAngle cameraOrientation: %{public}d, truthCameraOrientation: "
        "%{public}d, rotateDegree: %{public}d.", cameraOrientation, truthCameraOrientation, rotateDegree);
    CHECK_RETURN_ELOG(usePhysicalCameraOrientation_, "HCameraDevice::UpdateCameraRotateAngle do not need HAL rotate");
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings = std::make_shared<OHOS::Camera::CameraMetadata>(1, 1);
    CHECK_EXECUTE(rotateDegree >= 0, settings->addEntry(OHOS_CONTROL_ROTATE_ANGLE, &rotateDegree, 1));
    UpdateSettingOnce(settings);
    MEDIA_INFO_LOG("UpdateCameraRotateAngle success.");
}

bool HCameraDevice::GetSigleStrategyInfo(CameraRotateStrategyInfo &strategyInfo)
{
    auto infos = GetCameraRotateStrategyInfos();
    if (bundleName_ == "") {
        int uid = IPCSkeleton::GetCallingUid();
        bundleName_ = GetClientBundle(uid);
    }
    CHECK_EXECUTE(bundleName_ == "", { int uid = IPCSkeleton::GetCallingUid();
        bundleName_ = GetClientBundle(uid);});
    MEDIA_DEBUG_LOG("HCameraDevice::GetSigleStrategyInfo bundleName: %{public}s", bundleName_.c_str());
    std::string bundleName = bundleName_;
    auto it = std::find_if(infos.begin(), infos.end(), [&bundleName](const auto &info) {
        return info.bundleName == bundleName;
    });
    CHECK_RETURN_RET_ELOG(it == infos.end(), false, "Update roteta angle not supported");
    strategyInfo = *it;
    return true;
}

void HCameraDevice::SetCameraRotateStrategyInfos(std::vector<CameraRotateStrategyInfo> infos)
{
    std::lock_guard<std::mutex> lock(cameraRotateStrategyInfosLock_);
    cameraRotateStrategyInfos_ = infos;
}

std::vector<CameraRotateStrategyInfo> HCameraDevice::GetCameraRotateStrategyInfos()
{
    std::lock_guard<std::mutex> lock(cameraRotateStrategyInfosLock_);
    return cameraRotateStrategyInfos_;
}

int32_t HCameraDevice::UpdateSetting(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(settings == nullptr, CAMERA_INVALID_ARG,
        "HCameraDevice::UpdateSetting settings is null");
    CheckZoomChange(settings);
    CheckFocusChange(settings);
    CheckVideoStabilizationChange(settings);

    uint32_t count = OHOS::Camera::GetCameraMetadataItemCount(settings->get());
    CHECK_RETURN_RET_ELOG(!count, CAMERA_OK, "HCameraDevice::UpdateSetting Nothing to update");
    std::lock_guard<std::mutex> lock(opMutex_);
    if (updateSettings_ == nullptr || !CameraFwkMetadataUtils::MergeMetadata(settings, updateSettings_)) {
        updateSettings_ = settings;
    }
    MEDIA_INFO_LOG("HCameraDevice::UpdateSetting Updated device settings hdiCameraDevice_(%{public}d)",
        hdiCameraDevice_ != nullptr);
    if (hdiCameraDevice_ != nullptr) {
        std::vector<uint8_t> hdiSettings;
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(updateSettings_, hdiSettings);
        ReportMetadataDebugLog(updateSettings_);
        DumpMetadata(updateSettings_);
        CamRetCode rc = (CamRetCode)(hdiCameraDevice_->UpdateSettings(hdiSettings));
        CHECK_RETURN_RET_ELOG(rc != HDI::Camera::V1_0::NO_ERROR, HdiToServiceError(rc),
            "HCameraDevice::UpdateSetting Failed with error Code: %{public}d", rc);
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
    CHECK_RETURN_RET_ELOG(
        !CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraDevice::SetUsedAsPosition:SystemApi is called");
    usedAsPosition_ = value;
    // lockforcontrol
    return CAMERA_OK;
}

uint8_t HCameraDevice::GetUsedAsPosition()
{
    MEDIA_INFO_LOG("HCameraDevice::GetUsedAsPosition success");
    return usedAsPosition_;
}

int32_t HCameraDevice::UpdateSettingOnce(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraDevice::UpdateSettingOnce prepare execute");
    CHECK_RETURN_RET_ELOG(settings == nullptr, CAMERA_INVALID_ARG, "settings is null");
    CheckZoomChange(settings);

    uint32_t count = OHOS::Camera::GetCameraMetadataItemCount(settings->get());
    CHECK_RETURN_RET_ELOG(!count, CAMERA_OK, "Nothing to update");
    std::lock_guard<std::mutex> lock(opMutex_);
    MEDIA_INFO_LOG("Updated device settings once hdiCameraDevice_(%{public}d)", hdiCameraDevice_ != nullptr);
    if (hdiCameraDevice_ != nullptr) {
        std::vector<uint8_t> hdiSettings;
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(settings, hdiSettings);
        ReportMetadataDebugLog(settings);
        CamRetCode rc = (CamRetCode)(hdiCameraDevice_->UpdateSettings(hdiSettings));
        CHECK_RETURN_RET_ELOG(rc != HDI::Camera::V1_0::NO_ERROR, HdiToServiceError(rc),
            "Failed with error Code: %{public}d", rc);
    }
    MEDIA_INFO_LOG("HCameraDevice::UpdateSettingOnce execute success");
    return CAMERA_OK;
}

int32_t HCameraDevice::GetStatus(const std::shared_ptr<OHOS::Camera::CameraMetadata> &metaIn,
    std::shared_ptr<OHOS::Camera::CameraMetadata> &metaOut)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(metaIn == nullptr, CAMERA_INVALID_ARG, "HCameraDevice::GetStatus metaIn is null");
    uint32_t count = OHOS::Camera::GetCameraMetadataItemCount(metaIn->get());
    CHECK_RETURN_RET_ELOG(!count, CAMERA_OK, "HCameraDevice::GetStatus Nothing to query");

    sptr<OHOS::HDI::Camera::V1_2::ICameraDevice> hdiCameraDeviceV1_2;
    if (cameraHostManager_->GetVersionByCamera(cameraID_) >= HDI_VERSION_ID_1_2) {
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
        CHECK_RETURN_RET_ELOG(rc != HDI::Camera::V1_0::NO_ERROR, HdiToServiceError(rc),
            "HCameraDevice::GetStatus Failed with error Code: %{public}d", rc);
        CHECK_EXECUTE(hdiMetaOut.size() != 0, OHOS::Camera::MetadataUtils::ConvertVecToMetadata(hdiMetaOut, metaOut));
    }
    return CAMERA_OK;
}

void HCameraDevice::ReportMetadataDebugLog(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings)
{
    caller_ = CameraReportUtils::GetCallerInfo();
    for (const auto &tagInfo : reportTagInfos_) {
        std::string tagName;
        DFX_UB_NAME dfxUbStr;
        uint32_t tag;
        std::tie(tag, tagName, dfxUbStr) = tagInfo;
        DebugLogTag(settings, tag, tagName, dfxUbStr);
    }

    DebugLogForSmoothZoom(settings, OHOS_CONTROL_SMOOTH_ZOOM_RATIOS);
    DebugLogForAfRegions(settings, OHOS_CONTROL_AF_REGIONS);
    DebugLogForAeRegions(settings, OHOS_CONTROL_AE_REGIONS);
}

void HCameraDevice::DebugLogTag(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
                                uint32_t tag, std::string tagName, DFX_UB_NAME dfxUbStr)
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

    CHECK_EXECUTE(dfxUbStr != DFX_UB_NOT_REPORT,
        CameraReportUtils::GetInstance().ReportUserBehavior(dfxUbStr, valueStr, caller_));
}

void HCameraDevice::DebugLogForSmoothZoom(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag)
{
    // debug log for smooth zoom
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(settings->get(), tag, &item);
    if (ret != CAM_META_SUCCESS || item.count <= 0) {
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
    if (ret != CAM_META_SUCCESS || item.count <= 0) {
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
    if (ret != CAM_META_SUCCESS || item.count <= 0) {
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
    std::lock_guard<std::mutex> lock(foldStateListenerMutex_);
    bool isSystemApp =
        OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(IPCSkeleton::GetCallingFullTokenID()) ||
        IPCSkeleton::GetCallingUid() == FACE_CLIENT_UID;
    listener_ = new FoldScreenListener(this, cameraHostManager_, cameraID_, isSystemApp);
    if (cameraHostManager_) {
        int foldStatus = static_cast<int>(OHOS::Rosen::DisplayManager::GetInstance().GetFoldStatus());
        if (foldStatus == static_cast<int>(FoldStatus::HALF_FOLD)) {
            foldStatus = static_cast<int>(FoldStatus::EXPAND);
        }
        cameraHostManager_->NotifyDeviceStateChangeInfo(DeviceType::FOLD_TYPE, foldStatus);
    }
    auto ret = OHOS::Rosen::DisplayManager::GetInstance().RegisterFoldStatusListener(listener_);
    if (ret != OHOS::Rosen::DMError::DM_OK) {
        MEDIA_DEBUG_LOG("HCameraDevice::RegisterFoldStatusListener failed");
        listener_ = nullptr;
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::RegisterFoldStatusListener success");
    }
}

void HCameraDevice::UnregisterFoldStatusListener()
{
    std::lock_guard<std::mutex> lock(foldStateListenerMutex_);
    CHECK_RETURN_ELOG(listener_ == nullptr, "HCameraDevice::unRegisterFoldStatusListener  listener is null");
    auto ret = OHOS::Rosen::DisplayManager::GetInstance().UnregisterFoldStatusListener(listener_);
    if (ret != OHOS::Rosen::DMError::DM_OK) {
        MEDIA_DEBUG_LOG("HCameraDevice::UnregisterFoldStatusListener failed");
    }
    listener_ = nullptr;
}

void HCameraDevice::RegisterDisplayModeListener()
{
    std::lock_guard<std::mutex> lock(displayModeListenerMutex_);
    displayModeListener_ = new DisplayModeListener(this, cameraHostManager_, cameraID_);
    auto ret = OHOS::Rosen::DisplayManager::GetInstance().RegisterDisplayModeListener(displayModeListener_);
    if (ret != OHOS::Rosen::DMError::DM_OK) {
        MEDIA_DEBUG_LOG("HCameraDevice::RegisterDisplayModeListener failed");
        displayModeListener_ = nullptr;
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::RegisterDisplayModeListener success");
    }
}

void HCameraDevice::UnregisterDisplayModeListener()
{
    std::lock_guard<std::mutex> lock(displayModeListenerMutex_);
    CHECK_RETURN_ELOG(displayModeListener_ == nullptr, "HCameraDevice::UnregisterDisplayModeListener listener is null");
    auto ret = OHOS::Rosen::DisplayManager::GetInstance().UnregisterDisplayModeListener(displayModeListener_);
    CHECK_PRINT_DLOG(ret != OHOS::Rosen::DMError::DM_OK, "HCameraDevice::UnregisterDisplayModeListener failed");
    displayModeListener_ = nullptr;
}

int32_t HCameraDevice::EnableResult(const std::vector<int32_t> &results)
{
    CHECK_RETURN_RET_ELOG(results.empty(), CAMERA_INVALID_ARG, "HCameraDevice::EnableResult results is empty");
    std::lock_guard<std::mutex> lock(opMutex_);
    CHECK_RETURN_RET_ELOG(hdiCameraDevice_ == nullptr, CAMERA_UNKNOWN_ERROR,
        "HCameraDevice::hdiCameraDevice_ is null");

    CamRetCode rc = (CamRetCode)(hdiCameraDevice_->EnableResult(results));
    CHECK_RETURN_RET_ELOG(rc != HDI::Camera::V1_0::NO_ERROR, HdiToServiceError(rc),
        "HCameraDevice::EnableResult failed with error Code:%{public}d", rc);
    return CAMERA_OK;
}

int32_t HCameraDevice::SetDeviceRetryTime()
{
    MEDIA_INFO_LOG("HCameraDevice::SetDeviceRetryTime");
    g_lastDeviceDropTime = GetTimestamp();
    return CAMERA_OK;
}

int32_t HCameraDevice::DisableResult(const std::vector<int32_t> &results)
{
    CHECK_RETURN_RET_ELOG(results.empty(), CAMERA_INVALID_ARG, "HCameraDevice::DisableResult results is empty");
    std::lock_guard<std::mutex> lock(opMutex_);
    CHECK_RETURN_RET_ELOG(hdiCameraDevice_ == nullptr, CAMERA_UNKNOWN_ERROR,
        "HCameraDevice::hdiCameraDevice_ is null");

    CamRetCode rc = (CamRetCode)(hdiCameraDevice_->DisableResult(results));
    CHECK_RETURN_RET_ELOG(rc != HDI::Camera::V1_0::NO_ERROR, HdiToServiceError(rc),
        "HCameraDevice::DisableResult failed with error Code:%{public}d", rc);
    return CAMERA_OK;
}

int32_t HCameraDevice::SetCallback(const sptr<ICameraDeviceServiceCallback>& callback)
{
    if (callback == nullptr) {
        MEDIA_WARNING_LOG("HCameraDevice::SetCallback callback is null");
    }
    std::lock_guard<std::mutex> lock(deviceSvcCbMutex_);
    deviceSvcCallback_ = callback;
    return CAMERA_OK;
}

int32_t HCameraDevice::UnSetCallback()
{
    std::lock_guard<std::mutex> lock(deviceSvcCbMutex_);
    deviceSvcCallback_ = nullptr;
    return CAMERA_OK;
}

sptr<ICameraDeviceServiceCallback> HCameraDevice::GetDeviceServiceCallback()
{
    std::lock_guard<std::mutex> lock(deviceSvcCbMutex_);
    return deviceSvcCallback_;
}

void HCameraDevice::UpdateDeviceOpenLifeCycleSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> changedSettings)
{
    CHECK_RETURN(changedSettings == nullptr);
    std::lock_guard<std::mutex> lock(deviceOpenLifeCycleMutex_);
    for (auto itemTag : DEVICE_OPEN_LIFECYCLE_TAGS) {
        camera_metadata_item_t item;
        int32_t result = OHOS::Camera::FindCameraMetadataItem(changedSettings->get(), itemTag, &item);
        if (result != CAM_META_SUCCESS || item.count <= 0) {
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

int32_t HCameraDevice::GetStreamOperator(const sptr<IStreamOperatorCallback> &callbackObj,
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> &streamOperator)
{
    std::lock_guard<std::mutex> lock(opMutex_);
    proxyStreamOperatorCallback_ = callbackObj;
    CHECK_RETURN_RET_ELOG(hdiCameraDevice_ == nullptr, CAMERA_UNKNOWN_ERROR,
        "HCameraDevice::GetStreamOperator hdiCameraDevice_ is null");
    CamRetCode rc;
    sptr<OHOS::HDI::Camera::V1_1::ICameraDevice> hdiCameraDeviceV1_1;
    sptr<OHOS::HDI::Camera::V1_2::ICameraDevice> hdiCameraDeviceV1_2;
    sptr<OHOS::HDI::Camera::V1_3::ICameraDevice> hdiCameraDeviceV1_3;
    int32_t versionRes = cameraHostManager_->GetVersionByCamera(cameraID_);
    if (versionRes >= HDI_VERSION_ID_1_3) {
        MEDIA_DEBUG_LOG("HCameraDevice::GetStreamOperator ICameraDevice cast to V1_3");
        hdiCameraDeviceV1_3 = OHOS::HDI::Camera::V1_3::ICameraDevice::CastFrom(hdiCameraDevice_);
    } else if (versionRes >= HDI_VERSION_ID_1_2) {
        MEDIA_DEBUG_LOG("HCameraDevice::GetStreamOperator ICameraDevice cast to V1_2");
        hdiCameraDeviceV1_2 = OHOS::HDI::Camera::V1_2::ICameraDevice::CastFrom(hdiCameraDevice_);
    } else if (versionRes == HDI_VERSION_ID_1_1) {
        MEDIA_DEBUG_LOG("HCameraDevice::GetStreamOperator ICameraDevice cast to V1_1");
        hdiCameraDeviceV1_1 = OHOS::HDI::Camera::V1_1::ICameraDevice::CastFrom(hdiCameraDevice_);
        if (hdiCameraDeviceV1_1 == nullptr) {
            MEDIA_ERR_LOG("HCameraDevice::GetStreamOperator ICameraDevice cast to V1_1 error");
            hdiCameraDeviceV1_1 = static_cast<OHOS::HDI::Camera::V1_1::ICameraDevice*>(hdiCameraDevice_.GetRefPtr());
        }
    }

    if (hdiCameraDeviceV1_3 != nullptr && versionRes >= HDI_VERSION_ID_1_3) {
        sptr<OHOS::HDI::Camera::V1_3::IStreamOperator> streamOperator_v1_3;
        rc = (CamRetCode)(hdiCameraDeviceV1_3->GetStreamOperator_V1_3(callbackObj, streamOperator_v1_3));
        streamOperator = streamOperator_v1_3;
    } else if (hdiCameraDeviceV1_2 != nullptr && versionRes >= HDI_VERSION_ID_1_2) {
        MEDIA_DEBUG_LOG("HCameraDevice::GetStreamOperator ICameraDevice V1_2");
        sptr<OHOS::HDI::Camera::V1_2::IStreamOperator> streamOperator_v1_2;
        rc = (CamRetCode)(hdiCameraDeviceV1_2->GetStreamOperator_V1_2(callbackObj, streamOperator_v1_2));
        streamOperator = streamOperator_v1_2;
    } else if (hdiCameraDeviceV1_1 != nullptr && versionRes == HDI_VERSION_ID_1_1) {
        MEDIA_DEBUG_LOG("HCameraDevice::GetStreamOperator ICameraDevice V1_1");
        sptr<OHOS::HDI::Camera::V1_1::IStreamOperator> streamOperator_v1_1;
        rc = (CamRetCode)(hdiCameraDeviceV1_1->GetStreamOperator_V1_1(callbackObj, streamOperator_v1_1));
        streamOperator = streamOperator_v1_1;
    } else {
        MEDIA_DEBUG_LOG("HCameraDevice::GetStreamOperator ICameraDevice V1_0");
        rc = (CamRetCode)(hdiCameraDevice_->GetStreamOperator(callbackObj, streamOperator));
    }
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        MEDIA_ERR_LOG("HCameraDevice::GetStreamOperator failed with error Code:%{public}d", rc);
        CameraReportUtils::ReportCameraError(
            "HCameraDevice::GetStreamOperator", rc, true, CameraReportUtils::GetCallerInfo());
        return HdiToServiceError(rc);
    }
    return CAMERA_OK;
}

int32_t HCameraDevice::OnError(const OHOS::HDI::Camera::V1_0::ErrorType type, const int32_t errorMsg)
{
    auto errType = static_cast<OHOS::HDI::Camera::V1_3::ErrorType>(type);
    MEDIA_ERR_LOG("CameraDeviceCallback::OnError() is called!, type: %{public}d,"
                    "cameraID_: %{public}s, cameraPid: %{public}d.",
        type, cameraID_.c_str(), cameraPid_);
    if (errType == OHOS::HDI::Camera::V1_3::SENSOR_DATA_ERROR) {
        NotifyCameraStatus(HdiToCameraErrorType(errType), errorMsg);
        return CAMERA_OK;
    }
    NotifyCameraStatus(HdiToCameraErrorType(errType));
    auto callback = GetDeviceServiceCallback();
    if (callback != nullptr) {
        int32_t errorType;
        if (type == OHOS::HDI::Camera::V1_0::REQUEST_TIMEOUT) {
            errorType = CAMERA_DEVICE_REQUEST_TIMEOUT;
        } else if (type == OHOS::HDI::Camera::V1_0::DEVICE_PREEMPT) {
            errorType = CAMERA_DEVICE_PREEMPTED;
        } else if (type == DEVICE_DISCONNECT) {
            errorType = CAMERA_DEVICE_CLOSED;
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
    CHECK_RETURN_ELOG(cameraResult == nullptr, "HCameraDevice::OnResult cameraResult is nullptr");
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = cameraResult->get();
    int ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FLASH_MODE, &item);
    if (ret == 0 && item.count > 0) {
        MEDIA_DEBUG_LOG("Flash mode: %{public}d", item.data.u8[0]);
    }
    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FLASH_STATE, &item);
    if (ret == 0 && item.count > 0) {
        MEDIA_DEBUG_LOG("Flash state: %{public}d", item.data.u8[0]);
    }
    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FOCUS_MODE, &item);
    if (ret == CAM_META_SUCCESS && item.count > 0) {
        MEDIA_DEBUG_LOG("Focus mode: %{public}d", item.data.u8[0]);
    }
    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_QUALITY_PRIORITIZATION, &item);
    if (ret == CAM_META_SUCCESS && item.count > 0) {
        MEDIA_DEBUG_LOG("quality prioritization: %{public}d", item.data.u8[0]);
    }
    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FOCUS_STATE, &item);
    if (ret == CAM_META_SUCCESS && item.count > 0) {
        MEDIA_DEBUG_LOG("Focus state: %{public}d", item.data.u8[0]);
    }
    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_STATISTICS_FACE_RECTANGLES, &item);
    CHECK_PRINT_ELOG(
        ret != CAM_META_SUCCESS || item.count <= 0, "cannot find OHOS_STATISTICS_FACE_RECTANGLES: %{public}d", ret);
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
    CHECK_RETURN_RET_ELOG(result.size() == 0, CAMERA_INVALID_ARG, "onResult get null meta from HAL");
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult = nullptr;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(result, cameraResult);
    if (cameraResult == nullptr) {
        cameraResult = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
    }
    CHECK_EXECUTE(IsCameraDebugOn(), CameraFwkMetadataUtils::DumpMetadataInfo(cameraResult));
    auto callback = GetDeviceServiceCallback();
    CHECK_EXECUTE(callback != nullptr, callback->OnResult(timestamp, cameraResult));
    ReportDeviceProtectionStatus(cameraResult);
    CHECK_EXECUTE(IsCameraDebugOn(), CheckOnResultData(cameraResult));
    CHECK_EXECUTE(isMovingPhotoEnabled_, GetMovingPhotoStartAndEndTime(cameraResult));
    ReportZoomInfos(cameraResult);
    return CAMERA_OK;
}

void HCameraDevice::GetMovingPhotoStartAndEndTime(std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult)
{
    MEDIA_DEBUG_LOG("HCameraDevice::GetMovingPhotoStartAndEndTime enter.");
    {
        std::lock_guard<std::mutex> lock(movingPhotoStartTimeCallbackLock_);
        if (movingPhotoStartTimeCallback_) {
            camera_metadata_item_t item;
            int ret = OHOS::Camera::FindCameraMetadataItem(cameraResult->get(), OHOS_MOVING_PHOTO_START, &item);
            if (ret == CAM_META_SUCCESS && item.count != 0) {
                int64_t captureId = item.data.i64[0];
                int64_t startTime = item.data.i64[1];
                movingPhotoStartTimeCallback_(static_cast<int32_t>(captureId), startTime);
            }
        }
    }
    std::lock_guard<std::mutex> lock(movingPhotoEndTimeCallbackLock_);
    if (movingPhotoEndTimeCallback_) {
        camera_metadata_item_t item;
        int ret = OHOS::Camera::FindCameraMetadataItem(cameraResult->get(), OHOS_MOVING_PHOTO_END, &item);
        if (ret == CAM_META_SUCCESS && item.count != 0) {
            int64_t captureId = item.data.i64[0];
            int64_t endTime = item.data.i64[1];
            movingPhotoEndTimeCallback_(static_cast<int32_t>(captureId), endTime);
        }
    }
}

void HCameraDevice::SetMovingPhotoStartTimeCallback(std::function<void(int64_t, int64_t)> callback)
{
    std::lock_guard<std::mutex> lock(movingPhotoStartTimeCallbackLock_);
    movingPhotoStartTimeCallback_ = callback;
}

void HCameraDevice::SetMovingPhotoEndTimeCallback(std::function<void(int64_t, int64_t)> callback)
{
    std::lock_guard<std::mutex> lock(movingPhotoEndTimeCallbackLock_);
    movingPhotoEndTimeCallback_ = callback;
}

void HCameraDevice::ReportZoomInfos(std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult)
{
    std::shared_lock<std::shared_mutex> lock(zoomInfoCallbackLock_);
    CHECK_RETURN(!zoomInfoCallback_);
    float zoomRatio = 1.0;
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(cameraResult->get(), OHOS_CONTROL_ZOOM_RATIO, &item);
    CHECK_RETURN(ret != CAM_META_SUCCESS || item.count == 0);
    zoomRatio = item.data.f[0];
    MEDIA_DEBUG_LOG("ReportZoomInfos zoomRatio: %{public}f", zoomRatio);
    if (zoomRatio != zoomRatio_) {
        ZoomInfo zoomInfo;
        zoomInfo.zoomValue = zoomRatio;
        zoomInfo.focusStatus = focusStatus_;
        zoomInfo.focusMode = focusMode_;
        zoomInfo.videoStabilizationMode = videoStabilizationMode_;
        zoomInfoCallback_(zoomInfo);
    }
    zoomRatio_ = zoomRatio;
}

void HCameraDevice::SetZoomInfoCallback(std::function<void(ZoomInfo)> callback)
{
    MEDIA_DEBUG_LOG("HCameraDevice::SetZoomInfoCallback enter.");
    std::unique_lock<std::shared_mutex> lock(zoomInfoCallbackLock_);
    zoomInfoCallback_ = callback;
}

int32_t HCameraDevice::GetCallerToken()
{
    return callerToken_;
}

bool HCameraDevice::CanOpenCamera()
{
    int32_t cost;
    std::set<std::string> conflicting;
    if (GetCameraResourceCost(cost, conflicting)) {
        int32_t uidOfRequestProcess = IPCSkeleton::GetCallingUid();
        int32_t pidOfRequestProcess = IPCSkeleton::GetCallingPid();
        uint32_t accessTokenIdOfRequestProc = IPCSkeleton::GetCallingTokenID();
        uint32_t firstTokenIdOfRequestProcess = IPCSkeleton::GetFirstTokenID();

        sptr<HCameraDeviceHolder> cameraRequestOpen = new HCameraDeviceHolder(
            pidOfRequestProcess, uidOfRequestProcess, 0, 0, this, accessTokenIdOfRequestProc, cost, conflicting,
            firstTokenIdOfRequestProcess);

        std::vector<sptr<HCameraDeviceHolder>> evictedClients;
        bool ret = HCameraDeviceManager::GetInstance()->HandleCameraEvictions(evictedClients, cameraRequestOpen);
        // close evicted clients
        for (auto &camera : evictedClients) {
            MEDIA_DEBUG_LOG("HCameraDevice::CanOpenCamera open current device need to close");
            camera->GetDevice()->OnError(DEVICE_PREEMPT, 0);
            camera->GetDevice()->CloseDevice();
        }
        return ret;
    }
    std::vector<sptr<HCameraDevice>> cameraNeedEvict;
    bool ret = HCameraDeviceManager::GetInstance()->GetConflictDevices(cameraNeedEvict, this, cameraConcurrentType_);
    if (cameraNeedEvict.size() != 0) {
        MEDIA_DEBUG_LOG("HCameraDevice::CanOpenCamera open current device need to close other devices");
        for (auto deviceItem : cameraNeedEvict) {
            deviceItem->OnError(DEVICE_PREEMPT, 0);
            deviceItem->CloseDevice();
        }
    }
    return ret;
}

bool HCameraDevice::GetCameraResourceCost(int32_t &cost, std::set<std::string> &conflicting)
{
    OHOS::HDI::Camera::V1_3::CameraDeviceResourceCost resourceCost;
    int32_t errorCode = cameraHostManager_->GetCameraResourceCost(cameraID_, resourceCost);
    CHECK_RETURN_RET_ELOG(errorCode != CAMERA_OK, false, "GetCameraResourceCost failed");
    cost = static_cast<int32_t>(resourceCost.resourceCost_);
    for (size_t i = 0; i < resourceCost.conflictingDevices_.size(); i++) {
        conflicting.emplace(resourceCost.conflictingDevices_[i]);
    }
    return true;
}

int32_t HCameraDevice::OperatePermissionCheck(uint32_t interfaceCode)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t errCode = CheckPermission(OHOS_PERMISSION_CAMERA, callerToken);
    CHECK_RETURN_RET(errCode != CAMERA_OK, errCode);
    switch (static_cast<ICameraDeviceServiceIpcCode>(interfaceCode)) {
        case ICameraDeviceServiceIpcCode::COMMAND_OPEN:
        case ICameraDeviceServiceIpcCode::COMMAND_CLOSE:
        case ICameraDeviceServiceIpcCode::COMMAND_RELEASE:
        case ICameraDeviceServiceIpcCode::COMMAND_SET_CALLBACK:
        case ICameraDeviceServiceIpcCode::COMMAND_UN_SET_CALLBACK:
        case ICameraDeviceServiceIpcCode::COMMAND_UPDATE_SETTING:
        case ICameraDeviceServiceIpcCode::COMMAND_SET_USED_AS_POSITION:
        case ICameraDeviceServiceIpcCode::COMMAND_GET_ENABLED_RESULTS:
        case ICameraDeviceServiceIpcCode::COMMAND_ENABLE_RESULT:
        case ICameraDeviceServiceIpcCode::COMMAND_DISABLE_RESULT: {
            CHECK_RETURN_RET_ELOG(callerToken_ != callerToken, CAMERA_OPERATION_NOT_ALLOWED,
                "HCameraDevice::OperatePermissionCheck fail, callerToken_ is : %{public}d, now token "
                "is %{public}d", callerToken_, callerToken);
            break;
        }
        default:
            break;
    }
    return CAMERA_OK;
}

int32_t HCameraDevice::CallbackEnter([[maybe_unused]] uint32_t code)
{
    MEDIA_DEBUG_LOG("start, code:%{public}u", code);
    DisableJeMalloc();
    int32_t errCode = OperatePermissionCheck(code);
    CHECK_RETURN_RET_ELOG(errCode != CAMERA_OK, errCode, "HCameraDevice::OperatePermissionCheck fail");
    return CAMERA_OK;
}
int32_t HCameraDevice::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    MEDIA_DEBUG_LOG("leave, code:%{public}u, result:%{public}d", code, result);
    return CAMERA_OK;
}
void HCameraDevice::RemoveResourceWhenHostDied()
{
    MEDIA_DEBUG_LOG("HCameraDevice::RemoveResourceWhenHostDied start");
    CAMERA_SYNC_TRACE;
    bool isFoldable = OHOS::Rosen::DisplayManager::GetInstance().IsFoldable();
    if (isFoldable) {
        UnregisterFoldStatusListener();
        UnregisterDisplayModeListener();
    }
    HCameraDeviceManager::GetInstance()->RemoveDevice(cameraID_);
    if (cameraHostManager_) {
        cameraHostManager_->RemoveCameraDevice(cameraID_);
        cameraHostManager_->UpdateRestoreParamCloseTime(clientName_, cameraID_);
    }
    POWERMGR_SYSEVENT_CAMERA_DISCONNECT(cameraID_.c_str());
    NotifyCameraStatus(CAMERA_CLOSE);
#ifdef MEMMGR_OVERRID
    RequireMemory(Memory::CAMERA_END);
#endif
    HandlePrivacyAfterCloseDevice();
    MEDIA_DEBUG_LOG("HCameraDevice::RemoveResourceWhenHostDied end");
}

void HCameraDevice::NotifyCameraStatus(int32_t state, int32_t msg)
{
    OHOS::AAFwk::Want want;
    MEDIA_DEBUG_LOG("HCameraDevice::NotifyCameraStatus strat");
    want.SetAction(COMMON_EVENT_CAMERA_STATUS);
    want.SetParam(CLIENT_USER_ID, clientUserId_);
    want.SetParam(CAMERA_ID, cameraID_);
    want.SetParam(CAMERA_STATE, state);
    int32_t type = GetCameraType();
    want.SetParam(IS_SYSTEM_CAMERA, type);
    want.SetParam(CAMERA_MSG, msg);
    want.SetParam(CLIENT_NAME, clientName_);
    MEDIA_DEBUG_LOG(
        "OnCameraStatusChanged userId: %{public}d, cameraId: %{public}s, state: %{public}d, "
        "cameraType: %{public}d, msg: %{public}d, clientName: %{public}s",
        clientUserId_, cameraID_.c_str(), state, type, msg, clientName_.c_str());
    EventFwk::CommonEventData CommonEventData { want };
    EventFwk::CommonEventPublishInfo publishInfo;
    std::vector<std::string> permissionVec { OHOS_PERMISSION_MANAGE_CAMERA_CONFIG };
    publishInfo.SetSubscriberPermissions(permissionVec);
    EventFwk::CommonEventManager::PublishCommonEvent(CommonEventData, publishInfo);
    MEDIA_DEBUG_LOG("HCameraDevice::NotifyCameraStatus end");
}

int32_t HCameraDevice::Open(int32_t concurrentType)
{
    CAMERA_SYNC_TRACE;
    CameraXCollie cameraXCollie("HandleOpenConcurrent");
    std::lock_guard<std::mutex> lock(g_deviceOpenCloseMutex_);
    CHECK_PRINT_ELOG(isOpenedCameraDevice_.load(), "HCameraDevice::Open failed, camera is busy");
    CHECK_RETURN_RET_ELOG(!IsInForeGround(callerToken_), CAMERA_ALLOC_ERROR,
        "HCameraDevice::Open IsAllowedUsingPermission failed");
    MEDIA_INFO_LOG(
        "HCameraDevice::Open Camera width concurrent:[%{public}s, %{public}d]", cameraID_.c_str(), concurrentType);
    SetCameraConcurrentType(concurrentType);
    EnableDeviceOpenedByConcurrent(true);
    int32_t result = OpenDevice();
    return result;
}

std::vector<std::vector<std::int32_t>> HCameraDevice::GetConcurrentDevicesTable()
{
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability = GetDeviceAbility();
    std::vector<std::vector<std::int32_t>> resultTable;
    CHECK_RETURN_RET(ability == nullptr, resultTable);
    std::vector<std::int32_t> concurrentList;
    int32_t ret;
    camera_metadata_item_t item;
    ret = OHOS::Camera::FindCameraMetadataItem(ability->get(), OHOS_ABILITY_CONCURRENT_SUPPORTED_CAMERAS, &item);
    if (ret == CAM_META_SUCCESS && item.count > 0) {
        for (uint32_t index = 0; index < item.count; index++) {
            int32_t cameraId = item.data.i32[index];
            if (cameraId == -1) {
                resultTable.push_back(concurrentList);
                concurrentList.clear();
            } else {
                concurrentList.push_back(cameraId);
            }
        }
    }
    resultTable.push_back(concurrentList);
    concurrentList.clear();
    MEDIA_INFO_LOG("HCameraDevice::GetConcurrentDevicesTable device id : %{public}s"
        "find concurrent table size: %{public}zu", cameraID_.c_str(), resultTable.size());
    return resultTable;
}

#ifdef CAMERA_LIVE_SCENE_RECOGNITION
void HCameraDevice::UpdateLiveStreamSceneMetadata(uint32_t mode)
{
    constexpr int32_t DEFAULT_ITEMS = 1;
    constexpr int32_t DEFAULT_DATA_LENGTH = 1;
    int32_t count = 1;
    shared_ptr<OHOS::Camera::CameraMetadata> changedMetadata =
        make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    CHECK_RETURN_ELOG(changedMetadata == nullptr, "changedMetadata is nullptr");
    bool status = AddOrUpdateMetadata(changedMetadata, OHOS_CONTROL_APP_HINT, &mode, count);
    CHECK_RETURN_ELOG(!status, "AddOrUpdateMetadata camera live scene Failed");
    int32_t ret = UpdateSetting(changedMetadata);
    CHECK_RETURN_ELOG(ret != CAMERA_OK, "UpdateSetting camera live scene Failed");
    return;
}
#endif
} // namespace CameraStandard
} // namespace OHOS
