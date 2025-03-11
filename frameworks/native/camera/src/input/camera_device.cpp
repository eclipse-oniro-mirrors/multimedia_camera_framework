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

#include <mutex>
#include <securec.h>
#include "camera_metadata_info.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_rotation_api_utils.h"
#include "input/camera_device.h"
#include "input/camera_manager.h"
#include "metadata_common_utils.h"
#include "capture_scene_const.h"

using namespace std;

namespace OHOS {
namespace CameraStandard {
const std::unordered_map<camera_type_enum_t, CameraType> CameraDevice::metaToFwCameraType_ = {
    {OHOS_CAMERA_TYPE_WIDE_ANGLE, CAMERA_TYPE_WIDE_ANGLE},
    {OHOS_CAMERA_TYPE_ULTRA_WIDE, CAMERA_TYPE_ULTRA_WIDE},
    {OHOS_CAMERA_TYPE_TELTPHOTO, CAMERA_TYPE_TELEPHOTO},
    {OHOS_CAMERA_TYPE_TRUE_DEAPTH, CAMERA_TYPE_TRUE_DEPTH},
    {OHOS_CAMERA_TYPE_LOGICAL, CAMERA_TYPE_UNSUPPORTED},
    {OHOS_CAMERA_TYPE_UNSPECIFIED, CAMERA_TYPE_DEFAULT}
};

const std::unordered_map<camera_position_enum_t, CameraPosition> CameraDevice::metaToFwCameraPosition_ = {
    {OHOS_CAMERA_POSITION_FRONT, CAMERA_POSITION_FRONT},
    {OHOS_CAMERA_POSITION_BACK, CAMERA_POSITION_BACK},
    {OHOS_CAMERA_POSITION_OTHER, CAMERA_POSITION_UNSPECIFIED}
};

const std::unordered_map<camera_connection_type_t, ConnectionType> CameraDevice::metaToFwConnectionType_ = {
    {OHOS_CAMERA_CONNECTION_TYPE_REMOTE, CAMERA_CONNECTION_REMOTE},
    {OHOS_CAMERA_CONNECTION_TYPE_USB_PLUGIN, CAMERA_CONNECTION_USB_PLUGIN},
    {OHOS_CAMERA_CONNECTION_TYPE_BUILTIN, CAMERA_CONNECTION_BUILT_IN}
};

const std::unordered_map<camera_foldscreen_enum_t, CameraFoldScreenType> CameraDevice::metaToFwCameraFoldScreenType_ = {
    {OHOS_CAMERA_FOLDSCREEN_INNER, CAMERA_FOLDSCREEN_INNER},
    {OHOS_CAMERA_FOLDSCREEN_OUTER, CAMERA_FOLDSCREEN_OUTER},
    {OHOS_CAMERA_FOLDSCREEN_OTHER, CAMERA_FOLDSCREEN_UNSPECIFIED}
};

CameraDevice::CameraDevice(std::string cameraID, std::shared_ptr<Camera::CameraMetadata> metadata)
    : cameraID_(cameraID), baseAbility_(MetadataCommonUtils::CopyMetadata(metadata)),
      cachedMetadata_(MetadataCommonUtils::CopyMetadata(metadata))
{
    CHECK_EXECUTE(metadata != nullptr, init(metadata->get()));
}

CameraDevice::CameraDevice(
    std::string cameraID, std::shared_ptr<OHOS::Camera::CameraMetadata> metadata, dmDeviceInfo deviceInfo)
    : cameraID_(cameraID), baseAbility_(MetadataCommonUtils::CopyMetadata(metadata)),
      cachedMetadata_(MetadataCommonUtils::CopyMetadata(metadata))
{
    dmDeviceInfo_.deviceName = deviceInfo.deviceName;
    dmDeviceInfo_.deviceTypeId = deviceInfo.deviceTypeId;
    dmDeviceInfo_.networkId = deviceInfo.networkId;
    MEDIA_INFO_LOG("camera cameraid = %{public}s, devicename: = %{public}s", cameraID_.c_str(),
        dmDeviceInfo_.deviceName.c_str());
    if (metadata != nullptr) {
        init(metadata->get());
    }
}

CameraDevice::CameraDevice(
    std::string cameraID, dmDeviceInfo deviceInfo, std::shared_ptr<OHOS::Camera::CameraMetadata> metadata)
    : cameraID_(cameraID)
{
    dmDeviceInfo_.deviceName = deviceInfo.deviceName;
    dmDeviceInfo_.deviceTypeId = deviceInfo.deviceTypeId;
    dmDeviceInfo_.networkId = deviceInfo.networkId;
    MEDIA_INFO_LOG("camera cameraid = %{public}s, devicename: = %{public}s", cameraID_.c_str(),
        dmDeviceInfo_.deviceName.c_str());
    CHECK_EXECUTE(metadata != nullptr, init(metadata->get()));
}

bool CameraDevice::isFindModuleTypeTag(uint32_t &tagId)
{
    std::vector<vendorTag_t> infos;
    int32_t ret = OHOS::Camera::GetAllVendorTags(infos);
    if (ret == CAM_META_SUCCESS) {
        for (auto info : infos) {
            std::string tagName = info.tagName;
            if (tagName == "hwSensorName") {
                tagId = info.tagId;
                return true;
            }
        }
    }
    return false;
}

void CameraDevice::init(common_metadata_header_t* metadata)
{
    camera_metadata_item_t item;
    
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_POSITION, &item);
    if (ret == CAM_META_SUCCESS) {
        auto itr = metaToFwCameraPosition_.find(static_cast<camera_position_enum_t>(item.data.u8[0]));
        if (itr != metaToFwCameraPosition_.end()) {
            cameraPosition_ = itr->second;
        }
    }

    ret = Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_TYPE, &item);
    if (ret == CAM_META_SUCCESS) {
        auto itr = metaToFwCameraType_.find(static_cast<camera_type_enum_t>(item.data.u8[0]));
        if (itr != metaToFwCameraType_.end()) {
            cameraType_ = itr->second;
        }
    }

    ret = Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &item);
    if (ret == CAM_META_SUCCESS) {
        auto itr = metaToFwConnectionType_.find(static_cast<camera_connection_type_t>(item.data.u8[0]));
        if (itr != metaToFwConnectionType_.end()) {
            connectionType_ = itr->second;
        }
    }

    ret = Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_FOLDSCREEN_TYPE, &item);
    if (ret == CAM_META_SUCCESS) {
        auto itr = metaToFwCameraFoldScreenType_.find(static_cast<camera_foldscreen_enum_t>(item.data.u8[0]));
        if (itr != metaToFwCameraFoldScreenType_.end()) {
            foldScreenType_ = itr->second;
        }
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_SENSOR_ORIENTATION, &item);
    if (ret == CAM_META_SUCCESS) {
        cameraOrientation_ = static_cast<uint32_t>(item.data.i32[0]);
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_IS_RETRACTABLE, &item);
    if (ret == CAM_META_SUCCESS) {
        isRetractable_ = static_cast<bool>(item.data.u8[0]);
        MEDIA_INFO_LOG("Get isRetractable_  = %{public}d", isRetractable_);
    }

    uint32_t moduleTypeTagId;
    if (isFindModuleTypeTag(moduleTypeTagId)) {
        ret = Camera::FindCameraMetadataItem(metadata, moduleTypeTagId, &item);
        if (ret == CAM_META_SUCCESS) {
            moduleType_ = item.data.ui32[0];
        }
    }

    ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_FOLD_STATUS, &item);

    foldStatus_ = (ret == CAM_META_SUCCESS) ? item.data.u8[0] : OHOS_CAMERA_FOLD_STATUS_NONFOLDABLE;

    ret = Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CAMERA_MODES, &item);
    if (ret == CAM_META_SUCCESS) {
        for (uint32_t i = 0; i < item.count; i++) {
            auto it = g_metaToFwSupportedMode_.find(static_cast<HDI::Camera::V1_3::OperationMode>(item.data.u8[i]));
            if (it != g_metaToFwSupportedMode_.end()) {
                supportedModes_.emplace_back(it->second);
            }
        }
    }

    ret = Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_STATISTICS_DETECT_TYPE, &item);
    if (ret == CAM_META_SUCCESS) {
        for (uint32_t i = 0; i < item.count; i++) {
            auto iterator = g_metaToFwCameraMetaDetect_.find(static_cast<StatisticsDetectType>(item.data.u8[i]));
            if (iterator != g_metaToFwCameraMetaDetect_.end()) {
                objectTypes_.push_back(iterator->second);
            }
        }
    }

    ret = Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_PRELAUNCH_AVAILABLE, &item);

    isPrelaunch_ = (ret == CAM_META_SUCCESS && item.data.u8[0] == 1);

    MEDIA_INFO_LOG("camera position: %{public}d, camera type: %{public}d, camera connection type: %{public}d, "
                   "camera foldScreen type: %{public}d, camera orientation: %{public}d, isretractable: %{public}d, "
                   "moduleType: %{public}u, foldStatus: %{public}d", cameraPosition_, cameraType_, connectionType_,
                   foldScreenType_, cameraOrientation_, isRetractable_, moduleType_, foldStatus_);
}

std::string CameraDevice::GetID()
{
    return cameraID_;
}

std::shared_ptr<Camera::CameraMetadata> CameraDevice::GetMetadata()
{
    std::lock_guard<std::mutex> lock(cachedMetadataMutex_);
    CHECK_ERROR_RETURN_RET(cachedMetadata_ != nullptr, cachedMetadata_);
    auto cameraProxy = CameraManager::GetInstance()->GetServiceProxy();
    CHECK_ERROR_RETURN_RET_LOG(cameraProxy == nullptr, nullptr, "GetMetadata Failed to get cameraProxy");
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata;
    cameraProxy->GetCameraAbility(cameraID_, metadata);
    return metadata;
}

std::shared_ptr<Camera::CameraMetadata> CameraDevice::GetCachedMetadata()
{
    std::lock_guard<std::mutex> lock(cachedMetadataMutex_);
    return cachedMetadata_;
}

void CameraDevice::AddMetadata(std::shared_ptr<OHOS::Camera::CameraMetadata> srcMetadata)
{
    std::lock_guard<std::mutex> lock(cachedMetadataMutex_);
    cachedMetadata_ = MetadataCommonUtils::CopyMetadata(srcMetadata);
}

void CameraDevice::ResetMetadata()
{
    std::lock_guard<std::mutex> lock(cachedMetadataMutex_);
    CHECK_ERROR_RETURN(cachedMetadata_ == nullptr);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = GetCameraAbility();
    cachedMetadata_ = MetadataCommonUtils::CopyMetadata(metadata);
}

const std::shared_ptr<OHOS::Camera::CameraMetadata> CameraDevice::GetCameraAbility()
{
    auto cameraProxy = CameraManager::GetInstance()->GetServiceProxy();
    CHECK_ERROR_RETURN_RET_LOG(cameraProxy == nullptr, nullptr, "GetCameraAbility Failed to get cameraProxy");
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata;
    cameraProxy->GetCameraAbility(cameraID_, metadata);
    return metadata;
}

CameraPosition CameraDevice::GetPosition()
{
    uint32_t apiCompatibleVersion = CameraApiVersion::GetApiVersion();
    auto foldType = CameraManager::GetInstance()->GetFoldScreenType();
    if (apiCompatibleVersion < CameraApiVersion::APIVersion::API_FOURTEEN && cameraPosition_ == CAMERA_POSITION_FRONT &&
        (foldScreenType_ == CAMERA_FOLDSCREEN_INNER || foldStatus_ == OHOS_CAMERA_FOLD_STATUS_EXPANDED) &&
        !foldType.empty() && (foldType[0] == '1' || foldType[0] == '4')) {
        cameraPosition_ = CAMERA_POSITION_FOLD_INNER;
    }
    return cameraPosition_;
}

CameraPosition CameraDevice::GetUsedAsPosition()
{
    return usedAsCameraPosition_;
}

CameraType CameraDevice::GetCameraType()
{
    return cameraType_;
}

ConnectionType CameraDevice::GetConnectionType()
{
    return connectionType_;
}

CameraFoldScreenType CameraDevice::GetCameraFoldScreenType()
{
    return foldScreenType_;
}

std::vector<SceneMode> CameraDevice::GetSupportedModes() const
{
    return supportedModes_;
}

std::vector<MetadataObjectType> CameraDevice::GetObjectTypes() const
{
    return objectTypes_;
}

bool CameraDevice::IsPrelaunch() const
{
    return isPrelaunch_;
}

std::string CameraDevice::GetHostName()
{
    return dmDeviceInfo_.deviceName;
}

uint16_t CameraDevice::GetDeviceType()
{
    return dmDeviceInfo_.deviceTypeId;
}

std::string CameraDevice::GetNetWorkId()
{
    return dmDeviceInfo_.networkId;
}

uint32_t CameraDevice::GetCameraOrientation()
{
    return cameraOrientation_;
}

bool CameraDevice::GetisRetractable()
{
    return isRetractable_;
}

uint32_t CameraDevice::GetModuleType()
{
    return moduleType_;
}

std::vector<float> CameraDevice::GetZoomRatioRange()
{
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    std::vector<float> range;

    CHECK_ERROR_RETURN_RET(!zoomRatioRange_.empty(), zoomRatioRange_);

    int ret;
    uint32_t zoomRangeCount = 2;
    camera_metadata_item_t item;

    CHECK_ERROR_RETURN_RET_LOG(cachedMetadata_ == nullptr, {},
        "Failed to get zoom ratio range with cachedMetadata_ is nullptr");
    ret = Camera::FindCameraMetadataItem(cachedMetadata_->get(), OHOS_ABILITY_ZOOM_RATIO_RANGE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, {},
        "Failed to get zoom ratio range with return code %{public}d", ret);
    CHECK_ERROR_RETURN_RET_LOG(item.count != zoomRangeCount, {},
        "Failed to get zoom ratio range with return code %{public}d", ret);
    range = {item.data.f[minIndex], item.data.f[maxIndex]};

    CHECK_ERROR_RETURN_RET_LOG(range[minIndex] > range[maxIndex], {},
        "Invalid zoom range. min: %{public}f, max: %{public}f", range[minIndex], range[maxIndex]);
    MEDIA_DEBUG_LOG("Zoom range min: %{public}f, max: %{public}f", range[minIndex], range[maxIndex]);

    zoomRatioRange_ = range;
    return zoomRatioRange_;
}

void CameraDevice::SetProfile(sptr<CameraOutputCapability> capability)
{
    CHECK_ERROR_RETURN(capability == nullptr);
    modePreviewProfiles_[NORMAL] = capability->GetPreviewProfiles();
    modePhotoProfiles_[NORMAL] = capability->GetPhotoProfiles();
    modeVideoProfiles_[NORMAL] = capability->GetVideoProfiles();
    modeDepthProfiles_[NORMAL] = capability->GetDepthProfiles();
    modePreviewProfiles_[CAPTURE] = capability->GetPreviewProfiles();
    modePhotoProfiles_[CAPTURE] = capability->GetPhotoProfiles();
    modeDepthProfiles_[CAPTURE] = capability->GetDepthProfiles();
    modePreviewProfiles_[VIDEO] = capability->GetPreviewProfiles();
    modePhotoProfiles_[VIDEO] = capability->GetPhotoProfiles();
    modeVideoProfiles_[VIDEO] = capability->GetVideoProfiles();
    modeDepthProfiles_[VIDEO] = capability->GetDepthProfiles();
}

void CameraDevice::SetProfile(sptr<CameraOutputCapability> capability, int32_t modeName)
{
    CHECK_ERROR_RETURN(capability == nullptr);
    modePreviewProfiles_[modeName] = capability->GetPreviewProfiles();
    modePhotoProfiles_[modeName] = capability->GetPhotoProfiles();
    modeVideoProfiles_[modeName] = capability->GetVideoProfiles();
    modeDepthProfiles_[modeName] = capability->GetDepthProfiles();
}

std::vector<float> CameraDevice::GetExposureBiasRange()
{
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    uint32_t biasRangeCount = 2;

    if (isConcurrentLimted_ == 1) {
        std::vector<float> compensationRangeLimted = {};
        for (int i = 0; i < limtedCapabilitySave_.compensation.count; i++) {
            float num = static_cast<float>(limtedCapabilitySave_.compensation.range[i]);
            compensationRangeLimted.push_back(num);
        }
        exposureBiasRange_ = compensationRangeLimted;
        return exposureBiasRange_;
    }

    CHECK_ERROR_RETURN_RET(!exposureBiasRange_.empty(), exposureBiasRange_);

    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(GetMetadata()->get(), OHOS_ABILITY_AE_COMPENSATION_RANGE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, {},
        "Failed to get exposure compensation range with return code %{public}d", ret);
    CHECK_ERROR_RETURN_RET_LOG(item.count != biasRangeCount, {},
        "Invalid exposure compensation range count: %{public}d", item.count);
    int32_t minRange = item.data.i32[minIndex];
    int32_t maxRange = item.data.i32[maxIndex];

    CHECK_ERROR_RETURN_RET_LOG(minRange > maxRange, {},
        "Invalid exposure compensation range. min: %{public}d, max: %{public}d", minRange, maxRange);

    MEDIA_DEBUG_LOG("Exposure hdi compensation min: %{public}d, max: %{public}d", minRange, maxRange);
    exposureBiasRange_ = { static_cast<float>(minRange), static_cast<float>(maxRange) };
    return exposureBiasRange_;
}

void CameraDevice::SetCameraDeviceUsedAsPosition(CameraPosition usedAsPosition)
{
    MEDIA_INFO_LOG("CameraDevice::SetCameraDeviceUsedAsPosition params: %{public}u", usedAsPosition);
    usedAsCameraPosition_ = usedAsPosition;
}

uint32_t CameraDevice::GetSupportedFoldStatus()
{
    return foldStatus_;
}
} // namespace CameraStandard
} // namespace OHOS
