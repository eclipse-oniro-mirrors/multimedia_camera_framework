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
#include "input/camera_device.h"
#include "metadata_common_utils.h"

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
    if (metadata != nullptr) {
        init(metadata->get());
    }
}

CameraDevice::CameraDevice(
    std::string cameraID, std::shared_ptr<OHOS::Camera::CameraMetadata> metadata, dmDeviceInfo deviceInfo)
    : cameraID_(cameraID), baseAbility_(MetadataCommonUtils::CopyMetadata(metadata)),
      cachedMetadata_(MetadataCommonUtils::CopyMetadata(metadata))
{
    dmDeviceInfo_.deviceName = deviceInfo.deviceName;
    dmDeviceInfo_.deviceTypeId = deviceInfo.deviceTypeId;
    dmDeviceInfo_.networkId = deviceInfo.networkId;
    MEDIA_INFO_LOG("camera cameraid = %{public}s, devicename: = %{public}s, networkId = %{public}s", cameraID_.c_str(),
        dmDeviceInfo_.deviceName.c_str(), dmDeviceInfo_.networkId.c_str());
    if (metadata != nullptr) {
        init(metadata->get());
    }
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

    ret = Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &item);
    if (ret == CAM_META_SUCCESS) {
        isMirrorSupported_ = ((item.data.u8[0] == 1) || (item.data.u8[0] == 0));
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
        cameraOrientation_ = item.data.i32[0];
    }

    uint32_t moduleTypeTagId;
    if (isFindModuleTypeTag(moduleTypeTagId)) {
        ret = Camera::FindCameraMetadataItem(metadata, moduleTypeTagId, &item);
        if (ret == CAM_META_SUCCESS) {
            moduleType_ = item.data.ui32[0];
        }
    }

    MEDIA_INFO_LOG("camera position: %{public}d, camera type: %{public}d, camera connection type: %{public}d, "
                   "Mirror Supported: %{public}d, camera foldScreen type: %{public}d, camera orientation: %{public}d, "
                   "moduleType: %{public}u", cameraPosition_, cameraType_, connectionType_, isMirrorSupported_,
                   foldScreenType_, cameraOrientation_, moduleType_);
}

std::string CameraDevice::GetID()
{
    return cameraID_;
}

std::shared_ptr<Camera::CameraMetadata> CameraDevice::GetMetadata()
{
    std::lock_guard<std::mutex> lock(cachedMetadataMutex_);
    return cachedMetadata_;
}

void CameraDevice::ResetMetadata()
{
    std::lock_guard<std::mutex> lock(cachedMetadataMutex_);
    cachedMetadata_ = MetadataCommonUtils::CopyMetadata(baseAbility_);
}

const std::shared_ptr<OHOS::Camera::CameraMetadata> CameraDevice::GetCameraAbility()
{
    return baseAbility_;
}

CameraPosition CameraDevice::GetPosition()
{
    if (cameraPosition_ == CAMERA_POSITION_FRONT && foldScreenType_ == CAMERA_FOLDSCREEN_INNER) {
        cameraPosition_ = CAMERA_POSITION_FOLD_INNER;
    }
    return cameraPosition_;
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

bool CameraDevice::IsMirrorSupported()
{
    return isMirrorSupported_;
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

    if (!zoomRatioRange_.empty()) {
        return zoomRatioRange_;
    }

    int ret;
    uint32_t zoomRangeCount = 2;
    camera_metadata_item_t item;

    ret = Camera::FindCameraMetadataItem(baseAbility_->get(), OHOS_ABILITY_ZOOM_RATIO_RANGE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("Failed to get zoom ratio range with return code %{public}d", ret);
        return {};
    }
    if (item.count != zoomRangeCount) {
        MEDIA_ERR_LOG("Invalid zoom ratio range count: %{public}d", item.count);
        return {};
    }
    range = {item.data.f[minIndex], item.data.f[maxIndex]};

    if (range[minIndex] > range[maxIndex]) {
        MEDIA_ERR_LOG("Invalid zoom range. min: %{public}f, max: %{public}f", range[minIndex], range[maxIndex]);
        return {};
    }
    MEDIA_DEBUG_LOG("Zoom range min: %{public}f, max: %{public}f", range[minIndex], range[maxIndex]);

    zoomRatioRange_ = range;
    return zoomRatioRange_;
}

std::vector<float> CameraDevice::GetExposureBiasRange()
{
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    std::vector<int32_t> range;

    if (!exposureBiasRange_.empty()) {
        return exposureBiasRange_;
    }

    int ret;
    uint32_t biasRangeCount = 2;
    camera_metadata_item_t item;
    auto metadata = GetMetadata();
    ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AE_COMPENSATION_RANGE, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("Failed to get exposure compensation range with return code %{public}d", ret);
        return {};
    }
    if (item.count != biasRangeCount) {
        MEDIA_ERR_LOG("Invalid exposure compensation range count: %{public}d", item.count);
        return {};
    }

    range = { item.data.i32[minIndex], item.data.i32[maxIndex] };
    if (range[minIndex] > range[maxIndex]) {
        MEDIA_ERR_LOG(
            "Invalid exposure compensation range. min: %{public}d, max: %{public}d", range[minIndex], range[maxIndex]);
        return {};
    }
    MEDIA_DEBUG_LOG("Exposure hdi compensation min: %{public}d, max: %{public}d", range[minIndex], range[maxIndex]);
    exposureBiasRange_ = { range[minIndex], range[maxIndex] };
    return exposureBiasRange_;
}
} // namespace CameraStandard
} // namespace OHOS
