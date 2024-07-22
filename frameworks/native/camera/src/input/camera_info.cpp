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
#include "input/camera_info.h"
#include <securec.h>
#include "camera_metadata_info.h"
#include "camera_log.h"

using namespace std;

namespace OHOS {
namespace CameraStandard {
const std::unordered_map<camera_type_enum_t, CameraType> CameraInfo::metaToFwCameraType_ = {
    {OHOS_CAMERA_TYPE_WIDE_ANGLE, CAMERA_TYPE_WIDE_ANGLE},
    {OHOS_CAMERA_TYPE_ULTRA_WIDE, CAMERA_TYPE_ULTRA_WIDE},
    {OHOS_CAMERA_TYPE_TELTPHOTO, CAMERA_TYPE_TELEPHOTO},
    {OHOS_CAMERA_TYPE_TRUE_DEAPTH, CAMERA_TYPE_TRUE_DEPTH},
    {OHOS_CAMERA_TYPE_LOGICAL, CAMERA_TYPE_UNSUPPORTED},
    {OHOS_CAMERA_TYPE_UNSPECIFIED, CAMERA_TYPE_DEFAULT}
};

const std::unordered_map<camera_position_enum_t, CameraPosition> CameraInfo::metaToFwCameraPosition_ = {
    {OHOS_CAMERA_POSITION_FRONT, CAMERA_POSITION_FRONT},
    {OHOS_CAMERA_POSITION_BACK, CAMERA_POSITION_BACK},
    {OHOS_CAMERA_POSITION_OTHER, CAMERA_POSITION_UNSPECIFIED}
};

const std::unordered_map<camera_connection_type_t, ConnectionType> CameraInfo::metaToFwConnectionType_ = {
    {OHOS_CAMERA_CONNECTION_TYPE_REMOTE, CAMERA_CONNECTION_REMOTE},
    {OHOS_CAMERA_CONNECTION_TYPE_USB_PLUGIN, CAMERA_CONNECTION_USB_PLUGIN},
    {OHOS_CAMERA_CONNECTION_TYPE_BUILTIN, CAMERA_CONNECTION_BUILT_IN}
};

CameraInfo::CameraInfo(std::string cameraID, std::shared_ptr<Camera::CameraMetadata> metadata)
{
    cameraID_ = cameraID;
    metadata_ = metadata;
    init(metadata->get());
}

CameraInfo::~CameraInfo()
{
    metadata_.reset();
    metadata_ = nullptr;
}

void CameraInfo::init(common_metadata_header_t* metadata)
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

    MEDIA_INFO_LOG("camera position: %{public}d, camera type: %{public}d, camera connection type: %{public}d",
                   cameraPosition_, cameraType_, connectionType_);
}

std::string CameraInfo::GetID()
{
    return cameraID_;
}

std::shared_ptr<Camera::CameraMetadata> CameraInfo::GetMetadata()
{
    return metadata_;
}

void CameraInfo::SetMetadata(std::shared_ptr<Camera::CameraMetadata> metadata)
{
    metadata_ = metadata;
}

CameraPosition CameraInfo::GetPosition()
{
    return cameraPosition_;
}

CameraType CameraInfo::GetCameraType()
{
    return cameraType_;
}

ConnectionType CameraInfo::GetConnectionType()
{
    return connectionType_;
}

std::vector<float> CameraInfo::CalculateZoomRange()
{
    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata_->get(), OHOS_ABILITY_ZOOM_CAP, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, {},
        "Failed to get zoom cap with return code %{public}d", ret);
    uint32_t zoomRangeCount = 2;
    CHECK_ERROR_RETURN_RET_LOG(item.count != zoomRangeCount, {}, "Invalid zoom cap count: %{public}d", item.count);
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    constexpr float factor = 100.0;
    MEDIA_DEBUG_LOG("Zoom cap min: %{public}d, max: %{public}d",
                    item.data.i32[minIndex], item.data.i32[maxIndex]);
    float minZoom = item.data.i32[minIndex] / factor;
    float maxZoom = item.data.i32[maxIndex] / factor;

    ret = Camera::FindCameraMetadataItem(metadata_->get(), OHOS_ABILITY_SCENE_ZOOM_CAP, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, {},
        "Failed to get scene zoom cap with return code %{public}d", ret);
    CHECK_ERROR_RETURN_RET_LOG(item.count != zoomRangeCount, {}, "Invalid zoom cap count: %{public}d", item.count);
    MEDIA_DEBUG_LOG("Scene zoom cap min: %{public}d, max: %{public}d",
                    item.data.i32[minIndex], item.data.i32[maxIndex]);
    float tempZoom = item.data.i32[minIndex] / factor;
    if (minZoom < tempZoom) {
        minZoom = tempZoom;
    }
    tempZoom = item.data.i32[maxIndex] / factor;
    if (maxZoom > tempZoom) {
        maxZoom = tempZoom;
    }
    return {minZoom, maxZoom};
}

std::vector<float> CameraInfo::GetZoomRatioRange()
{
    if (!zoomRatioRange_.empty()) {
        return zoomRatioRange_;
    }

    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata_->get(), OHOS_ABILITY_ZOOM_RATIO_RANGE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, {},
        "Failed to get zoom ratio range with return code %{public}d", ret);
    uint32_t zoomRangeCount = 2;
    CHECK_ERROR_RETURN_RET_LOG(item.count != zoomRangeCount, {},
        "Invalid zoom ratio range count: %{public}d", item.count);
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    std::vector<float> range = {item.data.f[minIndex], item.data.f[maxIndex]};
    CHECK_ERROR_RETURN_RET_LOG(range[minIndex] > range[maxIndex], {},
        "Invalid zoom range. min: %{public}f, max: %{public}f", range[minIndex], range[maxIndex]);

    MEDIA_DEBUG_LOG("Zoom range min: %{public}f, max: %{public}f", range[minIndex], range[maxIndex]);

    zoomRatioRange_ = range;
    return zoomRatioRange_;
}

std::vector<float> CameraInfo::GetExposureBiasRange()
{
    if (!exposureBiasRange_.empty()) {
        return exposureBiasRange_;
    }

    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata_->get(), OHOS_ABILITY_AE_COMPENSATION_RANGE, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, {},
        "Failed to get exposure compensation range with return code %{public}d", ret);
    uint32_t biasRangeCount = 2;
    CHECK_ERROR_RETURN_RET_LOG(item.count != biasRangeCount, {},
        "Invalid exposure compensation range count: %{public}d", item.count);
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    std::vector<int32_t> range = {item.data.i32[minIndex], item.data.i32[maxIndex]};
    CHECK_ERROR_RETURN_RET_LOG(range[minIndex] > range[maxIndex], {},
        "Invalid exposure compensation range. min: %{public}d, max: %{public}d", range[minIndex], range[maxIndex]);
    MEDIA_DEBUG_LOG("Exposure hdi compensation min: %{public}d, max: %{public}d", range[minIndex], range[maxIndex]);

    ret = Camera::FindCameraMetadataItem(metadata_->get(), OHOS_ABILITY_AE_COMPENSATION_STEP, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, {},
        "Failed to get exposure compensation step with return code %{public}d", ret);
    int32_t stepNumerator = item.data.r->numerator;
    int32_t stepDenominator = item.data.r->denominator;
    float step = static_cast<float>(stepNumerator) / static_cast<float>(stepDenominator);
    MEDIA_DEBUG_LOG("Exposure step numerator: %{public}d, denominatormax: %{public}d, step: %{public}f",
        stepNumerator, stepDenominator, step);

    exposureBiasRange_ = {step * range[minIndex], step * range[maxIndex]};

    MEDIA_DEBUG_LOG("Exposure compensation min: %{public}f, max: %{public}f",
        exposureBiasRange_[minIndex], exposureBiasRange_[maxIndex]);
    return exposureBiasRange_;
}
} // CameraStandard
} // OHOS
