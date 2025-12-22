/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_METADATA_H
#define OHOS_CAMERA_METADATA_H

#include <cstdint>
#include "camera_metadata_operator.h"
#include "metadata_utils.h"

namespace OHOS {
namespace CameraStandard {
template<typename T>
bool AddOrUpdateMetadata(common_metadata_header_t* src, uint32_t tag, const T* data, uint32_t dataCount)
{
    if (src == nullptr) {
        return false;
    }
    uint32_t index = 0;
    int ret = OHOS::Camera::CameraMetadata::FindCameraMetadataItemIndex(src, tag, &index, false);
    if (ret == CAM_META_SUCCESS) {
        ret = OHOS::Camera::CameraMetadata::UpdateCameraMetadataItemByIndex(src, index, data, dataCount, nullptr);
    } else if (ret == CAM_META_ITEM_NOT_FOUND) {
        ret = OHOS::Camera::CameraMetadata::AddCameraMetadataItem(src, tag, data, dataCount);
    }
    return ret == CAM_META_SUCCESS;
}

template<typename T>
bool AddOrUpdateMetadata(
    std::shared_ptr<OHOS::Camera::CameraMetadata>& metadata, uint32_t tag, const T* data, uint32_t dataCount)
{
    common_metadata_header_t* src = metadata->get();
    if (src == nullptr) {
        return false;
    }

    uint32_t index = 0;
    int ret = OHOS::Camera::CameraMetadata::FindCameraMetadataItemIndex(src, tag, &index);
    if (ret == CAM_META_SUCCESS) {
        ret = OHOS::Camera::CameraMetadata::UpdateCameraMetadataItemByIndex(src, index, data, dataCount, nullptr);
    } else if (ret == CAM_META_ITEM_NOT_FOUND) {
        // addEntry can resize if need
        return metadata->addEntry(tag, data, dataCount);
    }
    return ret == CAM_META_SUCCESS;
}

std::shared_ptr<OHOS::Camera::CameraMetadata> CopyMetadata(
    const std::shared_ptr<OHOS::Camera::CameraMetadata> srcMetadata);

std::shared_ptr<camera_metadata_item_t> GetMetadataItem(const common_metadata_header_t* src, uint32_t tag);

} // namespace CameraStandard
} // namespace OHOS
#endif