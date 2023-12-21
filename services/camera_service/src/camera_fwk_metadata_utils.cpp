/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "camera_fwk_metadata_utils.h"
#include <cstdint>

#include "camera_log.h"
#include "camera_metadata_operator.h"

namespace OHOS {
namespace CameraStandard {
namespace CameraFwkMetadataUtils {
bool MergeMetadata(const std::shared_ptr<OHOS::Camera::CameraMetadata> srcMetadata,
    std::shared_ptr<OHOS::Camera::CameraMetadata> dstMetadata)
{
    if (srcMetadata == nullptr || dstMetadata == nullptr) {
        return false;
    }
    auto srcHeader = srcMetadata->get();
    if (srcHeader == nullptr) {
        return false;
    }
    auto dstHeader = dstMetadata->get();
    if (dstHeader == nullptr) {
        return false;
    }
    auto srcItemCount = srcHeader->item_count;
    camera_metadata_item_t srcItem;
    for (uint32_t index = 0; index < srcItemCount; index++) {
        int ret = OHOS::Camera::GetCameraMetadataItem(srcHeader, index, &srcItem);
        if (ret != CAM_META_SUCCESS) {
            MEDIA_ERR_LOG("Failed to get metadata item at index: %{public}d", index);
            return false;
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
            return false;
        }
    }
    return true;
}

std::shared_ptr<OHOS::Camera::CameraMetadata> CopyMetadata(
    const std::shared_ptr<OHOS::Camera::CameraMetadata> srcMetadata)
{
    if (srcMetadata == nullptr) {
        MEDIA_ERR_LOG("CopyMetadata fail, src is null");
        return nullptr;
    }
    auto metadataHeader = srcMetadata->get();
    auto newMetadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(metadataHeader->item_capacity, metadataHeader->data_capacity);
    MergeMetadata(srcMetadata, newMetadata);
    return newMetadata;
}

bool UpdateMetadataTag(const camera_metadata_item_t& srcItem, std::shared_ptr<OHOS::Camera::CameraMetadata> dstMetadata)
{
    if (dstMetadata == nullptr) {
        MEDIA_ERR_LOG("UpdateMetadataTag fail, dstMetadata is null");
        return false;
    }
    uint32_t itemIndex;
    int32_t result = OHOS::Camera::FindCameraMetadataItemIndex(dstMetadata->get(), srcItem.item, &itemIndex);
    bool status = false;
    if (result == CAM_META_ITEM_NOT_FOUND) {
        status = dstMetadata->addEntry(srcItem.item, srcItem.data.u8, srcItem.count);
    } else if (result == CAM_META_SUCCESS) {
        status = dstMetadata->updateEntry(srcItem.item, srcItem.data.u8, srcItem.count);
    }
    if (!status) {
        MEDIA_ERR_LOG("UpdateMetadataTag fail, err is %{public}d", result);
        return false;
    }
    return true;
}
} // namespace CameraFwkMetadataUtils
} // namespace CameraStandard
} // namespace OHOS