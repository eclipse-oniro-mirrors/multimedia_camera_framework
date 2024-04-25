/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_METADATA_COMMON_UTILS_H
#define OHOS_CAMERA_METADATA_COMMON_UTILS_H

#include "camera_output_capability.h"
#include "camera_stream_info_parse.h"
#include "metadata_utils.h"

namespace OHOS {
namespace CameraStandard {
class MetadataCommonUtils {
private:
    explicit MetadataCommonUtils() = default;

public:
    static std::shared_ptr<camera_metadata_item_t> GetCapabilityEntry(
        const std::shared_ptr<OHOS::Camera::CameraMetadata> metadata, uint32_t metadataTag);

    static std::shared_ptr<vector<Size>> GetSupportedPreviewSizeRange(const int32_t modeName,
        camera_format_t targetFormat, const std::shared_ptr<OHOS::Camera::CameraMetadata> metadata);

    static std::shared_ptr<OHOS::Camera::CameraMetadata> CopyMetadata(
        const std::shared_ptr<OHOS::Camera::CameraMetadata> srcMetadata);
};

template<typename T>
bool AddOrUpdateMetadata(std::shared_ptr<OHOS::Camera::CameraMetadata> metadata, uint32_t tag, T value)
{
    uint32_t count = 1;
    bool status = false;
    camera_metadata_item_t item;
    int32_t ret = OHOS::Camera::FindCameraMetadataItem(metadata->get(), tag, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = metadata->addEntry(tag, &value, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = metadata->updateEntry(tag, &value, count);
    }
    return status;
}

std::vector<float> ParsePhysicalApertureRangeByMode(const camera_metadata_item_t &item, const int32_t modeName);
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_METADATA_COMMON_UTILS_H