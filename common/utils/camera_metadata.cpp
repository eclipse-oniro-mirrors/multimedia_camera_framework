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

#include <cstdint>
#include "camera_log.h"
#include "camera_metadata.h"

namespace OHOS {
namespace CameraStandard {

std::shared_ptr<OHOS::Camera::CameraMetadata> CopyMetadata(
    const std::shared_ptr<OHOS::Camera::CameraMetadata> srcMetadata)
{
    CHECK_ERROR_RETURN_RET_LOG(srcMetadata == nullptr, nullptr, "CopyMetadata fail,src is null");
    auto oldMetadata = srcMetadata->get();
    CHECK_ERROR_RETURN_RET(oldMetadata == nullptr, nullptr);
    std::shared_ptr<OHOS::Camera::CameraMetadata> result =
        std::make_shared<OHOS::Camera::CameraMetadata>(oldMetadata->item_capacity, oldMetadata->data_capacity);
    auto newMetadata = result->get();
    int32_t ret = OHOS::Camera::CopyCameraMetadataItems(newMetadata, oldMetadata);
    CHECK_ERROR_PRINT_LOG(ret != CAM_META_SUCCESS, "CopyCameraMetadataItems failed ret:%{public}d", ret);
    return result;
}

std::shared_ptr<camera_metadata_item_t> GetMetadataItem(const common_metadata_header_t* src, uint32_t tag)
{
    CHECK_ERROR_RETURN_RET(src == nullptr, nullptr);
    auto item = std::make_shared<camera_metadata_item_t>();
    int32_t ret = OHOS::Camera::CameraMetadata::FindCameraMetadataItem(src, tag, item.get());
    CHECK_ERROR_RETURN_RET(ret != CAM_META_SUCCESS, nullptr);
    return item;
}

} // namespace CameraStandard
} // namespace OHOS
