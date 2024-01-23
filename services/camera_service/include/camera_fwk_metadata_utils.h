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

#ifndef OHOS_CAMERA_FWK_METADATA_UTILS_H
#define OHOS_CAMERA_FWK_METADATA_UTILS_H

#include <memory>

#include "camera_metadata_info.h"
#include "metadata_utils.h"

namespace OHOS {
namespace CameraStandard {
namespace CameraFwkMetadataUtils {

bool MergeMetadata(const std::shared_ptr<OHOS::Camera::CameraMetadata> srcMetadata,
    std::shared_ptr<OHOS::Camera::CameraMetadata> dstMetadata);

std::shared_ptr<OHOS::Camera::CameraMetadata> CopyMetadata(
    const std::shared_ptr<OHOS::Camera::CameraMetadata> srcMetadata);

bool UpdateMetadataTag(
    const camera_metadata_item_t& srcItem, std::shared_ptr<OHOS::Camera::CameraMetadata> dstMetadata);

void DumpMetadataInfo(const std::shared_ptr<OHOS::Camera::CameraMetadata> srcMetadata);

void DumpMetadataItemInfo(const camera_metadata_item_t& item);

std::shared_ptr<OHOS::Camera::CameraMetadata> RecreateMetadata(
    const std::shared_ptr<OHOS::Camera::CameraMetadata> metadata);

void LogFormatCameraMetadata(const std::shared_ptr<OHOS::Camera::CameraMetadata> metadata);
} // namespace CameraFwkMetadataUtils
} // namespace CameraStandard
} // namespace OHOS

#endif // OHOS_CAMERA_METADATA_UTILS_H