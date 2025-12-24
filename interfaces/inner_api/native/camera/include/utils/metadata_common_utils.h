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

#include <cstdint>
#include "camera_metadata_operator.h"
#include "camera_output_capability.h"
#include "camera_stream_info_parse.h"
#include "output/metadata_output.h"
#include "metadata_utils.h"
#include "camera_metadata.h"

namespace OHOS {
namespace CameraStandard {
enum RectBoxType {
    RECT_CAMERA = 0,
    RECT_MECH
};
class MetadataCommonUtils {
private:
    explicit MetadataCommonUtils() = default;

    static void GetMetadataResults(const common_metadata_header_t *metadata,
        std::vector<camera_metadata_item_t>& metadataResults, std::vector<uint32_t>& metadataTypes);

    static int32_t ProcessMetaObjects(const int32_t streamId, std::vector<sptr<MetadataObject>>& metaObjects,
                                            const std::vector<camera_metadata_item_t>& metadataItem,
                                            const std::vector<uint32_t>& metadataTypes,
                                            bool isNeedMirror, bool isNeedFlip, RectBoxType type);

    static void GenerateObjects(const camera_metadata_item_t &metadataItem, MetadataObjectType metadataType,
                                        std::vector<sptr<MetadataObject>> &metaObjects,
                                        bool isNeedMirror, bool isNeedFlip, RectBoxType rectBoxType);

    static void ProcessBaseInfo(sptr<MetadataObjectFactory> factoryPtr, const camera_metadata_item_t &metadataItem,
                                        int32_t &index, MetadataObjectType typeFromHal, bool isNeedMirror,
                                        bool isNeedFlip, RectBoxType type);

    static void ProcessExternInfo(sptr<MetadataObjectFactory> factoryPtr,
                                        const camera_metadata_item_t &metadataItem, int32_t &index,
                                        MetadataObjectType typeFromHal, bool isNeedMirror, bool isNeedFlip,
                                        RectBoxType type);

    static void ProcessFaceDetectInfo(sptr<MetadataObjectFactory> factoryPtr,
                                                    const camera_metadata_item_t &metadataItem, int32_t &index,
                                                    bool isNeedMirror, bool isNeedFlip, RectBoxType type,
                                                    MetadataObjectType typeFromHal);

    static void ProcessCatFaceDetectInfo(sptr<MetadataObjectFactory> factoryPtr,
                                                const camera_metadata_item_t &metadataItem, int32_t &index,
                                                bool isNeedMirror, bool isNeedFlip, RectBoxType type);

    static void ProcessDogFaceDetectInfo(sptr<MetadataObjectFactory> factoryPtr,
                                                const camera_metadata_item_t &metadataItem, int32_t &index,
                                                bool isNeedMirror, bool isNeedFlip, RectBoxType type);

    static Rect ProcessCameraRectBox(int32_t offsetTopLeftX, int32_t offsetTopLeftY,
        int32_t offsetBottomRightX, int32_t offsetBottomRightY, bool isNeedMirror, bool isNeedFlip);

    static Rect ProcessMechRectBox(int32_t offsetTopLeftX, int32_t offsetTopLeftY,
        int32_t offsetBottomRightX, int32_t offsetBottomRightY);
public:
    static std::shared_ptr<camera_metadata_item_t> GetCapabilityEntry(
        const std::shared_ptr<OHOS::Camera::CameraMetadata> metadata, uint32_t metadataTag);

    static std::shared_ptr<vector<Size>> GetSupportedPreviewSizeRange(const int32_t modeName,
        camera_format_t targetFormat, const std::shared_ptr<OHOS::Camera::CameraMetadata> metadata);

    static std::shared_ptr<OHOS::Camera::CameraMetadata> CopyMetadata(
        const std::shared_ptr<OHOS::Camera::CameraMetadata> srcMetadata);

    static bool ProcessFocusTrackingModeInfo(const std::shared_ptr<OHOS::Camera::CameraMetadata>& metadata,
        FocusTrackingMode& mode);

    static bool ProcessMetaObjects(const int32_t streamId, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result,
        std::vector<sptr<MetadataObject>> &metaObjects, bool isNeedMirror, bool isNeedFlip, RectBoxType type);

    static Rect ProcessRectBox(int32_t offsetTopLeftX, int32_t offsetTopLeftY,
        int32_t offsetBottomRightX, int32_t offsetBottomRightY, bool isNeedMirror, bool isNeedFlip,
        RectBoxType type);
};

std::vector<float> ParsePhysicalApertureRangeByMode(const camera_metadata_item_t &item, const int32_t modeName);

} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_METADATA_COMMON_UTILS_H