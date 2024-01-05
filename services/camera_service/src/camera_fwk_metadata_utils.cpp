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
namespace {

constexpr uint32_t ITEM_CAPACITY = 20;
constexpr uint32_t DATA_CAPACITY = 200;

std::vector<uint32_t> reportMetadataTag {
    OHOS_CONTROL_FLASH_MODE,
    OHOS_CONTROL_FLASH_STATE,
    OHOS_CONTROL_FOCUS_MODE,
    OHOS_CONTROL_FOCUS_STATE,
    OHOS_STATISTICS_FACE_RECTANGLES,
    OHOS_CAMERA_MACRO_STATUS
};

void ForEach(uint32_t iteratorCount, std::function<void(uint32_t)> fun)
{
    for (uint32_t index = 0; index < iteratorCount; index++) {
        fun(index);
    }
}
} // namespace
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

void DumpMetadataInfo(const std::shared_ptr<OHOS::Camera::CameraMetadata> srcMetadata)
{
    if (srcMetadata == nullptr) {
        MEDIA_ERR_LOG("DumpMetadataInfo srcMetadata is null");
        return;
    }
    auto metadataHeader = srcMetadata->get();
    uint32_t version = metadataHeader->version;
    uint32_t itemCount = metadataHeader->item_count;
    uint32_t dataCount = metadataHeader->data_count;
    uint32_t size = metadataHeader->size;
    MEDIA_DEBUG_LOG("DumpMetadataInfo srcMetadata \
    version:%{public}d, itemCount:%{public}d, dataCount:%{public}d, size:%{public}d",
        version, itemCount, dataCount, size);

    for (uint32_t i = 0; i < itemCount; i++) {
        camera_metadata_item_t item;
        Camera::GetCameraMetadataItem(metadataHeader, i, &item);
        DumpMetadataItemInfo(item);
    }
}

void DumpMetadataItemInfo(const camera_metadata_item_t& metadataItem)
{
    uint32_t dataType = metadataItem.data_type;
    uint32_t dataCount = metadataItem.count;
    const char* tagName = Camera::GetCameraMetadataItemName(metadataItem.item);
    MEDIA_DEBUG_LOG("DumpMetadataItemInfo \
    tag:%{public}d->%{public}s, dataType:%{public}d, dataCount:%{public}d",
        metadataItem.item, tagName, dataType, dataCount);
    if (dataType == META_TYPE_BYTE) {
        ForEach(dataCount, [&metadataItem, &tagName](uint32_t index) {
            MEDIA_DEBUG_LOG("DumpMetadataItemInfo:%{public}d->%{public}s, dataIndex:%{public}d, value:%{public}d",
                metadataItem.item, tagName, index, metadataItem.data.u8[index]);
        });
    } else if (dataType == META_TYPE_INT32) {
        ForEach(dataCount, [&metadataItem, &tagName](uint32_t index) {
            MEDIA_DEBUG_LOG("DumpMetadataItemInfo:%{public}d->%{public}s, dataIndex:%{public}d, value:%{public}d",
                metadataItem.item, tagName, index, metadataItem.data.i32[index]);
        });
    } else if (dataType == META_TYPE_UINT32) {
        ForEach(dataCount, [&metadataItem, &tagName](uint32_t index) {
            MEDIA_DEBUG_LOG("DumpMetadataItemInfo:%{public}d->%{public}s, dataIndex:%{public}d, value:%{public}d",
                metadataItem.item, tagName, index, metadataItem.data.ui32[index]);
        });
    } else if (dataType == META_TYPE_FLOAT) {
        ForEach(dataCount, [&metadataItem, &tagName](uint32_t index) {
            MEDIA_DEBUG_LOG("DumpMetadataItemInfo:%{public}d->%{public}s, dataIndex:%{public}d, value:%{public}f",
                metadataItem.item, tagName, index, metadataItem.data.f[index]);
        });
    } else if (dataType == META_TYPE_INT64) {
        ForEach(dataCount, [&metadataItem, &tagName](uint32_t index) {
            MEDIA_DEBUG_LOG("DumpMetadataItemInfo:%{public}d->%{public}s, dataIndex:%{public}d, value:%{public}lld",
                metadataItem.item, tagName, index, static_cast<long long>(metadataItem.data.i64[index]));
        });
    } else if (dataType == META_TYPE_DOUBLE) {
        ForEach(dataCount, [&metadataItem, &tagName](uint32_t index) {
            MEDIA_DEBUG_LOG("DumpMetadataItemInfo:%{public}d->%{public}s, dataIndex:%{public}d, value:%{public}lf",
                metadataItem.item, tagName, index, metadataItem.data.d[index]);
        });
    } else if (dataType == META_TYPE_RATIONAL) {
        ForEach(dataCount, [&metadataItem, &tagName](uint32_t index) {
            MEDIA_DEBUG_LOG("DumpMetadataItemInfo:%{public}d->%{public}s, dataIndex:%{public}d, numerator:%{public}d, "
                            "denominator:%{public}d",
                metadataItem.item, tagName, index, metadataItem.data.r[index].numerator,
                metadataItem.data.r[index].denominator);
        });
    } else {
        MEDIA_WARNING_LOG("DumpMetadataItemInfo get unknown dataType:%{public}d", dataType);
    }
}

std::shared_ptr<OHOS::Camera::CameraMetadata> RecreateMetadata(
    const std::shared_ptr<OHOS::Camera::CameraMetadata> metadata)
{
    common_metadata_header_t* header = metadata->get();
    std::shared_ptr<OHOS::Camera::CameraMetadata> newMetadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(ITEM_CAPACITY, DATA_CAPACITY);

    for (uint32_t metadataTag : reportMetadataTag) {
        camera_metadata_item_t item;
        int ret = Camera::FindCameraMetadataItem(header, metadataTag, &item);
        if (ret == 0 && item.count != 0) {
            newMetadata->addEntry(item.item, item.data.u8, item.count);
        }
    }
    return newMetadata;
}

void LogFormatCameraMetadata(const std::shared_ptr<OHOS::Camera::CameraMetadata> metadata)
{
    if (metadata == nullptr) {
        MEDIA_DEBUG_LOG("LogFormatCameraMetadata: Metadata pointer is null");
        return;
    }

    auto header = metadata->get();
    if (header == nullptr) {
        MEDIA_DEBUG_LOG("LogFormatCameraMetadata: Metadata header is null");
        return;
    }

    std::string metaStr = OHOS::Camera::FormatCameraMetadataToString(header);
    MEDIA_DEBUG_LOG("LogFormatCameraMetadata: metaStr %{public}s", metaStr.c_str());
}
} // namespace CameraFwkMetadataUtils
} // namespace CameraStandard
} // namespace OHOS