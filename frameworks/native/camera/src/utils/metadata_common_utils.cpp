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

#include "metadata_common_utils.h"

#include <memory>

#include "camera_log.h"
#include "capture_session.h"

namespace OHOS {
namespace CameraStandard {
namespace {
void FillSizeListFromStreamInfo(
    vector<Size>& sizeList, const StreamRelatedInfo& streamInfo, const camera_format_t targetFormat)
{
    for (uint32_t detailIndex = 0; detailIndex < streamInfo.detailInfoCount; detailIndex++) {
        auto detailInfo = std::move(streamInfo.detailInfo[detailIndex]);
        camera_format_t hdi_format = static_cast<camera_format_t>(detailInfo.format);
        if (hdi_format != targetFormat) {
            continue;
        }
        Size size { .width = detailInfo.width, .height = detailInfo.height };
        sizeList.emplace_back(size);
    }
}
std::shared_ptr<vector<Size>> GetSupportedPreviewSizeRangeFromExtendConfig(
    const int32_t modeName, camera_format_t targetFormat, const std::shared_ptr<OHOS::Camera::CameraMetadata> metadata)
{
    auto item = MetadataCommonUtils::GetCapabilityEntry(metadata, OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS);
    if (item == nullptr) {
        return nullptr;
    }
    std::shared_ptr<vector<Size>> sizeList = std::make_shared<vector<Size>>();

    ExtendInfo extendInfo = {};
    std::shared_ptr<CameraStreamInfoParse> modeStreamParse = std::make_shared<CameraStreamInfoParse>();
    modeStreamParse->getModeInfo(item->data.i32, item->count, extendInfo); // 解析tag中带的数据信息意义
    for (uint32_t modeIndex = 0; modeIndex < extendInfo.modeCount; modeIndex++) {
        auto modeInfo = std::move(extendInfo.modeInfo[modeIndex]);
        MEDIA_DEBUG_LOG("MetadataCommonUtils::GetSupportedPreviewSizeRangeFromExtendConfig check modeName: %{public}d",
            modeInfo.modeName);
        if (modeName != modeInfo.modeName) {
            continue;
        }
        for (uint32_t streamIndex = 0; streamIndex < modeInfo.streamTypeCount; streamIndex++) {
            auto streamInfo = std::move(modeInfo.streamInfo[streamIndex]);
            int32_t streamType = streamInfo.streamType;
            MEDIA_DEBUG_LOG(
                "MetadataCommonUtils::GetSupportedPreviewSizeRangeFromExtendConfig check streamType: %{public}d",
                streamType);
            if (streamType != 0) { // Stremp type 0 is preview type.
                continue;
            }
            FillSizeListFromStreamInfo(*sizeList.get(), streamInfo, targetFormat);
        }
    }
    MEDIA_INFO_LOG("MetadataCommonUtils::GetSupportedPreviewSizeRangeFromExtendConfig listSize: %{public}d",
        static_cast<int>(sizeList->size()));
    return sizeList;
}

std::shared_ptr<vector<Size>> GetSupportedPreviewSizeRangeFromBasicConfig(
    camera_format_t targetFormat, const std::shared_ptr<OHOS::Camera::CameraMetadata> metadata)
{
    auto item = MetadataCommonUtils::GetCapabilityEntry(metadata, OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS);
    if (item == nullptr) {
        return nullptr;
    }
    std::shared_ptr<vector<Size>> sizeList = std::make_shared<vector<Size>>();

    const uint32_t widthOffset = 1;
    const uint32_t heightOffset = 2;
    const uint32_t unitStep = 3;

    for (uint32_t i = 0; i < item->count; i += unitStep) {
        camera_format_t hdi_format = static_cast<camera_format_t>(item->data.i32[i]);
        if (hdi_format != targetFormat) {
            continue;
        }
        Size size;
        size.width = item->data.i32[i + widthOffset];
        size.height = item->data.i32[i + heightOffset];
        sizeList->emplace_back(size);
    }
    MEDIA_INFO_LOG("MetadataCommonUtils::GetSupportedPreviewSizeRangeFromBasicConfig listSize: %{public}d",
        static_cast<int>(sizeList->size()));
    return sizeList;
}
} // namespace

std::shared_ptr<camera_metadata_item_t> MetadataCommonUtils::GetCapabilityEntry(
    const std::shared_ptr<Camera::CameraMetadata> metadata, uint32_t metadataTag)
{
    if (metadata == nullptr) {
        return nullptr;
    }
    std::shared_ptr<camera_metadata_item_t> item = std::make_shared<camera_metadata_item_t>();
    int32_t retCode = Camera::FindCameraMetadataItem(metadata->get(), metadataTag, item.get());
    if (retCode != CAM_META_SUCCESS || item->count == 0) {
        return nullptr;
    }
    return item;
}

std::shared_ptr<vector<Size>> MetadataCommonUtils::GetSupportedPreviewSizeRange(
    const int32_t modeName, camera_format_t targetFormat, const std::shared_ptr<OHOS::Camera::CameraMetadata> metadata)
{
    MEDIA_DEBUG_LOG("MetadataCommonUtils::GetSupportedPreviewSizeRange modeName: %{public}d, targetFormat:%{public}d",
        modeName, targetFormat);
    std::shared_ptr<vector<Size>> sizeList = std::make_shared<vector<Size>>();
    auto extendList = GetSupportedPreviewSizeRangeFromExtendConfig(modeName, targetFormat, metadata);
    if (modeName == SceneMode::CAPTURE && extendList != nullptr && extendList->empty()) {
        extendList = GetSupportedPreviewSizeRangeFromExtendConfig(SceneMode::NORMAL, targetFormat, metadata);
    }
    if (extendList != nullptr && !extendList->empty()) {
        for (auto& size : *extendList) {
            MEDIA_DEBUG_LOG("MetadataCommonUtils::GetSupportedPreviewSizeRange extend info:%{public}dx%{public}d",
                size.width, size.height);
        }
        sizeList->insert(sizeList->end(), extendList->begin(), extendList->end());
        return sizeList;
    }
    auto basicList = GetSupportedPreviewSizeRangeFromBasicConfig(targetFormat, metadata);
    if (basicList != nullptr && !basicList->empty()) {
        for (auto& size : *basicList) {
            MEDIA_DEBUG_LOG("MetadataCommonUtils::GetSupportedPreviewSizeRange basic info:%{public}dx%{public}d",
                size.width, size.height);
        }
        sizeList->insert(sizeList->end(), basicList->begin(), basicList->end());
    }
    return sizeList;
}

std::shared_ptr<OHOS::Camera::CameraMetadata> MetadataCommonUtils::CopyMetadata(
    const std::shared_ptr<OHOS::Camera::CameraMetadata> srcMetadata)
{
    if (srcMetadata == nullptr) {
        MEDIA_ERR_LOG("CopyMetadata fail,src is null");
        return nullptr;
    }
    auto metadataHeader = srcMetadata->get();
    auto newMetadata =
        std::make_shared<OHOS::Camera::CameraMetadata>(metadataHeader->item_capacity, metadataHeader->data_capacity);
    MergeMetadata(srcMetadata, newMetadata);
    return newMetadata;
}

bool MetadataCommonUtils::MergeMetadata(const std::shared_ptr<OHOS::Camera::CameraMetadata> srcMetadata,
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
} // namespace CameraStandard
} // namespace OHOS
