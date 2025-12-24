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
#include "camera_metadata_operator.h"
#include "camera_util.h"
#include <cstdint>
#include <memory>

#include "camera_log.h"
#include "capture_session.h"

namespace OHOS {
namespace CameraStandard {
namespace {
const std::unordered_map<uint32_t, MetadataObjectType> g_HALResultToFwCameraMetaDetect = {
    {OHOS_STATISTICS_DETECT_HUMAN_FACE_INFOS, MetadataObjectType::FACE},
    {OHOS_STATISTICS_DETECT_HUMAN_BODY_INFOS, MetadataObjectType::HUMAN_BODY},
    {OHOS_STATISTICS_DETECT_CAT_FACE_INFOS, MetadataObjectType::CAT_FACE},
    {OHOS_STATISTICS_DETECT_CAT_BODY_INFOS, MetadataObjectType::CAT_BODY},
    {OHOS_STATISTICS_DETECT_DOG_FACE_INFOS, MetadataObjectType::DOG_FACE},
    {OHOS_STATISTICS_DETECT_DOG_BODY_INFOS, MetadataObjectType::DOG_BODY},
    {OHOS_STATISTICS_DETECT_SALIENT_INFOS, MetadataObjectType::SALIENT_DETECTION},
    {OHOS_STATISTICS_DETECT_BAR_CODE_INFOS, MetadataObjectType::BAR_CODE_DETECTION},
    {OHOS_STATISTICS_DETECT_BASE_FACE_INFO, MetadataObjectType::BASE_FACE_DETECTION},
    {OHOS_STATISTICS_DETECT_HUMAN_HEAD_INFOS, MetadataObjectType::HUMAN_HEAD},
};

std::vector<uint32_t> g_typesOfMetadata = {
    OHOS_STATISTICS_DETECT_HUMAN_FACE_INFOS,
    OHOS_STATISTICS_DETECT_HUMAN_BODY_INFOS,
    OHOS_STATISTICS_DETECT_CAT_FACE_INFOS,
    OHOS_STATISTICS_DETECT_CAT_BODY_INFOS,
    OHOS_STATISTICS_DETECT_DOG_FACE_INFOS,
    OHOS_STATISTICS_DETECT_DOG_BODY_INFOS,
    OHOS_STATISTICS_DETECT_SALIENT_INFOS,
    OHOS_STATISTICS_DETECT_BAR_CODE_INFOS,
    OHOS_STATISTICS_DETECT_BASE_FACE_INFO,
    OHOS_STATISTICS_DETECT_HUMAN_HEAD_INFOS};

void FillSizeListFromStreamInfo(
    vector<Size>& sizeList, const StreamInfo& streamInfo, const camera_format_t targetFormat)
{
    // LCOV_EXCL_START
    for (const auto& detail : streamInfo.detailInfos) {
        camera_format_t hdi_format = static_cast<camera_format_t>(detail.format);
        CHECK_CONTINUE(hdi_format != targetFormat);
        Size size { .width = detail.width, .height = detail.height };
        sizeList.emplace_back(size);
    }
    // LCOV_EXCL_STOP
}

void FillSizeListFromStreamInfo(
    vector<Size>& sizeList, const StreamRelatedInfo& streamInfo, const camera_format_t targetFormat)
{
    // LCOV_EXCL_START
    for (const auto &detail : streamInfo.detailInfo) {
        camera_format_t hdi_format = static_cast<camera_format_t>(detail.format);
        CHECK_CONTINUE(hdi_format != targetFormat);
        Size size{.width = detail.width, .height = detail.height};
        sizeList.emplace_back(size);
    }
    // LCOV_EXCL_STOP
}

std::shared_ptr<vector<Size>> GetSupportedPreviewSizeRangeFromProfileLevel(
    const int32_t modeName, camera_format_t targetFormat, const std::shared_ptr<OHOS::Camera::CameraMetadata> metadata)
{
    // LCOV_EXCL_START
    CHECK_RETURN_RET(metadata == nullptr, nullptr);
    camera_metadata_item_t item;
    int32_t retCode = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AVAILABLE_PROFILE_LEVEL, &item);
    bool isMetadataInvalid = retCode != CAM_META_SUCCESS || item.count == 0;
    CHECK_RETURN_RET(isMetadataInvalid, nullptr);
    std::shared_ptr<vector<Size>> sizeList = std::make_shared<vector<Size>>();
    std::vector<SpecInfo> specInfos;
    ProfileLevelInfo modeInfo = {};
    CameraAbilityParseUtil::GetModeInfo(modeName, item, modeInfo);
    specInfos.insert(specInfos.end(), modeInfo.specInfos.begin(), modeInfo.specInfos.end());
    for (SpecInfo& specInfo : specInfos) {
        for (StreamInfo& streamInfo : specInfo.streamInfos) {
            if (streamInfo.streamType == 0) {
                FillSizeListFromStreamInfo(*sizeList.get(), streamInfo, targetFormat);
            }
        }
    }
    MEDIA_INFO_LOG("MetadataCommonUtils::GetSupportedPreviewSizeRangeFromProfileLevel listSize: %{public}d",
        static_cast<int>(sizeList->size()));
    return sizeList;
    // LCOV_EXCL_STOP
}

std::shared_ptr<vector<Size>> GetSupportedPreviewSizeRangeFromExtendConfig(
    const int32_t modeName, camera_format_t targetFormat, const std::shared_ptr<OHOS::Camera::CameraMetadata> metadata)
{
    // LCOV_EXCL_START
    auto item = MetadataCommonUtils::GetCapabilityEntry(metadata, OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS);
    CHECK_RETURN_RET(item == nullptr, nullptr);
    std::shared_ptr<vector<Size>> sizeList = std::make_shared<vector<Size>>();

    ExtendInfo extendInfo = {};
    std::shared_ptr<CameraStreamInfoParse> modeStreamParse = std::make_shared<CameraStreamInfoParse>();
    modeStreamParse->getModeInfo(item->data.i32, item->count, extendInfo); // 解析tag中带的数据信息意义
    for (uint32_t modeIndex = 0; modeIndex < extendInfo.modeCount; modeIndex++) {
        auto modeInfo = std::move(extendInfo.modeInfo[modeIndex]);
        MEDIA_DEBUG_LOG("MetadataCommonUtils::GetSupportedPreviewSizeRangeFromExtendConfig check modeName: %{public}d",
            modeInfo.modeName);
        CHECK_CONTINUE(modeName != modeInfo.modeName);
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
    // LCOV_EXCL_STOP
}

std::shared_ptr<vector<Size>> GetSupportedPreviewSizeRangeFromBasicConfig(
    camera_format_t targetFormat, const std::shared_ptr<OHOS::Camera::CameraMetadata> metadata)
{
    // LCOV_EXCL_START
    auto item = MetadataCommonUtils::GetCapabilityEntry(metadata, OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS);
    CHECK_RETURN_RET(item == nullptr, nullptr);
    std::shared_ptr<vector<Size>> sizeList = std::make_shared<vector<Size>>();

    const uint32_t widthOffset = 1;
    const uint32_t heightOffset = 2;
    const uint32_t unitStep = 3;

    for (uint32_t i = 0; i < item->count; i += unitStep) {
        camera_format_t hdi_format = static_cast<camera_format_t>(item->data.i32[i]);
        CHECK_CONTINUE(hdi_format != targetFormat);
        Size size;
        size.width = static_cast<uint32_t>(item->data.i32[i + widthOffset]);
        size.height = static_cast<uint32_t>(item->data.i32[i + heightOffset]);
        sizeList->emplace_back(size);
    }
    MEDIA_INFO_LOG("MetadataCommonUtils::GetSupportedPreviewSizeRangeFromBasicConfig listSize: %{public}d",
        static_cast<int>(sizeList->size()));
    return sizeList;
    // LCOV_EXCL_STOP
}
} // namespace

std::shared_ptr<camera_metadata_item_t> MetadataCommonUtils::GetCapabilityEntry(
    const std::shared_ptr<Camera::CameraMetadata> metadata, uint32_t metadataTag)
{
    CHECK_RETURN_RET(metadata == nullptr, nullptr);
    std::shared_ptr<camera_metadata_item_t> item = std::make_shared<camera_metadata_item_t>();
    int32_t retCode = Camera::FindCameraMetadataItem(metadata->get(), metadataTag, item.get());
    bool isMetadataInvalid = retCode != CAM_META_SUCCESS || item->count == 0;
    return isMetadataInvalid ? nullptr : item;
}

std::shared_ptr<vector<Size>> MetadataCommonUtils::GetSupportedPreviewSizeRange(
    const int32_t modeName, camera_format_t targetFormat, const std::shared_ptr<OHOS::Camera::CameraMetadata> metadata)
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("MetadataCommonUtils::GetSupportedPreviewSizeRange modeName: %{public}d, targetFormat:%{public}d",
        modeName, targetFormat);
    std::shared_ptr<vector<Size>> sizeList = std::make_shared<vector<Size>>();
    auto levelList = GetSupportedPreviewSizeRangeFromProfileLevel(modeName, targetFormat, metadata);
    if (levelList && levelList->empty() && (modeName == SceneMode::CAPTURE || modeName == SceneMode::VIDEO)) {
        levelList = GetSupportedPreviewSizeRangeFromProfileLevel(SceneMode::NORMAL, targetFormat, metadata);
    }
    if (levelList && !levelList->empty()) {
        for (auto& size : *levelList) {
            MEDIA_DEBUG_LOG("MetadataCommonUtils::GetSupportedPreviewSizeRange level info:%{public}dx%{public}d",
                size.width, size.height);
        }
        sizeList->insert(sizeList->end(), levelList->begin(), levelList->end());
        return sizeList;
    }

    auto extendList = GetSupportedPreviewSizeRangeFromExtendConfig(modeName, targetFormat, metadata);
    if (extendList != nullptr && extendList->empty() &&
        (modeName == SceneMode::CAPTURE || modeName == SceneMode::VIDEO)) {
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
    // LCOV_EXCL_STOP
}

std::shared_ptr<OHOS::Camera::CameraMetadata> MetadataCommonUtils::CopyMetadata(
    const std::shared_ptr<OHOS::Camera::CameraMetadata> srcMetadata)
{
    return OHOS::CameraStandard::CopyMetadata(srcMetadata);
}

bool MetadataCommonUtils::ProcessFocusTrackingModeInfo(const std::shared_ptr<OHOS::Camera::CameraMetadata>& metadata,
    FocusTrackingMode& mode)
{
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(metadata == nullptr, false, "metadata is nullptr");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FOCUS_TRACKING_MODE, &item);
    CHECK_RETURN_RET_DLOG(
        ret != CAM_META_SUCCESS || item.count == 0, false, "%{public}s FindCameraMetadataItem failed", __FUNCTION__);
    mode = static_cast<FocusTrackingMode>(item.data.u8[0]);
    return true;
    // LCOV_EXCL_STOP
}

bool MetadataCommonUtils::ProcessMetaObjects(const int32_t streamId,
    const std::shared_ptr<OHOS::Camera::CameraMetadata>& result,
    std::vector<sptr<MetadataObject>> &metaObjects, bool isNeedMirror, bool isNeedFlip, RectBoxType type)
{
    CHECK_RETURN_RET(result == nullptr, false);
    // camera_metadata_item_t metadataItem;
    // LCOV_EXCL_START
    common_metadata_header_t *metadata = result->get();
    std::vector<camera_metadata_item_t> metadataResults;
    std::vector<uint32_t> metadataTypes;
    GetMetadataResults(metadata, metadataResults, metadataTypes);
    if (metadataResults.size() == 0) {
        metaObjects.clear();
        MEDIA_DEBUG_LOG("Camera not ProcessFaceRectangles");
        return false;
    }
    int32_t ret = ProcessMetaObjects(streamId, metaObjects, metadataResults, metadataTypes,
        isNeedMirror, isNeedFlip, type);
    CHECK_RETURN_RET_ELOG(
        ret != CameraErrorCode::SUCCESS, false, "MetadataCommonUtils::ProcessFaceRectangles() is failed.");
    return true;
    // LCOV_EXCL_STOP
}

void MetadataCommonUtils::GetMetadataResults(const common_metadata_header_t *metadata,
    std::vector<camera_metadata_item_t>& metadataResults, std::vector<uint32_t>& metadataTypes)
{
    // LCOV_EXCL_START
    for (auto itr : g_typesOfMetadata) {
        camera_metadata_item_t item;
        int ret = Camera::FindCameraMetadataItem(metadata, itr, &item);
        if (ret == CAM_META_SUCCESS) {
            metadataResults.emplace_back(std::move(item));
            metadataTypes.emplace_back(itr);
        }
    }
    // LCOV_EXCL_STOP
}

int32_t MetadataCommonUtils::ProcessMetaObjects(const int32_t streamId, std::vector<sptr<MetadataObject>>& metaObjects,
    const std::vector<camera_metadata_item_t>& metadataItem,
    const std::vector<uint32_t>& metadataTypes,
    bool isNeedMirror, bool isNeedFlip, RectBoxType type)
{
    // LCOV_EXCL_START
    for (size_t i = 0; i < metadataItem.size(); ++i) {
        auto itr = g_HALResultToFwCameraMetaDetect.find(metadataTypes[i]);
        if (itr != g_HALResultToFwCameraMetaDetect.end()) {
            GenerateObjects(metadataItem[i], itr->second, metaObjects, isNeedMirror, isNeedFlip, type);
        } else {
            MEDIA_ERR_LOG("MetadataOutput::ProcessMetaObjects() unsupported type: %{public}d", metadataTypes[i]);
        }
    }
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

void MetadataCommonUtils::GenerateObjects(const camera_metadata_item_t &metadataItem, MetadataObjectType metadataType,
    std::vector<sptr<MetadataObject>> &metaObjects,
    bool isNeedMirror, bool isNeedFlip, RectBoxType rectBoxType)
{
    int32_t index = 0;
    int32_t countOfObject = 0;
    auto iteratorOfLengthMap = mapLengthOfType.find(metadataType);
    if (iteratorOfLengthMap != mapLengthOfType.end()) {
        countOfObject = metadataItem.count / iteratorOfLengthMap->second;
    }
    // LCOV_EXCL_START
    for (int32_t itr = 0; itr < countOfObject; ++itr) {
        sptr<MetadataObjectFactory> objectFactoryPtr = new MetadataObjectFactory();
        index++;
        ProcessBaseInfo(objectFactoryPtr, metadataItem, index, metadataType, isNeedMirror, isNeedFlip, rectBoxType);
        ProcessExternInfo(objectFactoryPtr, metadataItem, index, metadataType, isNeedMirror, isNeedFlip, rectBoxType);
        metaObjects.push_back(objectFactoryPtr->createMetadataObject(metadataType));
    }
    // LCOV_EXCL_STOP
}

void MetadataCommonUtils::ProcessBaseInfo(sptr<MetadataObjectFactory> factoryPtr,
    const camera_metadata_item_t &metadataItem, int32_t &index, MetadataObjectType metadataType,
    bool isNeedMirror, bool isNeedFlip, RectBoxType type)
{
    // LCOV_EXCL_START
    const int32_t rectLength = 4;
    const int32_t offsetOne = 1;
    const int32_t offsetTwo = 2;
    const int32_t offsetThree = 3;
    factoryPtr->SetObjectId(metadataItem.data.i32[index]);
    index++;
    int32_t timestampLowBits = metadataItem.data.i32[index++];
    int32_t timestampHighBits = metadataItem.data.i32[index++];
    int64_t timestamp =
        (static_cast<int64_t>(timestampHighBits) << 32) | (static_cast<int64_t>(timestampLowBits) & 0xFFFFFFFF);
    MEDIA_DEBUG_LOG("MetadataObjectFactory::ProcessBaseInfo set timestamp: %{public}" PRId64, timestamp);
    factoryPtr->SetTimestamp(timestamp);
    factoryPtr->SetBox(ProcessRectBox(metadataItem.data.i32[index], metadataItem.data.i32[index + offsetOne],
                                      metadataItem.data.i32[index + offsetTwo],
                                      metadataItem.data.i32[index + offsetThree], isNeedMirror, isNeedFlip, type));
    index += rectLength;
    factoryPtr->SetConfidence(metadataItem.data.i32[index]);
    index++;
    int32_t externalLength = metadataItem.data.i32[index];
    index++;
    MEDIA_DEBUG_LOG("MetadataOutput::GenerateObjects, type: %{public}d, externalLength: %{public}d", metadataType,
                    externalLength);
    // LCOV_EXCL_STOP
}

void MetadataCommonUtils::ProcessFaceDetectInfo(sptr<MetadataObjectFactory> factoryPtr,
    const camera_metadata_item_t &metadataItem, int32_t &index, bool isNeedMirror, bool isNeedFlip, RectBoxType type,
    MetadataObjectType typeFromHal)
{
    // LCOV_EXCL_START
    int32_t version = metadataItem.data.i32[index++];
    MEDIA_DEBUG_LOG("isNeedMirror: %{public}d, isNeedFlip: %{public}d, version: %{public}d",
        isNeedMirror, isNeedFlip, version);
    const int32_t rectLength = 4;
    const int32_t offsetOne = 1;
    const int32_t offsetTwo = 2;
    const int32_t offsetThree = 3;
    factoryPtr->SetLeftEyeBoundingBox(ProcessRectBox(
        metadataItem.data.i32[index], metadataItem.data.i32[index + offsetOne],
        metadataItem.data.i32[index + offsetTwo],
        metadataItem.data.i32[index + offsetThree], isNeedMirror, isNeedFlip, type));
    index += rectLength;
    factoryPtr->SetRightEyeBoundingBoxd(ProcessRectBox(
        metadataItem.data.i32[index], metadataItem.data.i32[index + offsetOne],
        metadataItem.data.i32[index + offsetTwo],
        metadataItem.data.i32[index + offsetThree], isNeedMirror, isNeedFlip, type));
    index += rectLength;
    if (typeFromHal == MetadataObjectType::FACE) {
        factoryPtr->SetEmotion(static_cast<Emotion>(metadataItem.data.i32[index]));
        index++;
        factoryPtr->SetEmotionConfidence(static_cast<Emotion>(metadataItem.data.i32[index]));
        index++;
    }
    factoryPtr->SetPitchAngle(metadataItem.data.i32[index]);
    index++;
    factoryPtr->SetYawAngle(metadataItem.data.i32[index]);
    index++;
    factoryPtr->SetRollAngle(metadataItem.data.i32[index]);
    index++;
    // LCOV_EXCL_STOP
}

void MetadataCommonUtils::ProcessExternInfo(sptr<MetadataObjectFactory> factoryPtr,
    const camera_metadata_item_t &metadataItem, int32_t &index,
    MetadataObjectType metadataType, bool isNeedMirror, bool isNeedFlip, RectBoxType type)
{
    // LCOV_EXCL_START
    switch (metadataType) {
        case MetadataObjectType::FACE:
        case MetadataObjectType::BASE_FACE_DETECTION:
            ProcessFaceDetectInfo(factoryPtr, metadataItem, index, isNeedMirror, isNeedFlip, type, metadataType);
            break;
        case MetadataObjectType::CAT_FACE:
            ProcessCatFaceDetectInfo(factoryPtr, metadataItem, index, isNeedMirror, isNeedFlip, type);
            break;
        case MetadataObjectType::DOG_FACE:
            ProcessDogFaceDetectInfo(factoryPtr, metadataItem, index, isNeedMirror, isNeedFlip, type);
            break;
        default:
            break;
    }
    // LCOV_EXCL_STOP
}

void MetadataCommonUtils::ProcessCatFaceDetectInfo(sptr<MetadataObjectFactory> factoryPtr,
    const camera_metadata_item_t &metadataItem, int32_t &index,
    bool isNeedMirror, bool isNeedFlip, RectBoxType type)
{
    // LCOV_EXCL_START
    int32_t version = metadataItem.data.i32[index++];
    MEDIA_DEBUG_LOG("isNeedMirror: %{public}d, isNeedFlip: %{public}d, version: %{public}d",
        isNeedMirror, isNeedFlip, version);
    const int32_t rectLength = 4;
    const int32_t offsetOne = 1;
    const int32_t offsetTwo = 2;
    const int32_t offsetThree = 3;
    factoryPtr->SetLeftEyeBoundingBox(ProcessRectBox(
        metadataItem.data.i32[index], metadataItem.data.i32[index + offsetOne],
        metadataItem.data.i32[index + offsetTwo],
        metadataItem.data.i32[index + offsetThree], isNeedMirror, isNeedFlip, type));
    index += rectLength;
    factoryPtr->SetRightEyeBoundingBoxd(ProcessRectBox(
        metadataItem.data.i32[index], metadataItem.data.i32[index + offsetOne],
        metadataItem.data.i32[index + offsetTwo],
        metadataItem.data.i32[index + offsetThree], isNeedMirror, isNeedFlip, type));
    index += rectLength;
    // LCOV_EXCL_STOP
}

void MetadataCommonUtils::ProcessDogFaceDetectInfo(sptr<MetadataObjectFactory> factoryPtr,
    const camera_metadata_item_t &metadataItem, int32_t &index,
    bool isNeedMirror, bool isNeedFlip, RectBoxType type)
{
    // LCOV_EXCL_START
    int32_t version = metadataItem.data.i32[index++];
    MEDIA_DEBUG_LOG("isNeedMirror: %{public}d, isNeedFlip: %{public}d, version: %{public}d",
        isNeedMirror, isNeedFlip, version);
    const int32_t rectLength = 4;
    const int32_t offsetOne = 1;
    const int32_t offsetTwo = 2;
    const int32_t offsetThree = 3;
    factoryPtr->SetLeftEyeBoundingBox(ProcessRectBox(
        metadataItem.data.i32[index], metadataItem.data.i32[index + offsetOne],
        metadataItem.data.i32[index + offsetTwo],
        metadataItem.data.i32[index + offsetThree], isNeedMirror, isNeedFlip, type));
    index += rectLength;
    factoryPtr->SetRightEyeBoundingBoxd(ProcessRectBox(
        metadataItem.data.i32[index], metadataItem.data.i32[index + offsetOne],
        metadataItem.data.i32[index + offsetTwo],
        metadataItem.data.i32[index + offsetThree], isNeedMirror, isNeedFlip, type));
    index += rectLength;
    // LCOV_EXCL_STOP
}

Rect MetadataCommonUtils::ProcessRectBox(int32_t offsetTopLeftX, int32_t offsetTopLeftY,
    int32_t offsetBottomRightX, int32_t offsetBottomRightY, bool isNeedMirror, bool isNeedFlip, RectBoxType type)
{
    if (type == RectBoxType::RECT_MECH) {
        return ProcessMechRectBox(offsetTopLeftX, offsetTopLeftY, offsetBottomRightX, offsetBottomRightY);
    }
    return ProcessCameraRectBox(offsetTopLeftX, offsetTopLeftY, offsetBottomRightX, offsetBottomRightY,
        isNeedMirror, isNeedFlip);
}

Rect MetadataCommonUtils::ProcessCameraRectBox(int32_t offsetTopLeftX, int32_t offsetTopLeftY,
    int32_t offsetBottomRightX, int32_t offsetBottomRightY, bool isNeedMirror, bool isNeedFlip)
{
    constexpr int32_t scale = 1000000;
    double topLeftX = 0;
    double topLeftY = 0;
    double width = 0;
    double height = 0;
    if (isNeedMirror) {
        topLeftX = scale - offsetBottomRightY;
        topLeftY = scale - offsetBottomRightX;
        width = offsetBottomRightY - offsetTopLeftY;
        height = offsetBottomRightX - offsetTopLeftX;
    } else if (isNeedFlip) {
        topLeftX = offsetTopLeftY;
        topLeftY = offsetTopLeftX;
        width = offsetBottomRightY - offsetTopLeftY;
        height = offsetBottomRightX - offsetTopLeftX;
    } else {
        topLeftX = scale - offsetBottomRightY;
        topLeftY = offsetTopLeftX;
        width = offsetBottomRightY - offsetTopLeftY;
        height = offsetBottomRightX - offsetTopLeftX;
    }
    topLeftX = topLeftX < 0 ? 0 : topLeftX;
    topLeftX = topLeftX > scale ? scale : topLeftX;
    topLeftY = topLeftY < 0 ? 0 : topLeftY;
    topLeftY = topLeftY > scale ? scale : topLeftY;

    return (Rect){ topLeftX / scale, topLeftY / scale, width / scale, height / scale};
}

Rect MetadataCommonUtils::ProcessMechRectBox(int32_t offsetTopLeftX, int32_t offsetTopLeftY,
    int32_t offsetBottomRightX, int32_t offsetBottomRightY)
{
    constexpr int32_t scale = 1000000;
    double topLeftX = static_cast<double>(offsetTopLeftX);
    double topLeftY = static_cast<double>(offsetTopLeftY);
    double width = static_cast<double>(offsetBottomRightX);
    double height = static_cast<double>(offsetBottomRightY);

    return (Rect){ topLeftX / scale, topLeftY / scale, width / scale, height / scale};
}

std::vector<float> ParsePhysicalApertureRangeByMode(const camera_metadata_item_t &item, const int32_t modeName)
{
    const float factor = 20.0;
    std::vector<float> allRange = {};
    for (uint32_t i = 0; i < item.count; i++) {
        allRange.push_back(item.data.f[i] * factor);
    }
    MEDIA_DEBUG_LOG("ParsePhysicalApertureRangeByMode allRange=%{public}s",
                    Container2String(allRange.begin(), allRange.end()).c_str());
    float npos = -1.0;
    std::vector<std::vector<float>> modeRanges = {};
    std::vector<float> modeRange = {};
    for (uint32_t i = 0; i < item.count - 1; i++) {
        bool isRangeByMode = item.data.f[i] == npos && item.data.f[i + 1] == npos;
        if (isRangeByMode) {
            modeRange.emplace_back(npos);
            MEDIA_DEBUG_LOG("ParsePhysicalApertureRangeByMode mode %{public}d, modeRange=%{public}s",
                            modeName, Container2String(modeRange.begin(), modeRange.end()).c_str());
            modeRanges.emplace_back(std::move(modeRange));
            modeRange.clear();
            i++;
            continue;
        }
        modeRange.emplace_back(item.data.f[i]);
    }
    float currentMode = static_cast<float>(modeName);
    auto it = std::find_if(modeRanges.begin(), modeRanges.end(),
        [currentMode](auto value) -> bool {
            return currentMode == value[0];
        });
    CHECK_RETURN_RET_ELOG(it == modeRanges.end(), {},
        "ParsePhysicalApertureRangeByMode Failed meta not support mode:%{public}d", modeName);

    return *it;
}

} // namespace CameraStandard
} // namespace OHOS
