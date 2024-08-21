/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
#include "ability/camera_ability_parse_util.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {

void CameraAbilityParseUtil::GetModeInfo(
    const int32_t modeName, const camera_metadata_item_t &item, ProfileLevelInfo &modeInfo)
{
    int32_t* originInfo = item.data.i32;
    uint32_t count = item.count;
    if (count == 0 || originInfo == nullptr) {
        return;
    }
    uint32_t i = 0;
    uint32_t j = i + STEP_THREE;
    auto isModeEnd = [](int32_t *originInfo, uint32_t j) {
        return originInfo[j] == MODE_END && originInfo[j - 1] == SPEC_END &&
                originInfo[j - 2] == STREAM_END && originInfo[j - 3] == DETAIL_END;
    };
    while (j < count) {
        if (originInfo[j] != MODE_END) {
            j = j + STEP_FOUR;
            continue;
        }
        if (isModeEnd(originInfo, j)) {
            if (originInfo[i] == modeName) {
                GetSpecInfo(originInfo, i + 1, j - 1, modeInfo);
                break;
            } else {
                i = j + STEP_ONE;
                j = i + STEP_THREE;
            }
        } else {
            j++;
        }
    }
}

void CameraAbilityParseUtil::GetAvailableConfiguration(
    const int32_t modeName, common_metadata_header_t *metadata, AvailableConfig &availableConfig)
{
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_AVAILABLE_CONFIGURATIONS, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("GetAvailableConfiguration failed due to can't find related tag");
        return;
    }
    int32_t* originInfo = item.data.i32;
    uint32_t count = item.count;
    if (count == 0 || originInfo == nullptr) {
        return;
    }
    uint32_t i = 0;
    uint32_t j = i + STEP_ONE;
    while (j < count) {
        if (originInfo[j] != MODE_END) {
            j = j + STEP_TWO;
            continue;
        }
        if (originInfo[j-1] == TAG_END) {
            if (originInfo[i] == modeName) {
                GetAvailableConfigInfo(originInfo, i + 1, j - 1, availableConfig);
                break;
            } else {
                i = j + STEP_ONE;
                j = i + STEP_ONE;
            }
        } else {
            j++;
        }
    }
}

void CameraAbilityParseUtil::GetConflictConfiguration(
    const int32_t modeName, common_metadata_header_t *metadata, ConflictConfig &conflictConfig)
{
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_ABILITY_CONFLICT_CONFIGURATIONS, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("GetConflictConfiguration failed due to can't find related tag");
        return;
    }
    int32_t* originInfo = item.data.i32;
    uint32_t count = item.count;
    if (count == 0 || originInfo == nullptr) {
        return;
    }
    uint32_t i = 0;
    uint32_t j = i + STEP_ONE;
    while (j < count) {
        if (originInfo[j] != MODE_END) {
            j = j + STEP_TWO;
            continue;
        }
        if (originInfo[j-1] == TAG_END) {
            if (originInfo[i] == modeName) {
                GetConflictConfigInfo(originInfo, i + 1, j - 1, conflictConfig);
                break;
            } else {
                i = j + STEP_ONE;
                j = i + STEP_ONE;
            }
        } else {
            j++;
        }
    }
}

void CameraAbilityParseUtil::GetAbilityInfo(const int32_t modeName, common_metadata_header_t *metadata, uint32_t tagId,
    std::map<int32_t, std::vector<int32_t>> &infoMap)
{
    infoMap = {};
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata, tagId, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("GetAbilityInfo failed due to can't find related tag %{public}u", tagId);
        return;
    }
    int32_t* originInfo = item.data.i32;
    uint32_t count = item.count;
    if (count == 0 || originInfo == nullptr) {
        return;
    }
    uint32_t i = 0;
    uint32_t j = i + STEP_ONE;
    while (j < count) {
        if (originInfo[j] != MODE_END) {
            j = j + STEP_TWO;
            continue;
        }
        if (originInfo[j - 1] == INFO_END) {
            if (originInfo[i] == modeName) {
                GetInfo(originInfo, i + 1, j - 1, infoMap);
                break;
            } else {
                i = j + STEP_ONE;
                j = i + STEP_ONE;
            }
        } else {
            j++;
        }
    }
}

void CameraAbilityParseUtil::GetInfo(
    int32_t *originInfo, uint32_t start, uint32_t end, std::map<int32_t, std::vector<int32_t>> &infoMap)
{
    uint32_t i = start;
    uint32_t j = i;
    std::vector<std::pair<uint32_t, uint32_t>> infoIndexRange;
    while (j <= end) {
        if (originInfo[j] == INFO_END) {
            std::pair<uint32_t, uint32_t> indexPair(i, j);
            infoIndexRange.push_back(indexPair);
            i = j + STEP_ONE;
            j = i;
        } else {
            j++;
        }
    }

    for (const auto& indexPair : infoIndexRange) {
        i = indexPair.first;
        j = indexPair.second;
        int32_t specId = originInfo[i];
        std::vector<int32_t> infoValues(originInfo + i + 1, originInfo + j);
        infoMap[specId] = std::move(infoValues);
    }
}

void CameraAbilityParseUtil::GetSpecInfo(int32_t *originInfo, uint32_t start, uint32_t end, ProfileLevelInfo &modeInfo)
{
    uint32_t i = start;
    uint32_t j = i + STEP_TWO;
    std::vector<std::pair<uint32_t, uint32_t>> specIndexRange;
    while (j <= end) {
        if (originInfo[j] != SPEC_END) {
            j = j + STEP_THREE;
            continue;
        }
        if (originInfo[j - STEP_ONE] == STREAM_END && originInfo[j - STEP_TWO] == DETAIL_END) {
            std::pair<uint32_t, uint32_t> indexPair(i, j);
            specIndexRange.push_back(indexPair);
            i = j + STEP_ONE;
            j = i + STEP_TWO;
        } else {
            j++;
        }
    }
    uint32_t specCount = specIndexRange.size();
    modeInfo.specInfos.resize(specCount);

    for (uint32_t k = 0; k < specCount; ++k) {
        SpecInfo& specInfo = modeInfo.specInfos[k];
        i = specIndexRange[k].first;
        j = specIndexRange[k].second;
        specInfo.specId = originInfo[i];
        GetStreamInfo(originInfo, i + 1, j - 1, specInfo);
    }
}

void CameraAbilityParseUtil::GetStreamInfo(int32_t *originInfo, uint32_t start, uint32_t end, SpecInfo &specInfo)
{
    uint32_t i = start;
    uint32_t j = i + STEP_ONE;

    std::vector<std::pair<uint32_t, uint32_t>> streamIndexRange;
    while (j <= end) {
        if (originInfo[j] == STREAM_END) {
            if (originInfo[j - 1] == DETAIL_END) {
                std::pair<uint32_t, uint32_t> indexPair(i, j);
                streamIndexRange.push_back(indexPair);
                i = j + STEP_ONE;
                j = i + STEP_ONE;
            } else {
                j++;
            }
        } else {
            j = j + STEP_TWO;
        }
    }
    uint32_t streamTypeCount = streamIndexRange.size();
    specInfo.streamInfos.resize(streamTypeCount);

    for (uint32_t k = 0; k < streamTypeCount; ++k) {
        StreamInfo& streamInfo = specInfo.streamInfos[k];
        i = streamIndexRange[k].first;
        j = streamIndexRange[k].second;
        streamInfo.streamType = originInfo[i];
        GetDetailInfo(originInfo, i + 1, j - 1, streamInfo);
    }
}

void CameraAbilityParseUtil::GetDetailInfo(int32_t *originInfo, uint32_t start, uint32_t end, StreamInfo &streamInfo)
{
    uint32_t i = start;
    uint32_t j = i;
    std::vector<std::pair<uint32_t, uint32_t>> detailIndexRange;
    while (j <= end) {
        if (originInfo[j] == DETAIL_END) {
            std::pair<uint32_t, uint32_t> indexPair(i, j);
            detailIndexRange.push_back(indexPair);
            i = j + STEP_ONE;
            j = i;
        } else {
            j++;
        }
    }

    uint32_t detailCount = detailIndexRange.size();
    streamInfo.detailInfos.resize(detailCount);

    for (uint32_t k = 0; k < detailCount; ++k) {
        auto &detailInfo = streamInfo.detailInfos[k];
        i = detailIndexRange[k].first;
        j = detailIndexRange[k].second;
        detailInfo.format = static_cast<uint32_t>(originInfo[i++]);
        detailInfo.width = static_cast<uint32_t>(originInfo[i++]);
        detailInfo.height = static_cast<uint32_t>(originInfo[i++]);
        detailInfo.fixedFps = static_cast<uint32_t>(originInfo[i++]);
        detailInfo.minFps = static_cast<uint32_t>(originInfo[i++]);
        detailInfo.maxFps = static_cast<uint32_t>(originInfo[i++]);
        detailInfo.abilityIds.resize(j - i);
        std::transform(originInfo + i, originInfo + j, detailInfo.abilityIds.begin(),
            [](auto val) { return static_cast<uint32_t>(val); });
    }
}

void CameraAbilityParseUtil::GetAvailableConfigInfo(
    int32_t *originInfo, uint32_t start, uint32_t end, AvailableConfig &availableConfig)
{
    uint32_t i = start;
    uint32_t j = i;
    std::vector<std::pair<uint32_t, uint32_t>> infoIndexRange;
    while (j <= end) {
        if (originInfo[j] == TAG_END) {
            std::pair<uint32_t, uint32_t> indexPair(i, j-1);
            infoIndexRange.push_back(indexPair);
            i = j + STEP_ONE;
            j = i;
        } else {
            j++;
        }
    }

    uint32_t configInfoCount = infoIndexRange.size();
    availableConfig.configInfos.resize(configInfoCount);
    for (uint32_t k = 0; k < configInfoCount; ++k) {
        i = infoIndexRange[k].first;
        j = infoIndexRange[k].second;
        auto &configInfo = availableConfig.configInfos[k];
        configInfo.specId = originInfo[i++];
        configInfo.tagIds.resize(j - i + 1);
        std::transform(originInfo + i, originInfo + j + 1, configInfo.tagIds.begin(),
            [](auto val) { return static_cast<uint32_t>(val); });
    }
}

void CameraAbilityParseUtil::GetConflictConfigInfo(
    int32_t *originInfo, uint32_t start, uint32_t end, ConflictConfig &conflictConfig)
{
    uint32_t i = start;
    uint32_t j = i;
    std::vector<std::pair<uint32_t, uint32_t>> infoIndexRange;
    while (j <= end) {
        if (originInfo[j] == TAG_END) {
            std::pair<uint32_t, uint32_t> indexPair(i, j-1);
            infoIndexRange.push_back(indexPair);
            i = j + STEP_ONE;
            j = i;
        } else {
            j++;
        }
    }

    uint32_t configInfoCount = infoIndexRange.size();
    conflictConfig.configInfos.resize(configInfoCount);
    for (uint32_t k = 0; k < configInfoCount; ++k) {
        i = infoIndexRange[k].first;
        j = infoIndexRange[k].second;
        auto &configInfo = conflictConfig.configInfos[k];
        configInfo.cid = originInfo[i++];
        uint32_t tagInfoCount = (j - i + 1) / 2;
        configInfo.tagInfos.resize(tagInfoCount);
        for (uint32_t m = 0; m < tagInfoCount; ++m) {
            auto &tagInfo = configInfo.tagInfos[m];
            tagInfo.first = static_cast<uint32_t>(originInfo[i++]);
            tagInfo.second = static_cast<uint32_t>(originInfo[i++]);
        }
    }
}
} // namespace CameraStandard
} // namespace OHOS