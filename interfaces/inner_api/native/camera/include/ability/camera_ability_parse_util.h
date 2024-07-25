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
#ifndef CAMERA_ABILITY_PARSE_UTIL_H
#define CAMERA_ABILITY_PARSE_UTIL_H

#include <queue>
#include <vector>
#include <iostream>
#include <utility>
#include <variant>
#include <cstdint>
#include <memory>
#include <cstdint>
#include "metadata_utils.h"
#include <algorithm>

namespace OHOS {
namespace CameraStandard {

using namespace std;

typedef struct ProfileDetailInfo {
    uint32_t format;
    uint32_t width;
    uint32_t height;
    uint32_t fixedFps;
    uint32_t minFps;
    uint32_t maxFps;
    std::vector<uint32_t> abilityIds;
} ProfileDetailInfo;

typedef struct StreamInfo {
    int32_t streamType;
    std::vector<ProfileDetailInfo> detailInfos;
} StreamInfo;

typedef struct SpecInfo {
    int32_t specId;
    std::vector<StreamInfo> streamInfos;
} SpecInfo;

typedef struct ProfileLevelInfo {
    std::vector<SpecInfo> specInfos;
} ProfileLevelInfo;

typedef struct ConflictConfigInfo {
    int32_t cid;
    std::vector<std::pair<uint32_t, uint32_t>> tagInfos;
} ConflictConfigInfo;

typedef struct ConflictConfig {
    std::vector<ConflictConfigInfo> configInfos;
} ConflictConfig;

typedef struct AvailableConfigInfo {
    int32_t specId;
    std::vector<uint32_t> tagIds;
} AvailableConfigInfo;

typedef struct AvailableConfig {
    std::vector<AvailableConfigInfo> configInfos;
} AvailableConfig;

const int32_t MODE_END = -1;
const int32_t SPEC_END = -1;
const int32_t STREAM_END = -1;
const int32_t DETAIL_END = -1;
const int32_t INFO_END = -1;
const int32_t TAG_END = -1;
const int32_t STEP_ONE = 1;
const int32_t STEP_TWO = 2;
const int32_t STEP_THREE = 3;
const int32_t STEP_FOUR = 4;

class CameraAbilityParseUtil {
public:
    static void GetModeInfo(
        const int32_t modeName, const camera_metadata_item_t& item, ProfileLevelInfo& modeInfo);
    static void GetAvailableConfiguration(
        const int32_t modeName, common_metadata_header_t* metadata, AvailableConfig& availableConfig);
    static void GetConflictConfiguration(
        const int32_t modeName, common_metadata_header_t* metadata, ConflictConfig& conflictConfig);
    static void GetAbilityInfo(const int32_t modeName, common_metadata_header_t* metadata, uint32_t tagId,
        std::map<int32_t, std::vector<int32_t>>& infoMap);

private:
    static void GetInfo(
        int32_t* originInfo, uint32_t start, uint32_t end, std::map<int32_t, std::vector<int32_t>>& infoMap);
    static void GetSpecInfo(int32_t* originInfo, uint32_t start, uint32_t end, ProfileLevelInfo& modeInfo);
    static void GetStreamInfo(int32_t* originInfo, uint32_t start, uint32_t end, SpecInfo& specInfo);
    static void GetDetailInfo(int32_t* originInfo, uint32_t start, uint32_t end, StreamInfo& streamInfo);
    static void GetAvailableConfigInfo(
        int32_t* originInfo, uint32_t start, uint32_t end, AvailableConfig& availableConfig);
    static void GetConflictConfigInfo(
        int32_t* originInfo, uint32_t start, uint32_t end, ConflictConfig& conflictConfig);
};
} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_ABILITY_PARSE_UTIL_H