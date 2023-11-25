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
#ifndef COLOR_SPACE_INFO_PARSE_H
#define COLOR_SPACE_INFO_PARSE_H

#include <queue>
#include <vector>
#include <iostream>

namespace OHOS {
namespace CameraStandard {
using namespace std;

typedef struct ColorSpaceStreamInfo {
    int32_t streamType;
    uint32_t colorSpaceCount;
    std::vector<int32_t> colorSpaces;
} ColorSpaceStreamInfo;

typedef struct ColorSpaceModeInfo {
    int32_t modeType;
    uint32_t streamTypeCount;
    std::vector<ColorSpaceStreamInfo> streamInfo;
} ColorSpaceModeInfo;

typedef struct ColorSpaceInfo {
    uint32_t modeCount;
    std::vector<ColorSpaceModeInfo> modeInfo;
} ColorSpaceInfo;

constexpr static int32_t MODE_FINISH_IDENTIFIER = -1;
constexpr static int32_t STREAM_FINISH_IDENTIFIER = -1;
constexpr static int32_t LOOP_ONE_STEP = 1;
constexpr static int32_t COMMON_STREAM_WITHOUT_TYPE = -1;

class ColorSpaceInfoParse {
public:
    void getColorSpaceInfo(int32_t* originInfo, uint32_t count, ColorSpaceInfo& transferedInfo)
    {
        modeStartIndex_.push_back(0);
        // 处理mode层级的信息，记录mode数量及每个mode开始和结束的下标
        for (uint32_t i = LOOP_ONE_STEP; i < count; i++) {
            // 连续两个-1代表当前模式的色彩空间信息上报结束
            if (originInfo[i - LOOP_ONE_STEP] == STREAM_FINISH_IDENTIFIER && originInfo[i] == MODE_FINISH_IDENTIFIER) {
                modeEndIndex_.push_back(i);
                if (i + LOOP_ONE_STEP < count) {
                    modeStartIndex_.push_back(i + LOOP_ONE_STEP);
                }
                transferedInfo.modeCount++;
            }
        }
        transferedInfo.modeInfo.resize(transferedInfo.modeCount);

        getColorSpaceStreamCount(originInfo, transferedInfo);
        for (uint32_t i = 0; i < transferedInfo.modeCount; i++) {
            transferedInfo.modeInfo[i].modeType = originInfo[modeStartIndex_[i]];
            getColorSpaceStreamInfo(originInfo, transferedInfo.modeInfo[i]);
        }
    }
private:
    void getColorSpaceStreamCount(int32_t* originInfo, ColorSpaceInfo& transferedInfo)
    {
        for (uint32_t i = 0; i < transferedInfo.modeCount; i++) {
            for (uint32_t j = modeStartIndex_[i]; j < modeEndIndex_[i]; j++) {
                if (j == modeStartIndex_[i]) {
                    streamStartIndex_.push(modeStartIndex_[i] + LOOP_ONE_STEP);
                }
                if (originInfo[j] == STREAM_FINISH_IDENTIFIER) {
                    streamEndIndex_.push(j);
                    transferedInfo.modeInfo[i].streamTypeCount++;
                }
                if ((originInfo[j] == STREAM_FINISH_IDENTIFIER) && ((j + LOOP_ONE_STEP) < modeEndIndex_[i])) {
                    streamStartIndex_.push(j + LOOP_ONE_STEP);
                }
            }
        }
        modeStartIndex_.clear();
        modeEndIndex_.clear();
    }

    void getColorSpaceStreamInfo(int32_t* originInfo, ColorSpaceModeInfo& modeInfo)
    {
        modeInfo.streamInfo.resize(modeInfo.streamTypeCount);
        for (uint32_t i = 0; i < modeInfo.streamTypeCount; i++) {
            uint32_t loopStart;
            // 第一套色彩空间能力集为common能力，不报streamType
            if (i == 0) {
                modeInfo.streamInfo[i].streamType = COMMON_STREAM_WITHOUT_TYPE;
                loopStart = streamStartIndex_.front();
            } else {
                // 除第一套外，其余色彩空间能力集的第一个int值表示streamType
                modeInfo.streamInfo[i].streamType = originInfo[streamStartIndex_.front()];
                loopStart = streamStartIndex_.front() + LOOP_ONE_STEP;
            }

            modeInfo.streamInfo[i].colorSpaceCount = streamEndIndex_.front() - loopStart;
            modeInfo.streamInfo[i].colorSpaces.resize(modeInfo.streamInfo[i].colorSpaceCount);
            int j = 0;
            for (uint32_t k = loopStart; k < streamEndIndex_.front(); k++) {
                modeInfo.streamInfo[i].colorSpaces[j] = originInfo[k];
                j++;
            }

            streamStartIndex_.pop();
            streamEndIndex_.pop();
        }
    }

    std::vector<uint32_t> modeStartIndex_ = {};
    std::vector<uint32_t> modeEndIndex_ = {};
    std::queue<uint32_t> streamStartIndex_;
    std::queue<uint32_t> streamEndIndex_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // COLOR_SPACE_INFO_PARSE_H