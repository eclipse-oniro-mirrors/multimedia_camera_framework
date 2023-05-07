/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef CAMERA_STREAM_INFO_PARSE_H
#define CAMERA_STREAM_INFO_PARSE_H

#include <queue>
#include <vector>
#include <iostream>

namespace OHOS {
namespace CameraStandard {
using namespace std;
#define MAX_NUM 100
#define STEP 4
typedef struct DetailInfo {
    int32_t format;
    int32_t width;
    int32_t height;
    int32_t fps;
} DetailInfo;

typedef struct StreamInfo {
    int32_t streamType;
    uint32_t detailInfoCount;
    DetailInfo detailInfo[MAX_NUM];
} StreamInfo;

typedef struct ModeInfo {
    int32_t modeName;
    uint32_t streamTypeCount;
    StreamInfo streamInfo[MAX_NUM];
} ModeInfo;

typedef struct ExtendInfo {
    uint32_t modeCount;
    ModeInfo modeInfo[MAX_NUM];
} ExtendInfo;

class CameraStreamInfoParse {
public:
    void getModeInfo(int32_t* originInfo, uint32_t count, ExtendInfo& transferedInfo)
    {
        modeStartIndex_.push_back(0);
        for (uint32_t i = 1; i < count; i++) {
            if (originInfo[i -1] == -1 && originInfo[i] == -1) {
                    modeEndIndex_.push_back(i);
                    if (i + 1 < count) {
                        modeStartIndex_.push_back(i + 1);
                    }
                transferedInfo.modeCount++;
            }
        }
        modeCount_ = transferedInfo.modeCount;
        for (uint32_t i = 0; i < transferedInfo.modeCount; i++) {
            transferedInfo.modeInfo[i].modeName = originInfo[modeStartIndex_[i]];
        }
        getStreamCount(originInfo, transferedInfo);
        getStreamInfo(originInfo, transferedInfo);
        getDetailStreamInfo(originInfo, transferedInfo);
    }
private:
    void getStreamCount(int32_t* originInfo, ExtendInfo& transferedInfo)
    {
        for (uint32_t i = 0; i < modeCount_; i++) {
            for (uint32_t j = modeStartIndex_[i]; j < modeEndIndex_[i]; j++) {
                if (j == modeStartIndex_[i]) {
                    streamStartIndex_.push(modeStartIndex_[i] + 1);
                }
                if (originInfo[j] == -1) {
                    streamEndIndex_.push(j);
                    transferedInfo.modeInfo[i].streamTypeCount++;
                }
                if ((originInfo[j] == -1) && (j + 1 < modeEndIndex_[i])) {
                    streamStartIndex_.push(j + 1);
                }
            }
        }
        modeStartIndex_.clear();
        modeEndIndex_.clear();
        return;
    }
    void getStreamInfo(int32_t* originInfo, ExtendInfo& transferedInfo)
    {
        std::queue<uint32_t> tempStreamStartIndex = streamStartIndex_;
        std::queue<uint32_t> tempStreamEndIndex = streamEndIndex_;
        std::queue<uint32_t> streamTypeCount;
        for (uint32_t i = 0; i < modeCount_; i++) {
            streamTypeCount.push(transferedInfo.modeInfo[i].streamTypeCount);
        }
        streamTypeCount_ = streamTypeCount;
        for (uint32_t i = 0; i < modeCount_; i++) {
            for (uint32_t j = 0; j < streamTypeCount.front(); j++) {
                transferedInfo.modeInfo[i].streamInfo[j].streamType = originInfo[tempStreamStartIndex.front()];
                transferedInfo.modeInfo[i].streamInfo[j].detailInfoCount =
                    (tempStreamEndIndex.front() - tempStreamStartIndex.front()) / STEP;
                deatiInfoCount_.push(transferedInfo.modeInfo[i].streamInfo[j].detailInfoCount);
                tempStreamStartIndex.pop();
                tempStreamEndIndex.pop(); // 使用streamStartIndex 的一个副本
            }
            streamTypeCount.pop();
        }
        return;
    }
    void getDetailStreamInfo(int32_t* originInfo, ExtendInfo& transferedInfo)
    {
        std::queue<uint32_t> tempStreamStartIndex = streamStartIndex_;
        std::queue<uint32_t> deatiInfoCount = deatiInfoCount_;
        uint32_t formatOffset = 1;
        uint32_t widthOffset = 2;
        uint32_t heightOffset = 3;
        uint32_t fpsOffset = 4;
        for (uint32_t i = 0; i < modeCount_; i++) {
            for (uint32_t j = 0; j < streamTypeCount_.front(); j++) {
            uint32_t index = 0;
                for (uint32_t k = 0; k <deatiInfoCount.front(); k++) {
                    int indexLoop = tempStreamStartIndex.front();
                    transferedInfo.modeInfo[i].streamInfo[j].detailInfo[k].format =
                        originInfo[indexLoop + index + formatOffset];
                    transferedInfo.modeInfo[i].streamInfo[j].detailInfo[k].width =
                        originInfo[indexLoop + index + widthOffset];
                    transferedInfo.modeInfo[i].streamInfo[j].detailInfo[k].height =
                        originInfo[indexLoop + index + heightOffset];
                    transferedInfo.modeInfo[i].streamInfo[j].detailInfo[k].fps =
                        originInfo[indexLoop + index + fpsOffset];
                    index += STEP;
                }
                deatiInfoCount.pop();
                tempStreamStartIndex.pop();
                streamStartIndex_.pop();
                streamEndIndex_.pop();
                deatiInfoCount_.pop();
            }
            streamTypeCount_.pop();
        }
    }
private:
    std::vector<uint32_t>  modeStartIndex_ = {};
    std::vector<uint32_t> modeEndIndex_ = {};
    std::queue<uint32_t> streamStartIndex_;
    std::queue<uint32_t> streamEndIndex_;
    uint32_t modeCount_ = 0;
    std::queue<uint32_t> streamTypeCount_;
    std::queue<uint32_t> deatiInfoCount_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_ERROR_CODE_H