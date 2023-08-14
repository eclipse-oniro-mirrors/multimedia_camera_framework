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
typedef struct DetailInfo {
    int32_t format;
    int32_t width;
    int32_t height;
    int32_t fixedFps;
    int32_t minFps;
    int32_t maxFps;
    std::vector<uint32_t> abilityId;
} DetailInfo;

typedef struct StreamRelatedInfo {
    int32_t streamType;
    uint32_t detailInfoCount;
    std::vector<DetailInfo> detailInfo;
} StreamRelatedInfo;

typedef struct ModeInfo {
    int32_t modeName;
    uint32_t streamTypeCount;
    std::vector<StreamRelatedInfo> streamInfo;
} ModeInfo;

typedef struct ExtendInfo {
    uint32_t modeCount;
    std::vector<ModeInfo> modeInfo;
} ExtendInfo;

constexpr static int32_t MODE_FINISH = -1;
constexpr static int32_t STREAM_FINISH = -1;
constexpr static int32_t ABILITY_FINISH = -1;
constexpr static int32_t ONE_STEP = 1;
constexpr static int32_t TWO_STEP = 2;

class CameraStreamInfoParse {
public:
    void getModeInfo(int32_t* originInfo, uint32_t count, ExtendInfo& transferedInfo)
    {
        modeStartIndex_.push_back(0);
        for (uint32_t i = TWO_STEP; i < count; i++) {
            if (originInfo[i - TWO_STEP] == ABILITY_FINISH &&originInfo[i - ONE_STEP] == STREAM_FINISH
                && originInfo[i] == MODE_FINISH) { // 判断mode的-1 结束符位置
                    modeEndIndex_.push_back(i);
                    if (i + ONE_STEP < count) {
                        modeStartIndex_.push_back(i + ONE_STEP);
                    }
                transferedInfo.modeCount++;
            }
        }
        modeCount_ = transferedInfo.modeCount;
        transferedInfo.modeInfo.resize(transferedInfo.modeCount);

        getStreamCount(originInfo, transferedInfo);
        for (uint32_t i = 0; i < modeCount_; i++) {
            transferedInfo.modeInfo[i].modeName = originInfo[modeStartIndex_[i]];
            streamTypeCount_.push(transferedInfo.modeInfo[i].streamTypeCount);
        }
        for (uint32_t i = 0; i < transferedInfo.modeCount; i++) {
            getStreamInfo(originInfo, transferedInfo.modeInfo[i]);
        }
        for (uint32_t i = 0; i < transferedInfo.modeCount; i++) {
            getDetailStreamInfo(originInfo, transferedInfo.modeInfo[i]);
        }
    }
private:
    void getStreamCount(int32_t* originInfo, ExtendInfo& transferedInfo)
    {
        for (uint32_t i = 0; i < modeCount_; i++) {
            for (uint32_t j = modeStartIndex_[i]; j < modeEndIndex_[i]; j++) {
                if (j == modeStartIndex_[i]) {
                    streamStartIndex_.push(modeStartIndex_[i] + ONE_STEP);
                }
                if (originInfo[j] == STREAM_FINISH && originInfo[j - ONE_STEP] == ABILITY_FINISH) {
                    streamEndIndex_.push(j);
                    transferedInfo.modeInfo[i].streamTypeCount++;
                }
                if ((originInfo[j] == STREAM_FINISH) && (originInfo[j - ONE_STEP] == ABILITY_FINISH)
                    && ((j + ONE_STEP) < modeEndIndex_[i])) {
                    streamStartIndex_.push(j + ONE_STEP);
                }
            }
        }
        modeStartIndex_.clear();
        modeEndIndex_.clear();
        return;
    }

    void getStreamInfo(int32_t* originInfo, ModeInfo& modeInfo)
    {
        modeInfo.streamInfo.resize(modeInfo.streamTypeCount);
        for (uint32_t j = 0; j < modeInfo.streamTypeCount; j++) {
            modeInfo.streamInfo[j].streamType = originInfo[streamStartIndex_.front()];
            for (uint32_t k = streamStartIndex_.front(); k < streamEndIndex_.front(); k++) {
                if (k == streamStartIndex_.front()) {
                    abilityStartIndex_.push(k + ONE_STEP);
                }
                if (originInfo[k] == ABILITY_FINISH) {
                    abilityEndIndex_.push(k);
                    modeInfo.streamInfo[j].detailInfoCount++;
                }
                if (originInfo[k] == ABILITY_FINISH && originInfo[k + ONE_STEP] != STREAM_FINISH) {
                    abilityStartIndex_.push(k + ONE_STEP);
                }
            }
            deatiInfoCount_.push(modeInfo.streamInfo[j].detailInfoCount);
            streamStartIndex_.pop();
            streamEndIndex_.pop();
        }
        return;
    }

    void getDetailStreamInfo(int32_t* originInfo, ModeInfo& modeInfo)
    {
        for (uint32_t j = 0; j < streamTypeCount_.front(); j++) {
            modeInfo.streamInfo[j].detailInfo.resize(deatiInfoCount_.front());
            getDetailAbilityInfo(originInfo, modeInfo.streamInfo[j]);
        }
        streamTypeCount_.pop();
    }

    void getDetailAbilityInfo(int32_t* originInfo, StreamRelatedInfo& streamInfo)
    {
        uint32_t allOffset = 6;
        uint32_t formatOffset = 0;
        uint32_t widthOffset = 1;
        uint32_t heightOffset = 2;
        uint32_t fixedFpsOffset = 3;
        uint32_t minFpsOffset = 4;
        uint32_t maxFpsOffset = 5;
        for (uint32_t k = 0; k < deatiInfoCount_.front(); k++) {
            for (uint32_t m = abilityStartIndex_.front(); m < abilityEndIndex_.front(); m++) {
                streamInfo.detailInfo[k].format =
                    originInfo[m + formatOffset];
                streamInfo.detailInfo[k].width =
                    originInfo[m + widthOffset];
                streamInfo.detailInfo[k].height =
                    originInfo[m + heightOffset];
                streamInfo.detailInfo[k].fixedFps =
                    originInfo[m + fixedFpsOffset];
                streamInfo.detailInfo[k].minFps =
                    originInfo[m + minFpsOffset];
                streamInfo.detailInfo[k].maxFps =
                    originInfo[m + maxFpsOffset];
                for (uint32_t n = m + allOffset; n < abilityEndIndex_.front(); n++) {
                    streamInfo.detailInfo[k].abilityId.push_back(originInfo[n]);
                }
                m += abilityEndIndex_.front();
            }
            abilityStartIndex_.pop();
            abilityEndIndex_.pop();
        }
        deatiInfoCount_.pop();
    }
    uint32_t modeCount_ = 0;
    std::vector<uint32_t> modeStartIndex_ = {};
    std::vector<uint32_t> modeEndIndex_ = {};
    std::queue<uint32_t> streamStartIndex_;
    std::queue<uint32_t> streamEndIndex_;
    std::queue<uint32_t> streamTypeCount_;
    std::queue<uint32_t> deatiInfoCount_;
    std::queue<uint32_t> abilityEndIndex_;
    std::queue<uint32_t> abilityStartIndex_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_ERROR_CODE_H