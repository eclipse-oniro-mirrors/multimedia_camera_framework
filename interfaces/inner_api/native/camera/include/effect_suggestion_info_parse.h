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
#ifndef EFFECT_SUGGESTION_INFO_PARSE_H
#define EFFECT_SUGGESTION_INFO_PARSE_H

#include <queue>
#include <vector>
#include <iostream>

namespace OHOS {
namespace CameraStandard {
using namespace std;

typedef struct EffectSuggestionModeInfo {
    int32_t modeType;
    std::vector<int32_t> effectSuggestionList;
} EffectSuggestionModeInfo;

typedef struct EffectSuggestionInfo {
    uint32_t modeCount;
    std::vector<EffectSuggestionModeInfo> modeInfo;
} EffectSuggestionInfo;

constexpr static int32_t MODE_END = -1;

class EffectSuggestionInfoParse {
public:
    void GetEffectSuggestionInfo(int32_t* originInfo, uint32_t count, EffectSuggestionInfo& effectSuggestionInfo)
    {
        ResizeModeInfo(originInfo, count, effectSuggestionInfo);
        ResizeEffectSuggestionList(originInfo, effectSuggestionInfo);
    }
private:
    void ResizeModeInfo(int32_t* originInfo, uint32_t count, EffectSuggestionInfo& effectSuggestionInfo)
    {
        uint32_t i = 0;
        uint32_t j = i + 1;
        while (j < count) {
            if (originInfo[j] == MODE_END) {
                std::pair<uint32_t, uint32_t> indexPair(i, j-1);
                modeInfoIndexRange_.push_back(indexPair);
                effectSuggestionInfo.modeCount++;
                i = j+1;
                j = i+1;
            } else {
                j++;
            }
        }
        effectSuggestionInfo.modeInfo.resize(effectSuggestionInfo.modeCount);
    }

    void ResizeEffectSuggestionList(int32_t* originInfo, EffectSuggestionInfo& effectSuggestionInfo)
    {
        for (auto it = modeInfoIndexRange_.begin(); it != modeInfoIndexRange_.end(); ++it) {
            uint32_t start = it->first;
            int modeInfoIndex = std::distance(modeInfoIndexRange_.begin(), it);
            EffectSuggestionModeInfo& modeInfo = effectSuggestionInfo.modeInfo[modeInfoIndex];
            int32_t mode = originInfo[start];
            int32_t typeNum = originInfo[start+1];
            modeInfo.modeType = mode;
            modeInfo.effectSuggestionList.resize(typeNum);
            uint32_t effectStartIndex = start + 2;
            for (int i = 0; i < typeNum; i++) {
                modeInfo.effectSuggestionList[i]=originInfo[effectStartIndex+i];
            }
        }
    }
    std::vector<std::pair<uint32_t, uint32_t>> modeInfoIndexRange_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // EFFECT_SUGGESTION_INFO_PARSE_H