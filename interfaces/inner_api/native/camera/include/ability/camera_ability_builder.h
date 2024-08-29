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
#ifndef CAMERA_ABILITY_BUILDER_H
#define CAMERA_ABILITY_BUILDER_H

#include <set>
#include <map>
#include <queue>
#include <vector>
#include <iostream>
#include <utility>
#include <variant>
#include <cstdint>
#include <memory>
#include <algorithm>
#include "metadata_utils.h"
#include "ability/camera_ability.h"
#include "ability/camera_ability_parse_util.h"
#include "session/capture_session.h"

namespace OHOS {
namespace CameraStandard {

using namespace std;

class CameraAbilityBuilder : public RefBase {
public:
    virtual ~CameraAbilityBuilder() = default;

    std::vector<sptr<CameraAbility>> GetAbility(int32_t modeName, common_metadata_header_t* metadata,
        const std::set<int32_t>& specIds, sptr<CaptureSession> session, bool isForApp = true);

    std::vector<sptr<CameraAbility>> GetConflictAbility(int32_t modeName, common_metadata_header_t* metadata);

private:
    std::vector<int32_t> GetData(int32_t modeName, common_metadata_header_t* metadata, uint32_t tagId, int32_t specId);

    std::vector<float> GetValidZoomRatioRange(const std::vector<int32_t>& data);
    bool IsSupportMacro(const std::vector<int32_t>& data);

    void SetModeSpecTagField(sptr<CameraAbility> ability, int32_t modeName, common_metadata_header_t* metadata,
        uint32_t tagId, int32_t specId);
    void SetOtherTag(sptr<CameraAbility> ability, int32_t modeName, sptr<CaptureSession> session);

    std::map<uint32_t, std::map<int32_t, std::vector<int32_t>>> cacheTagDataMap_;
    std::set<uint32_t> cachedTagSet_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_ABILITY_BUILDER_H
