/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_LOGIC_CAMERA_UTILS_H
#define OHOS_LOGIC_CAMERA_UTILS_H

#include <vector>
#include <unordered_map>

#include "camera_metadata_info.h"

namespace OHOS {
namespace CameraStandard {
namespace LogicCameraUtils {
int32_t GetFoldWithDirectionOrientationMap(common_metadata_header_t* metadata,
    std::unordered_map<uint32_t, std::vector<uint32_t>>& foldWithDirectionOrientationMap);
int32_t GetPhysicalOrientationByFoldAndDirection(const uint32_t foldStatus, uint32_t& orientation,
    const std::unordered_map<uint32_t, std::vector<uint32_t>>& foldWithDirectionOrientationMap);
}
} // namespace CameraStandard
} // namespace OHOS

#endif