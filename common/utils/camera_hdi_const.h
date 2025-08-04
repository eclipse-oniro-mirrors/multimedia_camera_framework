/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_HDI_CONST_H
#define OHOS_CAMERA_HDI_CONST_H

#include <cstdint>

namespace OHOS {
namespace CameraStandard {

constexpr int32_t GetVersionId(uint32_t major, uint32_t minor)
{
    const uint32_t offset = 8;
    return static_cast<int32_t>((major << offset) | minor);
}

constexpr int32_t HDI_VERSION_ID_1_0 = GetVersionId(1, 0);
constexpr int32_t HDI_VERSION_ID_1_1 = GetVersionId(1, 1);
constexpr int32_t HDI_VERSION_ID_1_2 = GetVersionId(1, 2);
constexpr int32_t HDI_VERSION_ID_1_3 = GetVersionId(1, 3);
constexpr int32_t HDI_VERSION_ID_1_4 = GetVersionId(1, 4);
constexpr int32_t HDI_VERSION_ID_1_5 = GetVersionId(1, 5);

} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_HDI_CONST_H