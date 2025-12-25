/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_WATERMARK_INFO_H
#define OHOS_CAMERA_WATERMARK_INFO_H

namespace OHOS {
namespace CameraStandard {
// water mark
using namespace Media;

struct WatermarkInfo {
    int32_t captureID = 0;
    uint64_t timestamp = 0;
    int64_t expoTime = 0;
    int32_t expoIso = 0;
    double expoFNumber = 0;
    double expoEfl = 0;
    int64_t captureTime = 0;
};

} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_WATERMARK_INFO_H
