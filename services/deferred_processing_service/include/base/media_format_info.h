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

#ifndef MEDIA_FORMAT_INFO_H
#define MEDIA_FORMAT_INFO_H

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
constexpr double DEFAULT_SCALING_FACTOR = -1.0;
struct MediaUserInfo {
    float scalingFactor {DEFAULT_SCALING_FACTOR};
    std::string interpolationFramePts;
    std::string stageVid;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // MEDIA_FORMAT_INFO_H