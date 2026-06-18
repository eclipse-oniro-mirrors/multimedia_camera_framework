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

#include "video_info.h"

#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
VideoInfo::VideoInfo(const std::string& srcPath, const std::string& temp1Path, const std::string& temp2Path,
    const std::string& moviePath)
    : srcPath_(srcPath), temp1Path_(temp1Path), temp2Path_(temp2Path), moviePath_(moviePath) {}

VideoInfo::VideoInfo(const std::vector<std::string>& srcPaths, const std::string& temp1Path,
    const std::string& temp2Path, const std::string& moviePath)
    : srcPaths_(srcPaths), temp1Path_(temp1Path), temp2Path_(temp2Path), moviePath_(moviePath)
{
    if (!srcPaths_.empty()) {
        srcPath_ = srcPaths_[0];
    }
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
