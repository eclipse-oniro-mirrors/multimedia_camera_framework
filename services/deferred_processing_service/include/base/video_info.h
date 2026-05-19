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

#ifndef OHOS_CAMERA_DPS_VIDEO_INFO_H
#define OHOS_CAMERA_DPS_VIDEO_INFO_H

#include <fcntl.h>
#include <string>

namespace OHOS {
namespace CameraStandard {
class PictureIntf;
namespace DeferredProcessing {
class VideoInfo {
public:
VideoInfo(const std::string& srcPath, const std::string& temp1Path, const std::string& temp2Path,
    const std::string& moviePath = "");
~VideoInfo() = default;

    inline const std::string& GetSrcPath() const
    {
        return srcPath_;
    }
    inline const std::string& GetTemp1Path() const
    {
        return temp1Path_;
    }
    inline const std::string& GetTemp2Path() const
    {
        return temp2Path_;
    }
    inline const std::string& GetMoviePath() const
    {
        return moviePath_;
    }

private:
    std::string srcPath_;
    std::string temp1Path_;
    std::string temp2Path_;
    std::string moviePath_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_VIDEO_INFO_H