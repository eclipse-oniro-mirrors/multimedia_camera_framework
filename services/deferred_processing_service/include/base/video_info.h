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

#include "dps_fd.h"

namespace OHOS {
namespace CameraStandard {
class PictureIntf;
namespace DeferredProcessing {
class VideoInfo {
public:
    VideoInfo(const DpsFdPtr& srcFd, const DpsFdPtr& dstFd,
        const DpsFdPtr& movieFd = nullptr, const DpsFdPtr& movieCopyFd = nullptr);
    ~VideoInfo() = default;

    std::shared_ptr<DpsFd> srcFd_ {nullptr};
    std::shared_ptr<DpsFd> dstFd_ {nullptr};
    std::shared_ptr<DpsFd> movieFd_ {nullptr};
    std::shared_ptr<DpsFd> movieCopyFd_ {nullptr};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_VIDEO_INFO_H