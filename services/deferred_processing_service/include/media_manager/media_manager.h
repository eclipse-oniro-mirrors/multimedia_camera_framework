/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
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

#ifndef OHOS_CAMERA_DPS_FILE_MANAGER_H
#define OHOS_CAMERA_DPS_FILE_MANAGER_H

#include <set>

#include "reader.h"
#include "writer.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class MediaManager {
public:
    MediaManager() = default;
    virtual ~MediaManager() = default;

    MediaManagerError Create(int32_t inFd, int32_t outFd, int32_t tempFd);
    MediaManagerError Pause();
    MediaManagerError Stop();
    MediaManagerError ReadSample(TrackType type, std::shared_ptr<AVBuffer>& sample);
    MediaManagerError WriteSample(TrackType type, const std::shared_ptr<AVBuffer>& sample);

    inline void GetMediaInfo(std::shared_ptr<MediaInfo>& mediaInfo)
    {
        mediaInfo = mediaInfo_;
    }

private:
    MediaManagerError InitReader();
    MediaManagerError InitWriter();
    MediaManagerError Recover(const int64_t size);
    MediaManagerError CopyAudioTrack();
    MediaManagerError InitRecoverReader(const int64_t size, int64_t& duration, int64_t& bitRate);
    MediaManagerError GetRecoverInfo(const int64_t size);

    int32_t inputFileFd_ {-1};
    int32_t outputFileFd_ {-1};
    int32_t tempFileFd_ {-1};
    int32_t finalFrameNum_ {0};
    int64_t resumePts_ {-1};
    int64_t pausePts_ {-1};
    int64_t curProcessPts_ {-1};
    int64_t finalSyncPts_ {-1};
    bool hasAudio_ {false};
    bool started_ {false};
    std::shared_ptr<Reader> inputReader_ {nullptr};
    std::shared_ptr<Reader> recoverReader_ {nullptr};
    std::shared_ptr<Writer> outputWriter_ {nullptr};
    std::shared_ptr<MediaInfo> mediaInfo_ {nullptr};
    std::set<int64_t> IFramePts_ {};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_FILE_MANAGER_H