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

#ifndef OHOS_CAMERA_DPS_DEMUXER_H
#define OHOS_CAMERA_DPS_DEMUXER_H

#include "avdemuxer.h"
#include "basic_definitions.h"
#include "track.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
using namespace MediaAVCodec;
class Demuxer {
public:
    Demuxer() = default;
    virtual ~Demuxer();

    MediaManagerError Create(const std::shared_ptr<AVSource>& source,
        const std::map<Media::Plugins::MediaType, const std::shared_ptr<Track>>& tracks);
    MediaManagerError ReadStream(Media::Plugins::MediaType trackType, std::shared_ptr<AVBuffer>& sample);
    MediaManagerError SeekToTime(int64_t lastPts);

private:
    MediaManagerError SeletctTrackByID(int32_t trackID);
    int32_t GetTrackId(Media::Plugins::MediaType trackType);
    void SetTrackId(Media::Plugins::MediaType trackType, int32_t trackId);

    std::shared_ptr<AVDemuxer> demuxer_ {nullptr};
    std::unordered_map<Media::Plugins::MediaType, int32_t> trackIds_ = {
        {Media::Plugins::MediaType::AUDIO, INVALID_TRACK_ID},
        {Media::Plugins::MediaType::VIDEO, INVALID_TRACK_ID},
        {Media::Plugins::MediaType::TIMEDMETA, INVALID_TRACK_ID}
    };
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEMUXER_H