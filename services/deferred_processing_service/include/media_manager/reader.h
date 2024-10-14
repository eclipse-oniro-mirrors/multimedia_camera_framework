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
#ifndef OHOS_CAMERA_DPS_READER_H
#define OHOS_CAMERA_DPS_READER_H

#include "basic_definitions.h"
#include "demuxer.h"
#include "track.h"
#include "media_format.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
using namespace MediaAVCodec;
class Reader {
public:
    Reader() = default;
    virtual ~Reader();

    MediaManagerError Create(int32_t inputFd);
    MediaManagerError Read(TrackType trackType, std::shared_ptr<AVBuffer>& sample);
    MediaManagerError GetMediaInfo(std::shared_ptr<MediaInfo>& mediaInfo);
    MediaManagerError Reset(int64_t resetPts);

    inline const std::map<TrackType, const std::shared_ptr<Track>>& GetTracks() const
    {
        return tracks_;
    };

private:
    MediaManagerError GetSourceFormat();
    void GetSourceMediaInfo(std::shared_ptr<MediaInfo>& mediaInfo) const;
    MediaManagerError GetTrackMediaInfo(const TrackFormat& trackFormat, std::shared_ptr<MediaInfo>& mediaInfo) const;
    MediaManagerError InitTracksAndDemuxer();
    static int32_t FixFPS(const double fps);

private:
    std::shared_ptr<AVSource> source_ {nullptr};
    std::shared_ptr<Format> sourceFormat_ {nullptr};
    std::shared_ptr<Format> userFormat_ {nullptr};
    std::shared_ptr<Demuxer> inputDemuxer_ {nullptr};
    int32_t trackCount_ {0};
    std::map<TrackType, const std::shared_ptr<Track>> tracks_ {};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_READER_H