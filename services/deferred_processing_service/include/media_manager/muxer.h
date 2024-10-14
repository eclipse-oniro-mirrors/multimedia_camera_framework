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

#ifndef OHOS_CAMERA_DPS_MUXER_H
#define OHOS_CAMERA_DPS_MUXER_H

#include "avmuxer.h"
#include "basic_definitions.h"
#include "media_format.h"
#include "track.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
using namespace MediaAVCodec;
class Muxer {
public:
    Muxer() = default;
    virtual ~Muxer();

    MediaManagerError Create(int32_t outputFd, Plugins::OutputFormat format);
    MediaManagerError AddTracks(const std::map<TrackType, const std::shared_ptr<Track>>& trackMap);
    MediaManagerError WriteStream(TrackType trackType, const std::shared_ptr<AVBuffer>& sample);
    MediaManagerError Start();
    MediaManagerError Stop();
    MediaManagerError AddMediaInfo(const std::shared_ptr<MediaInfo>& mediaInfo);

private:
    std::shared_ptr<AVMuxer> muxer_ {nullptr};
    int32_t videoTrackId_ {-1};
    int32_t audioTrackId_ {-1};
};

} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_MUXER_H