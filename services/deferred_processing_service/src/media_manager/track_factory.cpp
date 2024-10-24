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

#include "track_factory.h"

#include "basic_definitions.h"
#include "dp_log.h"
#include "media_format.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
TrackFactory::TrackFactory()
{
    DP_DEBUG_LOG("entered.");
}

TrackFactory::~TrackFactory()
{
    DP_DEBUG_LOG("entered.");
}

std::shared_ptr<Track> TrackFactory::CreateTrack(const std::shared_ptr<AVSource>& source, int trackIndex)
{
    DP_DEBUG_LOG("entered.");
    Format trackFormat;
    int32_t trackType = -1;
    auto ret = source->GetTrackFormat(trackFormat, trackIndex);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), nullptr, "get track format failed.");
    DP_CHECK_ERROR_RETURN_RET_LOG(!trackFormat.GetIntValue(Media::Tag::MEDIA_TYPE, trackType),
        nullptr, "get track type failed.");

    DP_INFO_LOG("CreateTrack type: %{public}d", trackType);
    auto track = std::make_shared<Track>();
    if (static_cast<TrackType>(trackType) == TrackType::AV_KEY_AUDIO_TYPE ||
        static_cast<TrackType>(trackType) == TrackType::AV_KEY_VIDEO_TYPE) {
        TrackFormat formatOfIndex;
        formatOfIndex.format = std::make_shared<Format>(trackFormat);
        formatOfIndex.trackId = trackIndex;
        track->SetFormat(formatOfIndex, static_cast<TrackType>(trackType));
    }
    return track;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
