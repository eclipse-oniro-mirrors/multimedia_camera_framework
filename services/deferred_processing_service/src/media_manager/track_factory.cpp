/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
namespace {
    static const std::unordered_set<Media::Plugins::MediaType> TRACK_TYPES = {
        Media::Plugins::MediaType::AUDIO,
        Media::Plugins::MediaType::VIDEO,
        Media::Plugins::MediaType::TIMEDMETA
    };
}

TrackFactory::TrackFactory()
{
    DP_DEBUG_LOG("entered.");
}

TrackFactory::~TrackFactory()
{
    DP_DEBUG_LOG("entered.");
}

std::shared_ptr<Track> TrackFactory::CreateTrack(const std::shared_ptr<AVSource>& source, int32_t trackIndex)
{
    DP_DEBUG_LOG("entered.");
    DP_CHECK_ERROR_RETURN_RET_LOG(source == nullptr, nullptr, "AVSource is nullptr.");
    Format trackFormat;
    int32_t trackType = -1;
    auto ret = source->GetTrackFormat(trackFormat, trackIndex);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != static_cast<int32_t>(OK), nullptr, "Get track format failed.");
    DP_CHECK_ERROR_RETURN_RET_LOG(!trackFormat.GetIntValue(Media::Tag::MEDIA_TYPE, trackType),
        nullptr, "Get track type failed.");

    DP_INFO_LOG("CreateTrack type: %{public}d", trackType);
    auto type = static_cast<Media::Plugins::MediaType>(trackType);
    DP_CHECK_ERROR_RETURN_RET_LOG(!CheckTrackFormat(type), nullptr, "Track type: %{public}d is not supported.", type);

    auto track = std::make_shared<Track>();
    TrackFormat formatOfIndex;
    formatOfIndex.format = std::make_shared<Format>(trackFormat);
    formatOfIndex.trackId = trackIndex;
    track->SetFormat(formatOfIndex, type);
    return track;
}

bool TrackFactory::CheckTrackFormat(Media::Plugins::MediaType type)
{
    return TRACK_TYPES.find(type) != TRACK_TYPES.end();
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
