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
#include "dp_log.h"
#include "track.h"
#include "media_format.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class Reader {
public:
    Reader() = default;
    virtual ~Reader();

    MediaManagerError Create(int32_t inputFd);
    MediaManagerError Read(Media::Plugins::MediaType trackType, std::shared_ptr<AVBuffer>& sample);
    MediaManagerError GetMediaInfo(std::shared_ptr<MediaInfo>& mediaInfo);
    MediaManagerError Reset(int64_t resetPts);

    inline const std::map<Media::Plugins::MediaType, std::shared_ptr<Track>>& GetTracks()
    {
        return tracks_;
    };

private:
    MediaManagerError GetSourceFormat();
    MediaManagerError GetUserMeta();
    void GetSourceMediaInfo(std::shared_ptr<MediaInfo>& mediaInfo) const;
    MediaManagerError GetTrackMediaInfo(const TrackFormat& trackFormat, std::shared_ptr<MediaInfo>& mediaInfo) const;
    MediaManagerError InitTracksAndDemuxer();
    static int32_t FixFPS(const double fps);
    Media::Plugins::VideoEncodeBitrateMode MapVideoBitrateMode(const std::string& modeName) const;

    template <typename T>
    bool CheckAndGetValue(const std::shared_ptr<Format>& format, const std::string_view& key, T& value) const
    {
        bool ret = false;
        if (format == nullptr) {
            return ret;
        }

        if constexpr (std::is_same_v<T, int32_t>) {
            ret = format->GetIntValue(key, value);
        } else if constexpr (std::is_same_v<T, float>) {
            ret = format->GetFloatValue(key, value);
        } else if constexpr (std::is_same_v<T, double>) {
            ret = format->GetDoubleValue(key, value);
        } else if constexpr (std::is_same_v<T, int64_t>) {
            ret = format->GetLongValue(key, value);
        } else if constexpr (std::is_same_v<T, std::string>) {
            ret = format->GetStringValue(key, value);
        }
        return ret;
    }

private:
    std::shared_ptr<AVSource> source_ {nullptr};
    std::shared_ptr<Format> sourceFormat_ {nullptr};
    std::shared_ptr<Format> userFormat_ {nullptr};
    std::shared_ptr<Demuxer> inputDemuxer_ {nullptr};
    int32_t trackCount_ {0};
    std::map<Media::Plugins::MediaType, std::shared_ptr<Track>> tracks_ {};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_READER_H