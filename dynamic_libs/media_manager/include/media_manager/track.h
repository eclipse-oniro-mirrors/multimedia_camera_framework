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

#ifndef OHOS_CAMERA_DPS_TRACK_H
#define OHOS_CAMERA_DPS_TRACK_H

#include "av_common.h"
#include "media_types.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
using namespace MediaAVCodec;

struct TrackFormat {
    std::shared_ptr<Format> format;
    int32_t trackId;
};

class Track {
public:
    Track() = default;
    virtual ~Track();
    const TrackFormat& GetFormat();
    void SetFormat(const TrackFormat& format, Media::Plugins::MediaType type);
    
    inline Media::Plugins::MediaType GetType()
    {
        return trackType_;
    };

private:
    TrackFormat trackFormat_ {nullptr};
    Media::Plugins::MediaType trackType_ {Media::Plugins::MediaType::UNKNOWN};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_TRACK_H