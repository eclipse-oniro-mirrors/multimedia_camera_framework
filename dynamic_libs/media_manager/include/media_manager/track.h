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

enum class AuxiliaryType : int32_t {
    UNKNOWN = -1,
    RAW_AUDIO,
    VIDEO,
};

class Track {
public:
    Track(int32_t id, std::unique_ptr<Format> format, Media::Plugins::MediaType trackType);
    virtual ~Track() = default;

    void SetAuxiliaryType(AuxiliaryType type);
    std::shared_ptr<Media::Meta> GetMeta();

    inline int32_t GetId() const
    {
        return trackId_;
    }
    
    inline Media::Plugins::MediaType GetType() const
    {
        return trackType_;
    };

    inline AuxiliaryType GetAuxiliaryType() const
    {
        return auxType_;
    };

private:
    int32_t trackId_ {-1};
    std::unique_ptr<Format> format_ {nullptr};
    Media::Plugins::MediaType trackType_ {Media::Plugins::MediaType::UNKNOWN};
    AuxiliaryType auxType_ {AuxiliaryType::UNKNOWN};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_TRACK_H