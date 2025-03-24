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

#ifndef OHOS_CAMERA_DPS_MEDIA_FORMAT_H
#define OHOS_CAMERA_DPS_MEDIA_FORMAT_H

#include "meta_key.h"
#include "mime_type.h"
#include "video_types.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
const std::string MIME_VIDEO_AVC = Media::Plugins::MimeType::VIDEO_AVC;
const std::string MIME_VIDEO_HEVC = Media::Plugins::MimeType::VIDEO_HEVC;
const std::string MIME_TIMED_META = Media::Plugins::MimeType::TIMED_METADATA;
const std::string LIVE_PHOTO_COVERTIME = "com.openharmony.covertime";
const std::string TIMED_METADATA_VALUE = "com.openharmony.timed_metadata.vid_maker_info";
const std::string SCALING_FACTOR_KEY = "com.openharmony.scaling_factor";
const std::string INTERPOLATION_FRAME_PTS_KEY = "com.openharmony.interp_frame_pts";
const double DEFAULT_SCALING_FACTOR = -1.0;
const std::string DEFAULT_INTERPOLATION_FRAME_PTS = "";

enum class MediaInfoKey : uint32_t {
    META_VALUE_TYPE_NONE,
    META_VALUE_TYPE_INT32,
    META_VALUE_TYPE_INT64,
    META_VALUE_TYPE_FLOAT,
    META_VALUE_TYPE_DOUBLE,
    META_VALUE_TYPE_STRING,
};

enum class ColorRange {
    COL_RANGE_NONE = -1,
    COL_RANGE_UNSPECIFIED = 0,
    COL_RANGE_MPEG = 1,
    COL_RANGE_JPEG = 2,
};

struct CodecInfo {
    std::string mimeType;
    ColorRange colorRange;
    Media::Plugins::VideoPixelFormat pixelFormat;
    Media::Plugins::ColorPrimary colorPrimary;
    Media::Plugins::TransferCharacteristic colorTransferCharacter;
    int32_t profile;
    int32_t level;
    int64_t bitRate;
    int32_t fps;
    int64_t duration;
    int32_t width;
    int32_t height;
    int32_t rotation;
    int32_t bitMode;
    bool isHdrvivid;
};

struct MediaInfo {
    int64_t recoverTime;
    int32_t streamCount;
    std::string creationTime;
    float latitude {-1.0};
    float longitude {-1.0};
    float livePhotoCovertime {-1.0};
    CodecInfo codecInfo {};
};

struct MediaUserInfo {
    float scalingFactor{DEFAULT_SCALING_FACTOR};
    std::string interpolationFramePts{DEFAULT_INTERPOLATION_FRAME_PTS};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_MEDIA_FORMAT_H