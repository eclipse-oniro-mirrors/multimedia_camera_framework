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

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
const std::string MINE_VIDEO_AVC = Media::Plugins::MimeType::VIDEO_AVC;
const std::string MINE_VIDEO_HEVC = Media::Plugins::MimeType::VIDEO_HEVC;
const std::string VIDEO_FRAME_COUNT = "com.openharmony.frame_num";
const std::string RECORD_SYSTEM_TIMESTAMP = "com.openharmony.recorder.timestamp";

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

enum class PixelFormat {
    PIX_FMT_NONE    = -1,
    PIX_FMT_YUV420P = 0,
    PIX_FMT_YUVI420 = 1,
    PIX_FMT_NV12 = 2,
    PIX_FMT_YUV420P10LE = 62,
};

enum class ColorPrimaries {
    COL_PRI_RESERVED0 = 0,
    COL_PRI_BT709     = 1,
    COL_PRI_BT2020    = 9, // hdr
};

enum class ColorTransferCharacteristic {
    COL_TRC_RESERVED0 = 0,
    COL_TRC_BT709     = 1,
    COL_TRC_BT2020_10 = 14,
    COL_TRC_BT2020_12 = 15,
    COL_TRC_ARIB_STD_B67 = 18,  // colorPrimary  ARIB STD-B67, known as "Hybrid log-gamma"
};

enum class AVCProfile : int32_t {
    AVC_PROFILE_BASELINE = 0,
    AVC_PROFILE_HIGH = 4,
    AVC_PROFILE_MAIN = 8,
};

struct CodecInfo {
    std::string mimeType;
    ColorRange colorRange;
    PixelFormat pixelFormat;  // color space pixel format. e.g. YUV420P, NV12 etc.
    ColorPrimaries colorPrimary;
    ColorTransferCharacteristic colorTransferCharacter;
    int32_t profile;
    int32_t level;
    int64_t bitRate;
    int32_t fps;
    int64_t duration;
    int32_t numFrames;
    int32_t width;
    int32_t height;
    int32_t rotation;
    int32_t isHdrvivid;
    int32_t bitMode;
};

struct MediaInfo {
    int64_t recoverTime;
    int32_t streamCount;
    std::string creationTime;
    float latitude;
    float longitude;
    CodecInfo codecInfo {};
    std::string recorderTime;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_MEDIA_FORMAT_H