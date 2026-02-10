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

const std::string ENC_PARAM_KEY = "com.openharmony.encParam";
const std::string IS_WATER_MARK_KEY = "com.openharmony.isWaterMark";
const std::string RECORDER_TIMESTAMP_KEY = "com.openharmony.recorder.timestamp";
const std::string LIVE_PHOTO_COVERTIME = "com.openharmony.covertime";
const std::string TIMED_METADATA_VALUE = "com.openharmony.timed_metadata.vid_maker_info";

const std::string DEVICE_FOLD_STATE_KEY = "com.openharmony.deviceFoldState";
const std::string DEVICE_MODEL_KEY = "com.openharmony.deviceModel";
const std::string CAMERA_POSITION_KEY = "com.openharmony.cameraPosition";

const std::string SCALING_FACTOR_KEY = "com.openharmony.scaling_factor";
const std::string INTERPOLATION_FRAME_PTS_KEY = "com.openharmony.interp_frame_pts";
const std::string STAGE_VID_KEY = "com.openharmony.stage_vid";
const std::string WATER_MARK_INFO_KEY = "com.openharmony.water_mark_info";

enum class MediaInfoKey : uint32_t {
    META_VALUE_TYPE_NONE,
    META_VALUE_TYPE_INT32,
    META_VALUE_TYPE_INT64,
    META_VALUE_TYPE_FLOAT,
    META_VALUE_TYPE_DOUBLE,
    META_VALUE_TYPE_STRING,
};

struct WaterMarkInfo {
    std::string imagePath;
    int32_t rotation {0};
    float scaleFactor {0};
    int32_t x {0};
    int32_t y {0};
    int32_t width {0};
    int32_t height {0};
};

struct CodecInfo {
    std::string mimeType;
    int32_t profile {-1};
    int32_t level {-1};
    int64_t bitRate {-1};
    int32_t fps {-1};
    int64_t duration {-1};
    int32_t width {-1};
    int32_t height {-1};
    bool isHdrvivid {false};
    bool colorRange {false};
    bool isBFrame {false};
    uint32_t srqFactor {0};
    Media::Plugins::VideoPixelFormat pixelFormat {Media::Plugins::VideoPixelFormat::NV12};
    Media::Plugins::ColorPrimary colorPrimary {Media::Plugins::ColorPrimary::BT2020};
    Media::Plugins::TransferCharacteristic colorTransferCharacter {Media::Plugins::TransferCharacteristic::BT709};
    Media::Plugins::VideoRotation rotation {Media::Plugins::VideoRotation::VIDEO_ROTATION_0};
    Media::Plugins::VideoEncodeBitrateMode bitMode {Media::Plugins::VideoEncodeBitrateMode::SQR};
    Media::Plugins::VideoEncodeBFrameGopMode bFrameGopMode
        {Media::Plugins::VideoEncodeBFrameGopMode::VIDEO_ENCODE_GOP_ADAPTIVE_B_MODE};
};

struct MediaInfo {
    int64_t recoverTime {-1};
    int32_t streamCount {-1};
    float latitude {-1.0};
    float longitude {-1.0};
    float livePhotoCovertime {-1.0};
    std::string creationTime;
    std::string isWaterMark;
    std::string waterMarkInfo;
    std::string deviceFoldState;
    std::string deviceModel;
    std::string cameraPosition;
    CodecInfo codecInfo {};
};

} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_MEDIA_FORMAT_H