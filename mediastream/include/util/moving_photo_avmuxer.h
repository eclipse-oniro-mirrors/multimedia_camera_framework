/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_MEDIA_STREAM_MOVING_PHOTO_AVMUXER_H
#define OHOS_CAMERA_MEDIA_STREAM_MOVING_PHOTO_AVMUXER_H

#include <atomic>
#include <cstdint>
#include <refbase.h>
#include "avmuxer.h"
#include "media_description.h"
#include "photo_asset_interface.h"
#include "avcodec_errors.h"

namespace OHOS {
namespace CameraStandard {
using namespace MediaAVCodec;

const std::string MOVING_PHOTO_COVER_TIME = "com.openharmony.covertime";
const std::string MOVING_PHOTO_VIDEO_ID = "com.openharmony.videoId";
const std::string MOVING_PHOTO_DEFERRED_VIDEO_ENHANCE_FLAG = "com.openharmony.deferredVideoEnhanceFlag";
const std::string MOVING_PHOTO_START_TIME = "com.openharmony.starttime";
const std::string MOVING_PHOTO_ENCODER_PARAM = "com.openharmony.encParam";
struct MuxerConfig
{
    float covertime;
    std::string videoId;
    bool hasVideoId = false;
    uint32_t videoEnhanceFlag;
    bool hasEnhanceFlag = false;
    std::string starttime;
    std::string bitrateString;
    bool hasBitrateString = false;
};

class MovingPhotoAVMuxer : public RefBase {
public:
    explicit MovingPhotoAVMuxer();
    ~MovingPhotoAVMuxer();

    int32_t Create(Plugins::OutputFormat format, int32_t fd);
    int32_t AddTrack(int32_t &trackId, std::shared_ptr<Meta> meta);
    int32_t Start();
    int32_t WriteSampleBuffer(int32_t trackId, std::shared_ptr<OHOS::Media::AVBuffer> sample);
    int32_t Stop();
    int32_t Release();
    int32_t SetParameter(const std::shared_ptr<Meta> &param);
    int32_t SetTimedMetadata();
    int32_t GetVideoFd();

    int32_t SetUserMeta(MuxerConfig& config);
    std::shared_ptr<PhotoAssetIntf> GetPhotoAssetProxy();
    int audioTrackId_ = -1;
    int videoTrackId_ = -1;
    int metaTrackId_ = -1;
private:
    std::shared_ptr<AVMuxer> muxer_ = nullptr;
    int32_t fd_ = -1;
};
} // CameraStandard
} // OHOS
#endif // OHOS_CAMERA_MEDIA_STREAM_MOVING_PHOTO_AVMUXER_H