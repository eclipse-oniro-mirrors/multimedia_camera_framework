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

#ifndef AVCODEC_AUDIO_VIDEO_MUXER_H
#define AVCODEC_AUDIO_VIDEO_MUXER_H

#include "native_avmuxer.h"
#include "native_avcodec_base.h"
#include "native_avformat.h"
#include "native_avbuffer.h"
#include <atomic>
#include <cstdint>
#include <refbase.h>
#include "avmuxer.h"
#include "media_photo_asset_proxy.h"

namespace OHOS {
namespace CameraStandard {
enum TrackType {
    AUDIO_TRACK = 0,
    VIDEO_TRACK,
    META_TRACK
};
using namespace MediaAVCodec;
class AudioVideoMuxer : public RefBase {
public:
    explicit AudioVideoMuxer();
    ~AudioVideoMuxer();

    int32_t Create(int32_t fd, OH_AVOutputFormat format, std::shared_ptr<Media::PhotoAssetProxy> photoAssetProxy);
    int32_t AddTrack(int &trackId, OH_AVFormat *format, TrackType type);
    int32_t Start();
    int32_t WriteSampleBuffer(OH_AVBuffer *sample, TrackType type);
    int32_t Stop();
    int32_t Release();
    int32_t SetRotation(int32_t rotation);
    int32_t SetCoverTime(float timems);
    int32_t GetVideoFd();
    std::shared_ptr<Media::PhotoAssetProxy> GetPhotoAssetProxy();
    std::atomic<int32_t> releaseSignal_ = 2;

private:
    std::shared_ptr<AVMuxer> muxer_ = nullptr;
    int32_t fd_ = -1;
    std::shared_ptr<Media::PhotoAssetProxy> photoAssetProxy_;
    int audioTrackId_ = -1;
    int videoTrackId_ = -1;
    int metaTrackId_ = -1;
};
} // CameraStandard
} // OHOS
#endif // AVCODEC_SAMPLE_VIDEO_ENCODER_H