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

#ifndef AVCODEC_SAMPLE_VIDEO_ENCODER_H
#define AVCODEC_SAMPLE_VIDEO_ENCODER_H

#include "frame_record.h"
#include "native_avcodec_videoencoder.h"
#include "output/camera_output_capability.h"
#include "sample_info.h"
#include "camera_util.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
class VideoEncoder {
public:
    VideoEncoder() = default;
    explicit VideoEncoder(VideoCodecType type);
    ~VideoEncoder();

    int32_t Create(const std::string &codecMime);
    int32_t Config();
    int32_t Start();
    int32_t PushInputData(sptr<CodecAVBufferInfo> info);
    int32_t NotifyEndOfStream();
    int32_t FreeOutputData(uint32_t bufferIndex);
    bool EncodeSurfaceBuffer(sptr<FrameRecord> frameRecord);
    int32_t Stop();
    int32_t Release();
    int32_t GetSurface();
    int32_t ReleaseSurfaceBuffer(sptr<FrameRecord> frameRecord);

private:
    int32_t SetCallback(CodecUserData *codecUserData);
    int32_t SetParameterCallback(CodecUserData *codecUserData);
    int32_t Configure();
    void RestartVideoCodec(shared_ptr<Size> size, int32_t rotation);
    bool EnqueueBuffer(sptr<FrameRecord> frameRecord);
    std::atomic<bool> isStarted_ { false };
    std::mutex encoderMutex_;
    OH_AVCodec *encoder_ = nullptr;
    std::mutex contextMutex_;
    CodecUserData *context_ = nullptr;
    shared_ptr<Size> size_;
    int32_t rotation_ = 0;
    std::mutex surfaceMutex_; // guard codecSurface_
    sptr<Surface> codecSurface_;
    VideoCodecType videoCodecType_ = VIDEO_ENCODE_TYPE_HEVC;
    int32_t bitrate_ = 0;
    bool successFrame_ = false;
};
} // CameraStandard
} // OHOS
#endif // AVCODEC_SAMPLE_VIDEO_ENCODER_H