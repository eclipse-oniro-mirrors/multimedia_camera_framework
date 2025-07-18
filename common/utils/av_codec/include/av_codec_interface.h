/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef AV_CODEC_INTERFACE_H
#define AV_CODEC_INTERFACE_H
#include "avcodec_video_encoder.h"
#include "avmuxer.h"
#include "avdemuxer.h"
#include "avsource.h"

/**
 * @brief Internal usage only, for camera framework interacts with av_codec related interfaces.
 * @since 12
 */
namespace OHOS::CameraStandard {
using AVMuxer = OHOS::MediaAVCodec::AVMuxer;
using AVCodecVideoEncoder = OHOS::MediaAVCodec::AVCodecVideoEncoder;
using AVMuxerFactory = OHOS::MediaAVCodec::AVMuxerFactory;
using VideoEncoderFactory = OHOS::MediaAVCodec::VideoEncoderFactory;
using Meta = OHOS::MediaAVCodec::Meta;
using AVBuffer = OHOS::MediaAVCodec::AVBuffer;
using AVCodecBufferInfo = OHOS::MediaAVCodec::AVCodecBufferInfo;
using AVCodecBufferFlag = OHOS::MediaAVCodec::AVCodecBufferFlag;
using Format = OHOS::Media::Format;
using MediaCodecCallback = OHOS::MediaAVCodec::MediaCodecCallback;
using AVSource = OHOS::MediaAVCodec::AVSource;
using SeekMode = OHOS::Media::Plugins::SeekMode;
using OutputFormat = OHOS::Media::Plugins::OutputFormat;
using AVSourceFactory = OHOS::MediaAVCodec::AVSourceFactory;
using AVDemuxer = OHOS::MediaAVCodec::AVDemuxer;
using AVDemuxerFactory = OHOS::MediaAVCodec::AVDemuxerFactory;
const int32_t AV_ERR_OK = 0;
const int32_t AV_ERR_INVALID_VAL = -1;
const int32_t AV_ERR_FAILED = -2;
class AVCodecIntf {
public:
    virtual ~AVCodecIntf() = default;
    virtual int32_t CreateAVMuxer(int32_t fd, OutputFormat format) = 0;
    virtual int32_t CreateAVCodecVideoEncoder(const std::string& codecMime) = 0;
    virtual int32_t AVMuxerSetParameter(const std::shared_ptr<Meta>& param) = 0;
    virtual int32_t AVMuxerSetUserMeta(const std::shared_ptr<Meta>& userMeta) = 0;
    virtual int32_t AVMuxerAddTrack(int32_t& trackIndex, const std::shared_ptr<Meta>& trackDesc) = 0;
    virtual int32_t AVMuxerStart() = 0;
    virtual int32_t AVMuxerWriteSample(uint32_t trackIndex, const std::shared_ptr<AVBuffer>& sample) = 0;
    virtual int32_t AVMuxerStop() = 0;
    virtual int32_t AVCodecVideoEncoderPrepare() = 0;
    virtual int32_t AVCodecVideoEncoderStart() = 0;
    virtual int32_t AVCodecVideoEncoderStop() = 0;
    virtual int32_t AVCodecVideoEncoderRelease() = 0;
    virtual bool IsVideoEncoderExisted() = 0;
    virtual sptr<Surface> CreateInputSurface() = 0;
    virtual int32_t QueueInputBuffer(uint32_t index) = 0;
    virtual int32_t AVCodecVideoEncoderNotifyEos() = 0;
    virtual int32_t ReleaseOutputBuffer(uint32_t index) = 0;
    virtual int32_t AVCodecVideoEncoderSetParameter(const Format& format) = 0;
    virtual int32_t AVCodecVideoEncoderSetCallback(const std::shared_ptr<MediaCodecCallback>& callback) = 0;
    virtual int32_t AVCodecVideoEncoderConfigure(const Format& format) = 0;
    virtual void CreateAVSource(int32_t fd, int64_t offset, int64_t size) = 0;
    virtual int32_t AVSourceGetSourceFormat(Format& format) = 0;
    virtual int32_t AVSourceGetUserMeta(Format& format) = 0;
    virtual int32_t AVSourceGetTrackFormat(Format& format, uint32_t trackIndex) = 0;
    virtual void CreateAVDemuxer(std::shared_ptr<AVSource> source) = 0;
    virtual int32_t ReadSampleBuffer(uint32_t trackIndex, std::shared_ptr<AVBuffer> sample) = 0;
    virtual int32_t AVDemuxerSeekToTime(int64_t millisecond, SeekMode mode) = 0;
    virtual int32_t AVDemuxerSelectTrackByID(uint32_t trackIndex) = 0;
};
}  // namespace OHOS::CameraStandard
#endif //AV_CODEC_INTERFACE_H