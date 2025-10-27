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
#ifndef AV_CODEC_ADAPTER_H
#define AV_CODEC_ADAPTER_H
#include "av_codec_interface.h"
namespace OHOS {
namespace CameraStandard {
class AVCodecAdapter : public AVCodecIntf {
public:
    AVCodecAdapter();
    ~AVCodecAdapter() override;
    int32_t CreateAVMuxer(int32_t fd, OutputFormat format) override;
    int32_t CreateAVCodecVideoEncoder(const std::string &codecMime) override;
    int32_t AVMuxerSetParameter(const std::shared_ptr<Meta> &param) override;
    int32_t AVMuxerSetUserMeta(const std::shared_ptr<Meta> &userMeta) override;
    int32_t AVMuxerAddTrack(int32_t &trackIndex, const std::shared_ptr<Meta> &trackDesc) override;
    int32_t AVMuxerStart() override;
    int32_t AVMuxerWriteSample(uint32_t trackIndex, const std::shared_ptr<AVBuffer> &sample) override;
    int32_t AVMuxerStop() override;
    int32_t AVCodecVideoEncoderPrepare() override;
    int32_t AVCodecVideoEncoderStart() override;
    int32_t AVCodecVideoEncoderStop() override;
    int32_t AVCodecVideoEncoderRelease() override;
    bool IsVideoEncoderExisted() override;
    sptr<Surface> CreateInputSurface() override;
    int32_t QueueInputBuffer(uint32_t index) override;
    int32_t QueueInputParameter(uint32_t index) override;
    int32_t AVCodecVideoEncoderNotifyEos() override;
    int32_t ReleaseOutputBuffer(uint32_t index) override;
    int32_t AVCodecVideoEncoderSetParameter(const Format &format) override;
    int32_t AVCodecVideoEncoderSetCallback(const std::shared_ptr<MediaCodecCallback> &callback) override;
    int32_t AVCodecVideoEncoderInfoIframeSetCallback(
        const std::shared_ptr<MediaAVCodec::MediaCodecParameterWithAttrCallback>& callback) override;
    int32_t AVCodecVideoEncoderConfigure(const Format &format) override;
    void CreateAVSource(int32_t fd, int64_t offset, int64_t size) override;
    int32_t AVSourceGetSourceFormat(Format &format) override;
    int32_t AVSourceGetUserMeta(Format &format) override;
    int32_t AVSourceGetTrackFormat(Format &format, uint32_t trackIndex) override;
    void CreateAVDemuxer(std::shared_ptr<AVSource> source) override;
    int32_t ReadSampleBuffer(uint32_t trackIndex, std::shared_ptr<AVBuffer> sample) override;
    int32_t AVDemuxerSeekToTime(int64_t millisecond, SeekMode mode) override;
    int32_t AVDemuxerSelectTrackByID(uint32_t trackIndex) override;
    bool IsBframeSurported() override;
private:
    std::shared_ptr<AVMuxer> muxer_ = nullptr;
    std::shared_ptr<AVCodecVideoEncoder> videoEncoder_ = nullptr;
    std::shared_ptr<AVSource> source_ = nullptr;
    std::shared_ptr<AVDemuxer> demuxer_ = nullptr;
};
} //namespace CameraStandard
} //namespace OHOS
#endif // AV_CODEC_ADAPTER_H
