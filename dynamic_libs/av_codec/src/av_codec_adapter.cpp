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
#include "av_codec_adapter.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
AVCodecAdapter::AVCodecAdapter()
{
    MEDIA_DEBUG_LOG("AVCodecAdapter constructor");
}

AVCodecAdapter::~AVCodecAdapter()
{
    MEDIA_DEBUG_LOG("AVCodecAdapter destructor");
}

int32_t AVCodecAdapter::CreateAVMuxer(int32_t fd, OutputFormat format)
{
    MEDIA_DEBUG_LOG("CreateAVMuxer start");
    muxer_ = AVMuxerFactory::CreateAVMuxer(fd, format);
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, AV_ERR_FAILED, "CreateAVMuxer failed");
    return AV_ERR_OK;
}

int32_t AVCodecAdapter::CreateAVCodecVideoEncoder(const std::string &codecMime)
{
    MEDIA_DEBUG_LOG("CreateAVCodecVideoEncoder start");
    videoEncoder_ = VideoEncoderFactory::CreateByMime(codecMime);
    CHECK_RETURN_RET_ELOG(
        videoEncoder_ == nullptr, AV_ERR_FAILED, "CreateAVCodecVideoEncoder failed");
    MEDIA_DEBUG_LOG("CreateAVCodecVideoEncoder success");
    return AV_ERR_OK;
}

int32_t AVCodecAdapter::AVMuxerSetParameter(const std::shared_ptr<Meta> &param)
{
    MEDIA_DEBUG_LOG("AVMuxerSetParameter start");
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, AV_ERR_INVALID_VAL, "muxer_ is not created");
    CHECK_RETURN_RET_ELOG(param == nullptr, AV_ERR_INVALID_VAL, "input param is nullptr!");
    int32_t ret = muxer_->SetParameter(param);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, AV_ERR_FAILED, "AVMuxerSetParameter failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVMuxerSetParameter end");
    return ret;
}

int32_t AVCodecAdapter::AVMuxerSetUserMeta(const std::shared_ptr<Meta> &userMeta)
{
    MEDIA_DEBUG_LOG("AVMuxerSetUserMeta start");
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, AV_ERR_INVALID_VAL, "muxer_ is not created");
    CHECK_RETURN_RET_ELOG(userMeta == nullptr, AV_ERR_INVALID_VAL, "input userMeta is nullptr!");
    int32_t ret = muxer_->SetUserMeta(userMeta);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, AV_ERR_FAILED, "AVMuxerSetUserMeta failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVMuxerSetUserMeta end");
    return ret;
}

int32_t AVCodecAdapter::AVMuxerAddTrack(int32_t &trackIndex, const std::shared_ptr<Meta> &trackDesc)
{
    MEDIA_DEBUG_LOG("AVMuxerAddTrack start");
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, AV_ERR_INVALID_VAL, "muxer_ is not created");
    CHECK_RETURN_RET_ELOG(trackDesc == nullptr, AV_ERR_INVALID_VAL, "input trackDesc is nullptr!");
    int32_t ret = muxer_->AddTrack(trackIndex, trackDesc);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, AV_ERR_FAILED, "AVMuxerAddTrack failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVMuxerAddTrack end");
    return ret;
}

int32_t AVCodecAdapter::AVMuxerStart()
{
    MEDIA_DEBUG_LOG("AVMuxerStart start");
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, AV_ERR_INVALID_VAL, "muxer_ is not created");
    int32_t ret = muxer_->Start();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, AV_ERR_FAILED, "AVMuxerStart failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVMuxerStart end");
    return ret;
}

int32_t AVCodecAdapter::AVMuxerWriteSample(uint32_t trackIndex, const std::shared_ptr<AVBuffer> &sample)
{
    MEDIA_DEBUG_LOG("AVMuxerWriteSampleBuffer start");
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, AV_ERR_INVALID_VAL, "muxer_ is not created");
    CHECK_RETURN_RET_ELOG(sample == nullptr, AV_ERR_INVALID_VAL, "input sample is nullptr!");
    int32_t ret = muxer_->WriteSample(trackIndex, sample);
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVMuxerWriteSampleBuffer failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVMuxerWriteSampleBuffer end");
    return ret;
}

int32_t AVCodecAdapter::AVMuxerStop()
{
    MEDIA_DEBUG_LOG("AVMuxerStop start");
    CHECK_RETURN_RET_ELOG(muxer_ == nullptr, AV_ERR_INVALID_VAL, "muxer_ is not created");
    int32_t ret = muxer_->Stop();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, AV_ERR_FAILED, "AVMuxerStop failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVMuxerStop end");
    return ret;
}

int32_t AVCodecAdapter::AVCodecVideoEncoderPrepare()
{
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderPrepare start");
    CHECK_RETURN_RET_ELOG(videoEncoder_ == nullptr, AV_ERR_INVALID_VAL, "videoEncoder_ is not created");
    int32_t ret = videoEncoder_->Prepare();
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVCodecVideoEncoderPrepare failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderPrepare end");
    return ret;
}

int32_t AVCodecAdapter::AVCodecVideoEncoderStart()
{
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderStart start");
    CHECK_RETURN_RET_ELOG(videoEncoder_ == nullptr, AV_ERR_INVALID_VAL, "videoEncoder_ is not created");
    int32_t ret = videoEncoder_->Start();
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVCodecVideoEncoderStart failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderStart end");
    return ret;
}

int32_t AVCodecAdapter::AVCodecVideoEncoderStop()
{
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderStop start");
    CHECK_RETURN_RET_ELOG(videoEncoder_ == nullptr, AV_ERR_INVALID_VAL, "videoEncoder_ is not created");
    int32_t ret = videoEncoder_->Stop();
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVCodecVideoEncoderStop failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderStop end");
    return ret;
}

int32_t AVCodecAdapter::AVCodecVideoEncoderRelease()
{
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderRelease start");
    CHECK_RETURN_RET_ELOG(videoEncoder_ == nullptr, AV_ERR_INVALID_VAL, "videoEncoder_ is not created");
    int32_t ret = videoEncoder_->Release();
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVCodecVideoEncoderRelease failed, ret: %{public}d", ret);
    videoEncoder_ = nullptr;
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderRelease end");
    return ret;
}

bool AVCodecAdapter::IsVideoEncoderExisted()
{
    MEDIA_DEBUG_LOG("IsVideoEncoderExisted start");
    CHECK_RETURN_RET_ELOG(videoEncoder_ == nullptr, false, "videoEncoder_ is not created");
    return true;
}

sptr<Surface> AVCodecAdapter::CreateInputSurface()
{
    MEDIA_DEBUG_LOG("CreateInputSurface start");
    CHECK_RETURN_RET_ELOG(videoEncoder_ == nullptr, nullptr, "videoEncoder_ is not created");
    sptr<Surface> surface = videoEncoder_->CreateInputSurface();
    CHECK_RETURN_RET_ELOG(surface == nullptr, nullptr, "CreateInputSurface failed");
    MEDIA_DEBUG_LOG("CreateInputSurface end");
    return surface;
}

int32_t AVCodecAdapter::QueueInputBuffer(uint32_t index)
{
    MEDIA_DEBUG_LOG("QueueInputBuffer start");
    CHECK_RETURN_RET_ELOG(videoEncoder_ == nullptr, AV_ERR_INVALID_VAL, "videoEncoder_ is not created");
    int32_t ret = videoEncoder_->QueueInputBuffer(index);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, AV_ERR_FAILED, "QueueInputBuffer failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("QueueInputBuffer end");
    return ret;
}

int32_t AVCodecAdapter::AVCodecVideoEncoderNotifyEos()
{
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderNotifyEos start");
    CHECK_RETURN_RET_ELOG(videoEncoder_ == nullptr, AV_ERR_INVALID_VAL, "videoEncoder_ is not created");
    int32_t ret = videoEncoder_->NotifyEos();
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVCodecVideoEncoderNotifyEos failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderNotifyEos end");
    return ret;
}

int32_t AVCodecAdapter::ReleaseOutputBuffer(uint32_t index)
{
    MEDIA_DEBUG_LOG("ReleaseOutputBuffer start");
    CHECK_RETURN_RET_ELOG(videoEncoder_ == nullptr, AV_ERR_INVALID_VAL, "videoEncoder_ is not created");
    int32_t ret = videoEncoder_->ReleaseOutputBuffer(index);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, AV_ERR_FAILED, "ReleaseOutputBuffer failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("ReleaseOutputBuffer end");
    return ret;
}

int32_t AVCodecAdapter::AVCodecVideoEncoderSetParameter(const Format &format)
{
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderSetParameter start");
    CHECK_RETURN_RET_ELOG(videoEncoder_ == nullptr, AV_ERR_INVALID_VAL, "videoEncoder_ is not created");
    int32_t ret = videoEncoder_->SetParameter(format);
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVCodecVideoEncoderSetParameter failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderSetParameter end");
    return ret;
}

int32_t AVCodecAdapter::AVCodecVideoEncoderSetCallback(const std::shared_ptr<MediaCodecCallback> &callback)
{
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderSetCallback start");
    CHECK_RETURN_RET_ELOG(videoEncoder_ == nullptr, AV_ERR_INVALID_VAL, "videoEncoder_ is not created");
    CHECK_RETURN_RET_ELOG(callback == nullptr, AV_ERR_INVALID_VAL, "input callback is nullptr!");
    int32_t ret = videoEncoder_->SetCallback(callback);
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVCodecVideoEncoderSetCallback failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderSetCallback end");
    return ret;
}

int32_t AVCodecAdapter::AVCodecVideoEncoderConfigure(const Format &format)
{
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderConfigure start");
    CHECK_RETURN_RET_ELOG(videoEncoder_ == nullptr, AV_ERR_INVALID_VAL, "videoEncoder_ is not created");
    int32_t ret = videoEncoder_->Configure(format);
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVCodecVideoEncoderConfigure failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderConfigure end");
    return ret;
}

void AVCodecAdapter::CreateAVSource(int32_t fd, int64_t offset, int64_t size)
{
    MEDIA_DEBUG_LOG("CreateAVSource start");
    source_ = AVSourceFactory::CreateWithFD(fd, offset, size);
    CHECK_RETURN_ELOG(source_ == nullptr,
        "CreateAVSource failed for fd: %{public}d, offset: %{public}" PRId64 ", size: %{public}" PRId64,
        fd, offset, size);
    MEDIA_DEBUG_LOG("CreateAVSource end");
}

int32_t AVCodecAdapter::AVSourceGetSourceFormat(Format &format)
{
    MEDIA_DEBUG_LOG("AVSourceGetSourceFormat start");
    CHECK_RETURN_RET_ELOG(source_ == nullptr, AV_ERR_INVALID_VAL, "source_ is not created");
    int32_t ret = source_->GetSourceFormat(format);
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVSourceGetSourceFormat failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVSourceGetSourceFormat end");
    return ret;
}

int32_t AVCodecAdapter::AVSourceGetUserMeta(Format &format)
{
    MEDIA_DEBUG_LOG("AVSourceGetUserMeta start");
    CHECK_RETURN_RET_ELOG(source_ == nullptr, AV_ERR_INVALID_VAL, "source_ is not created");
    int32_t ret = source_->GetUserMeta(format);
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVSourceGetUserMeta failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVSourceGetUserMeta end");
    return ret;
}

int32_t AVCodecAdapter::AVSourceGetTrackFormat(Format &format, uint32_t trackIndex)
{
    MEDIA_DEBUG_LOG("AVSourceGetTrackFormat start");
    CHECK_RETURN_RET_ELOG(source_ == nullptr, AV_ERR_INVALID_VAL, "source_ is not created");
    int32_t ret = source_->GetTrackFormat(format, trackIndex);
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVSourceGetTrackFormat failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVSourceGetTrackFormat end");
    return ret;
}

void AVCodecAdapter::CreateAVDemuxer(std::shared_ptr<AVSource> source)
{
    MEDIA_DEBUG_LOG("CreateAVDemuxer start");
    CHECK_RETURN_ELOG(source == nullptr, "source is nullptr");
    demuxer_ = AVDemuxerFactory::CreateWithSource(source);
    CHECK_RETURN_ELOG(demuxer_ == nullptr, "CreateAVDemuxer failed");
    MEDIA_DEBUG_LOG("CreateAVDemuxer end");
}

int32_t AVCodecAdapter::ReadSampleBuffer(uint32_t trackIndex, std::shared_ptr<AVBuffer> sample)
{
    MEDIA_DEBUG_LOG("ReadSampleBuffer start");
    CHECK_RETURN_RET_ELOG(demuxer_ == nullptr, AV_ERR_INVALID_VAL, "demuxer_ is not created");
    CHECK_RETURN_RET_ELOG(sample == nullptr, AV_ERR_INVALID_VAL, "input sample is nullptr!");
    int32_t ret = demuxer_->ReadSampleBuffer(trackIndex, sample);
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "ReadSampleBuffer failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("ReadSampleBuffer end");
    return ret;
}

int32_t AVCodecAdapter::AVDemuxerSeekToTime(int64_t millisecond, SeekMode mode)
{
    MEDIA_DEBUG_LOG("AVDemuxerSeekToTime start");
    CHECK_RETURN_RET_ELOG(demuxer_ == nullptr, AV_ERR_INVALID_VAL, "demuxer_ is not created");
    int32_t ret = demuxer_->SeekToTime(millisecond, mode);
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVDemuxerSeekToTime failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVDemuxerSeekToTime end");
    return ret;
}

int32_t AVCodecAdapter::AVDemuxerSelectTrackByID(uint32_t trackIndex)
{
    MEDIA_DEBUG_LOG("AVDemuxerSelectTrackByID start");
    CHECK_RETURN_RET_ELOG(demuxer_ == nullptr, AV_ERR_INVALID_VAL, "demuxer_ is not created");
    int32_t ret = demuxer_->SelectTrackByID(trackIndex);
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVDemuxerSelectTrackByID failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVDemuxerSelectTrackByID end");
    return ret;
}

extern "C" AVCodecIntf *createAVCodecIntf()
{
    return new AVCodecAdapter();
}
} // namespace CameraStandard
} // namespace OHOS