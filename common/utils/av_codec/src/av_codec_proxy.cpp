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
#include "av_codec_proxy.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
typedef AVCodecIntf* (*CreateAVCodecIntf)();

AVCodecProxy::AVCodecProxy(std::shared_ptr<Dynamiclib> avcodecLib, std::shared_ptr<AVCodecIntf> avcodecIntf)
    : avcodecLib_(avcodecLib), avcodecIntf_(avcodecIntf)
{
    MEDIA_DEBUG_LOG("AVCodecProxy constructor");
    CHECK_RETURN_ELOG(avcodecLib_ == nullptr, "avcodecLib is nullptr");
    CHECK_RETURN_ELOG(avcodecIntf_ == nullptr, "avcodecIntf is nullptr");
}

AVCodecProxy::~AVCodecProxy()
{
    MEDIA_DEBUG_LOG("AVCodecProxy destructor");
}

void AVCodecProxy::Release()
{
    MEDIA_DEBUG_LOG("AVCodecProxy Release");
    CameraDynamicLoader::FreeDynamicLibDelayed(AV_CODEC_SO, LIB_DELAYED_UNLOAD_TIME);
    MEDIA_DEBUG_LOG("AVCodecProxy Release end");
}

std::shared_ptr<AVCodecProxy> AVCodecProxy::CreateAVCodecProxy()
{
    std::shared_ptr<Dynamiclib> dynamiclib = CameraDynamicLoader::GetDynamiclib(AV_CODEC_SO);
    CHECK_RETURN_RET_ELOG(dynamiclib == nullptr, nullptr, "Failed to load media library");
    CreateAVCodecIntf createAVCodecIntf =
        (CreateAVCodecIntf)dynamiclib->GetFunction("createAVCodecIntf");
    CHECK_RETURN_RET_ELOG(
        createAVCodecIntf == nullptr, nullptr, "Failed to get createAVCodecInf function");
    AVCodecIntf* avcodecIntf = createAVCodecIntf();
    CHECK_RETURN_RET_ELOG(
        avcodecIntf == nullptr, nullptr, "Failed to create AVCodecIntf instance");
    std::shared_ptr<AVCodecProxy> avcodecProxy =
        std::make_shared<AVCodecProxy>(dynamiclib, std::shared_ptr<AVCodecIntf>(avcodecIntf));
    return avcodecProxy;
}

int32_t AVCodecProxy::CreateAVMuxer(int32_t fd, OutputFormat format)
{
    MEDIA_DEBUG_LOG("CreateAVMuxer start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is nullptr");
    auto ret = avcodecIntf_->CreateAVMuxer(fd, format);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, AV_ERR_FAILED, "CreateAVMuxer failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("CreateAVMuxer success");
    return ret;
}

int32_t AVCodecProxy::CreateAVCodecVideoEncoder(const std::string& codecMime)
{
    MEDIA_DEBUG_LOG("CreateAVCodecVideoEncoder start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is nullptr");
    int32_t ret = avcodecIntf_->CreateAVCodecVideoEncoder(codecMime);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, AV_ERR_FAILED,
        "CreateAVCodecVideoEncoder failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("CreateAVCodecVideoEncoder success");
    return ret;
}

int32_t AVCodecProxy::AVMuxerSetParameter(const std::shared_ptr<Meta>& param)
{
    MEDIA_DEBUG_LOG("AVMuxerSetParameter start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    CHECK_RETURN_RET_ELOG(param == nullptr, AV_ERR_INVALID_VAL, "input param is nullptr!");
    int32_t ret = avcodecIntf_->AVMuxerSetParameter(param);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, AV_ERR_FAILED, "AVMuxerSetParameter failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVMuxerSetParameter end");
    return ret;
}

int32_t AVCodecProxy::AVMuxerSetUserMeta(const std::shared_ptr<Meta>& userMeta)
{
    MEDIA_DEBUG_LOG("AVMuxerSetUserMeta start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    CHECK_RETURN_RET_ELOG(userMeta == nullptr, AV_ERR_INVALID_VAL, "input userMeta is nullptr!");
    int32_t ret = avcodecIntf_->AVMuxerSetUserMeta(userMeta);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, AV_ERR_FAILED, "AVMuxerSetUserMeta failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVMuxerSetUserMeta end");
    return ret;
}

int32_t AVCodecProxy::AVMuxerAddTrack(int32_t& trackIndex, const std::shared_ptr<Meta>& trackDesc)
{
    MEDIA_DEBUG_LOG("AVMuxerAddTrack start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    CHECK_RETURN_RET_ELOG(trackDesc == nullptr, AV_ERR_INVALID_VAL, "input trackDesc is nullptr!");
    int32_t ret = avcodecIntf_->AVMuxerAddTrack(trackIndex, trackDesc);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, AV_ERR_FAILED, "AVMuxerAddTrack failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVMuxerAddTrack end");
    return ret;
}

int32_t AVCodecProxy::AVMuxerStart()
{
    MEDIA_DEBUG_LOG("AVMuxerStart start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    int32_t ret = avcodecIntf_->AVMuxerStart();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, AV_ERR_FAILED, "AVMuxerStart failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVMuxerStart end");
    return ret;
}

int32_t AVCodecProxy::AVMuxerWriteSample(uint32_t trackIndex, const std::shared_ptr<AVBuffer>& sample)
{
    MEDIA_DEBUG_LOG("AVMuxerWriteSampleBuffer start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    CHECK_RETURN_RET_ELOG(sample == nullptr, AV_ERR_INVALID_VAL, "input sample is nullptr!");
    int32_t ret = avcodecIntf_->AVMuxerWriteSample(trackIndex, sample);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, AV_ERR_FAILED, "AVMuxerWriteSample failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVMuxerWriteSampleBuffer end");
    return ret;
}

int32_t AVCodecProxy::AVMuxerStop()
{
    MEDIA_DEBUG_LOG("AVMuxerStop start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    int32_t ret = avcodecIntf_->AVMuxerStop();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, AV_ERR_FAILED, "AVMuxerStop failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVMuxerStop end");
    return ret;
}

int32_t AVCodecProxy::AVCodecVideoEncoderPrepare()
{
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderPrepare start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    int32_t ret = avcodecIntf_->AVCodecVideoEncoderPrepare();
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVCodecVideoEncoderPrepare failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderPrepare end");
    return ret;
}

int32_t AVCodecProxy::AVCodecVideoEncoderStart()
{
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderStart start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    int32_t ret = avcodecIntf_->AVCodecVideoEncoderStart();
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVCodecVideoEncoderStart failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderStart end");
    return ret;
}

int32_t AVCodecProxy::AVCodecVideoEncoderStop()
{
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderStop start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    int32_t ret = avcodecIntf_->AVCodecVideoEncoderStop();
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVCodecVideoEncoderStop failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderStop end");
    return ret;
}

int32_t AVCodecProxy::AVCodecVideoEncoderRelease()
{
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderRelease start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    int32_t ret = avcodecIntf_->AVCodecVideoEncoderRelease();
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVCodecVideoEncoderRelease failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderRelease end");
    return ret;
}

bool AVCodecProxy::IsVideoEncoderExisted()
{
    MEDIA_DEBUG_LOG("IsVideoEncoderExisted start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, false, "avcodecIntf_ is not created");
    bool isExisted = avcodecIntf_->IsVideoEncoderExisted();
    MEDIA_DEBUG_LOG("IsVideoEncoderExisted end");
    return isExisted;
}

sptr<Surface> AVCodecProxy::CreateInputSurface()
{
    MEDIA_DEBUG_LOG("CreateInputSurface start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, nullptr, "avcodecIntf_ is not created");
    sptr<Surface> surface = avcodecIntf_->CreateInputSurface();
    CHECK_RETURN_RET_ELOG(surface == nullptr, nullptr, "CreateInputSurface failed");
    MEDIA_DEBUG_LOG("CreateInputSurface end");
    return surface;
}

int32_t AVCodecProxy::QueueInputBuffer(uint32_t index)
{
    MEDIA_DEBUG_LOG("QueueInputBuffer start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    int32_t ret = avcodecIntf_->QueueInputBuffer(index);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, AV_ERR_FAILED, "QueueInputBuffer failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("QueueInputBuffer end");
    return ret;
}

int32_t AVCodecProxy::AVCodecVideoEncoderNotifyEos()
{
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderNotifyEos start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    int32_t ret = avcodecIntf_->AVCodecVideoEncoderNotifyEos();
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVCodecVideoEncoderNotifyEos failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderNotifyEos end");
    return ret;
}

int32_t AVCodecProxy::ReleaseOutputBuffer(uint32_t index)
{
    MEDIA_DEBUG_LOG("ReleaseOutputBuffer start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    int32_t ret = avcodecIntf_->ReleaseOutputBuffer(index);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, AV_ERR_FAILED, "ReleaseOutputBuffer failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("ReleaseOutputBuffer end");
    return ret;
}

int32_t AVCodecProxy::AVCodecVideoEncoderSetParameter(const Format& format)
{
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderSetParameter start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    int32_t ret = avcodecIntf_->AVCodecVideoEncoderSetParameter(format);
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVCodecVideoEncoderSetParameter failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderSetParameter end");
    return ret;
}

int32_t AVCodecProxy::AVCodecVideoEncoderSetCallback(const std::shared_ptr<MediaCodecCallback>& callback)
{
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderSetCallback start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    CHECK_RETURN_RET_ELOG(callback == nullptr, AV_ERR_INVALID_VAL, "input callback is nullptr!");
    int32_t ret = avcodecIntf_->AVCodecVideoEncoderSetCallback(callback);
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVCodecVideoEncoderSetCallback failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderSetCallback end");
    return ret;
}
int32_t AVCodecProxy::AVCodecVideoEncoderConfigure(const Format& format)
{
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderConfigure start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    int32_t ret = avcodecIntf_->AVCodecVideoEncoderConfigure(format);
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVCodecVideoEncoderConfigure failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVCodecVideoEncoderConfigure end");
    return ret;
}

void AVCodecProxy::CreateAVSource(int32_t fd, int64_t offset, int64_t size)
{
    MEDIA_DEBUG_LOG("CreateAVSource start");
    CHECK_RETURN_ELOG(avcodecIntf_ == nullptr, "avcodecIntf_ is nullptr");
    avcodecIntf_->CreateAVSource(fd, offset, size);
    MEDIA_DEBUG_LOG("CreateAVSource end");
}

int32_t AVCodecProxy::AVSourceGetSourceFormat(Format& format)
{
    MEDIA_DEBUG_LOG("AVSourceGetSourceFormat start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    int32_t ret = avcodecIntf_->AVSourceGetSourceFormat(format);
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVSourceGetSourceFormat failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVSourceGetSourceFormat end");
    return ret;
}

int32_t AVCodecProxy::AVSourceGetUserMeta(Format& format)
{
    MEDIA_DEBUG_LOG("AVSourceGetUserMeta start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    int32_t ret = avcodecIntf_->AVSourceGetUserMeta(format);
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVSourceGetUserMeta failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVSourceGetUserMeta end");
    return ret;
}

int32_t AVCodecProxy::AVSourceGetTrackFormat(Format& format, uint32_t trackIndex)
{
    MEDIA_DEBUG_LOG("AVSourceGetTrackFormat start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    int32_t ret = avcodecIntf_->AVSourceGetTrackFormat(format, trackIndex);
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVSourceGetTrackFormat failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVSourceGetTrackFormat end");
    return ret;
}

void AVCodecProxy::CreateAVDemuxer(std::shared_ptr<AVSource> source)
{
    MEDIA_DEBUG_LOG("CreateAVDemuxer start");
    CHECK_RETURN_ELOG(avcodecIntf_ == nullptr, "avcodecIntf_ is nullptr");
    avcodecIntf_->CreateAVDemuxer(source);
    MEDIA_DEBUG_LOG("CreateAVDemuxer end");
}

int32_t AVCodecProxy::ReadSampleBuffer(uint32_t trackIndex, std::shared_ptr<AVBuffer> sample)
{
    MEDIA_DEBUG_LOG("ReadSampleBuffer start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    CHECK_RETURN_RET_ELOG(sample == nullptr, AV_ERR_INVALID_VAL, "input sample is nullptr!");
    int32_t ret = avcodecIntf_->ReadSampleBuffer(trackIndex, sample);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, AV_ERR_FAILED, "ReadSampleBuffer failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("ReadSampleBuffer end");
    return ret;
}

int32_t AVCodecProxy::AVDemuxerSeekToTime(int64_t millisecond, SeekMode mode)
{
    MEDIA_DEBUG_LOG("AVDemuxerSeekToTime start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    int32_t ret = avcodecIntf_->AVDemuxerSeekToTime(millisecond, mode);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, AV_ERR_FAILED, "AVDemuxerSeekToTime failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVDemuxerSeekToTime end");
    return ret;
}

int32_t AVCodecProxy::AVDemuxerSelectTrackByID(uint32_t trackIndex)
{
    MEDIA_DEBUG_LOG("AVDemuxerSelectTrackByID start");
    CHECK_RETURN_RET_ELOG(avcodecIntf_ == nullptr, AV_ERR_INVALID_VAL, "avcodecIntf_ is not created");
    int32_t ret = avcodecIntf_->AVDemuxerSelectTrackByID(trackIndex);
    CHECK_RETURN_RET_ELOG(
        ret != AV_ERR_OK, AV_ERR_FAILED, "AVDemuxerSelectTrackByID failed, ret: %{public}d", ret);
    MEDIA_DEBUG_LOG("AVDemuxerSelectTrackByID end");
    return ret;
}
} // namespace CameraStandard
} // namespace OHOS