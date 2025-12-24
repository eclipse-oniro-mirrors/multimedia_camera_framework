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

#include <fcntl.h>

#include "cfilter.h"
#include "cfilter_factory.h"
#include "deferred_process.h"
#include "camera_log.h"
#include "format.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {
namespace {
    const std::string FILTER_NAME = "deferred.process.demuxer";
}

DeferredProcessCEventReceiver::DeferredProcessCEventReceiver(const std::weak_ptr<DeferredProcess>& process)
    : process_(process) {}

void DeferredProcessCEventReceiver::OnEvent(const Event& event)
{
    auto process = process_.lock();
    CHECK_RETURN_ELOG(process == nullptr, "DeferredProcess is nullptr");
    process->OnEvent(event);
}

DeferredProcessFilterCallback::DeferredProcessFilterCallback(const std::weak_ptr<DeferredProcess>& process)
    : process_(process) {}

Status DeferredProcessFilterCallback::OnCallback(const std::shared_ptr<CFilter>& filter,
    CFilterCallBackCommand cmd, CStreamType outType)
{
    auto process = process_.lock();
    CHECK_RETURN_RET_ELOG(process == nullptr, Status::ERROR_NULL_POINTER, "DeferredProcess is nullptr");
    return process->OnCallback(filter, cmd, outType);
}

void DeferredProcess::OnEvent(const Event &event)
{

}

Status DeferredProcess::OnCallback(const std::shared_ptr<CFilter>& filter,
    const CFilterCallBackCommand cmd, CStreamType outType)
{
    CHECK_RETURN_RET(cmd != CFilterCallBackCommand::NEXT_FILTER_NEEDED, Status::OK);
    MEDIA_INFO_LOG("OnCallback filterType: %{public}d, streamType: %{public}d", filter->GetCFilterType(), outType);
    switch (outType) {
            case CStreamType::RAW_AUDIO:
                return LinkSinkFilter(filter, outType);
            case CStreamType::ENCODED_AUDIO:
            case CStreamType::ENCODED_VIDEO:
            case CStreamType::ENCODED_METADATA:
                return LinkMuxerFilter(filter, outType);
            default:
                break;
        }
    return Status::OK;
}

int32_t DeferredProcess::Init()
{
    processId_ = std::string("DeferredProcess_") + std::to_string(Pipeline::GetNextPipelineId());
    processEventReceiver_ = std::make_shared<DeferredProcessCEventReceiver>(weak_from_this());
    processCallback_ = std::make_shared<DeferredProcessFilterCallback>(weak_from_this());
    pipeline_ = std::make_shared<Pipeline>();
    pipeline_->Init(processEventReceiver_, processCallback_, processId_);
    return static_cast<int32_t>(Status::NO_ERROR);
}

int32_t DeferredProcess::Prepare()
{
    AddDemuxerFilter();
    AddVideoFilter();
    AddMetaFilter();
    
    if (videoEncoderFilter_) {
        videoEncoderFilter_->SetCodecFormat(videoFormat_);
        videoEncoderFilter_->Init(processEventReceiver_, processCallback_);
        videoEncoderFilter_->Configure(videoFormat_);
    }
    if (metaDataFilter_) {
        metaDataFilter_->Init(processEventReceiver_, processCallback_);
        metaDataFilter_->Configure(metaDataFormat_);
    }
    auto ret = pipeline_->Prepare();
    CHECK_RETURN_RET_ELOG(ret != Status::OK, static_cast<int32_t>(ret), "Pipeline prepare failed.");
    OnStateChanged(StateId::READY);
    return static_cast<int32_t>(Status::NO_ERROR);
}

int32_t DeferredProcess::Start()
{
    MEDIA_INFO_LOG("Start enter.");
    Status ret = Status::OK;
    if (curState_ == StateId::PAUSE) {
        ret = pipeline_->Resume();
    } else {
        ret = pipeline_->Start();
    }
    CHECK_RETURN_RET_ELOG(ret != Status::OK, static_cast<int32_t>(ret), "Start fail");
    OnStateChanged(StateId::RECORDING);
    return static_cast<int32_t>(Status::NO_ERROR);
}

int32_t DeferredProcess::Pause()
{
    MEDIA_INFO_LOG("Pause enter.");
    Status ret = Status::OK;
    if (curState_ != StateId::READY) {
        ret = pipeline_->Pause();
        CHECK_RETURN_RET_ELOG(ret == Status::OK, static_cast<int32_t>(ret), "Pause fail");
    }
    OnStateChanged(StateId::PAUSE);
    return static_cast<int32_t>(Status::NO_ERROR);
}

int32_t DeferredProcess::Resume()
{
    MEDIA_INFO_LOG("Resume enter.");
    Status ret = Status::OK;
    ret = pipeline_->Resume();
    CHECK_RETURN_RET_ELOG(ret == Status::OK, static_cast<int32_t>(ret), "Resume fail");
    OnStateChanged(StateId::RECORDING);
    return static_cast<int32_t>(Status::NO_ERROR);
}

int32_t DeferredProcess::Stop()
{
    MEDIA_INFO_LOG("Stop enter.");
    CHECK_RETURN_RET_ILOG(
        curState_ == StateId::INIT, static_cast<int32_t>(Status::OK), "Stop exit.the reason is state = INIT");
    // real stop operations
    Status ret = HandleStopOperation();
    // clear all configurations and remove all filters
    RemoveFilter();
    CHECK_RETURN_RET_ELOG(curState_ != StateId::INIT, ERR_UNKNOWN_REASON, "stop fail");
    return static_cast<int32_t>(ret);
}

Status DeferredProcess::HandleStopOperation()
{
    Status ret = Status::OK;
    if (videoEncoderFilter_) {
        ret = videoEncoderFilter_->SetStopTime();
    }
    ret = pipeline_->Stop();
    CHECK_EXECUTE(ret == Status::OK, OnStateChanged(StateId::INIT));
    return ret;
}

int32_t DeferredProcess::Release()
{
    return static_cast<int32_t>(Status::NO_ERROR);
}

Status DeferredProcess::SetMediaSource(int32_t srcFd, int32_t outFd)
{
    fd_ = outFd;
    CHECK_RETURN_RET_ELOG(srcFd < 0, Status::ERROR_INVALID_DATA, "Input fd is negative");
    auto size = lseek(srcFd, 0, SEEK_END);
    CHECK_RETURN_RET_ELOG(size < 0, Status::ERROR_INVALID_DATA, "Input size must be greater than zero");
    int32_t flag = fcntl(srcFd, F_GETFL, 0);
    CHECK_RETURN_RET_ELOG(flag < 0, Status::ERROR_INVALID_DATA, "Get fd status failed");
    CHECK_RETURN_RET_ELOG(
        (static_cast<uint32_t>(flag) & static_cast<uint32_t>(O_WRONLY)) == static_cast<uint32_t>(O_WRONLY),
        Status::ERROR_INVALID_PARAMETER, "Fd is not permitted to read");
    CHECK_RETURN_RET_ELOG(lseek(srcFd, 0, SEEK_CUR) == -1, Status::ERROR_INVALID_DATA, "Fd unseekable");

    std::string uri = "fd://" + std::to_string(srcFd) + "?offset=" + \
        std::to_string(0) + "&size=" + std::to_string(size);
    auto mediaSource = std::make_shared<MediaSource>(uri);
    demuxerFilter_ = CFilterFactory::Instance().CreateCFilter<DemuxerFilter>("DeferredDemuxer",
        CFilterType::DEMUXER);
    CHECK_RETURN_RET_ELOG(demuxerFilter_ == nullptr, Status::ERROR_NULL_POINTER, "Create mediaDemuxer failed");

    pipeline_->AddHeadFilters({demuxerFilter_});
    demuxerFilter_->Init(processEventReceiver_, processCallback_);
    auto ret = demuxerFilter_->SetDataSource(mediaSource);
    muxerFormat_ = demuxerFilter_->GetGlobalMetaInfo();
    userMeta_ = demuxerFilter_->GetUserMetaInfo();
    for (const auto& trackMeta : demuxerFilter_->GetStreamMetaInfo()) {
        Plugins::MediaType trackType;
        trackMeta->Get<Tag::MEDIA_TYPE>(trackType);
        if (trackType == Plugins::MediaType::AUDIO) {
            audioFormat_ = trackMeta;
        } else if (trackType == Plugins::MediaType::VIDEO) {
            videoFormat_ = trackMeta;
        } else if (trackType == Plugins::MediaType::TIMEDMETA) {
            metaDataFormat_ = trackMeta;
        }
        Format format;
        format.SetMeta(trackMeta);
        MEDIA_INFO_LOG("PrepareTrack data: %{public}s", format.Stringify().c_str());
    }
    return ret;
}

Status DeferredProcess::AddDemuxerFilter()
{
    return Status::OK;
}

Status DeferredProcess::AddVideoFilter()
{
    videoEncoderFilter_ = CFilterFactory::Instance().CreateCFilter<VideoEncoderFilter>("DeferredVideoEncoder",
        CFilterType::VIDEO_ENC);
    CHECK_RETURN_RET_DLOG(videoEncoderFilter_ == nullptr, Status::ERROR_NULL_POINTER, "VideoEncoderFilter is nullptr.");
    CHECK_RETURN_RET_DLOG(pipeline_ == nullptr, Status::ERROR_NULL_POINTER, "Pipeline is nullptr.");
    pipeline_->AddHeadFilters({videoEncoderFilter_});
    return Status::OK;
}

Status DeferredProcess::AddMetaFilter()
{
    metaDataFilter_ = CFilterFactory::Instance().CreateCFilter<MetaDataFilter>("DeferredMetaData",
        CFilterType::TIMED_METADATA);
    CHECK_RETURN_RET_DLOG(metaDataFilter_ == nullptr, Status::ERROR_NULL_POINTER, "MetaDataFilter is nullptr.");
    CHECK_RETURN_RET_DLOG(pipeline_ == nullptr, Status::ERROR_NULL_POINTER, "Pipeline is nullptr.");
    pipeline_->AddHeadFilters({metaDataFilter_});
    return Status::OK;
}

Status DeferredProcess::LinkSinkFilter(const std::shared_ptr<CFilter>& filter, CStreamType outType)
{
    if (sinkFilter_ == nullptr) {
        sinkFilter_ = CFilterFactory::Instance().CreateCFilter<SinkFilter>("DeferredSink",
            CFilterType::DEFER_AUDIO_SOURCE);
        CHECK_RETURN_RET_DLOG(sinkFilter_ == nullptr, Status::ERROR_NULL_POINTER, "SinkFilter is nullptr.");
        sinkFilter_->Init(processEventReceiver_, processCallback_);
    }
    pipeline_->LinkFilters(filter, {sinkFilter_}, outType);
    return Status::OK;
}

Status DeferredProcess::LinkMuxerFilter(const std::shared_ptr<CFilter>& filter, CStreamType outType)
{
    if (muxerFilter_ == nullptr) {
        muxerFilter_ = CFilterFactory::Instance().CreateCFilter<MuxerFilter>("DeferredMuxer", CFilterType::MUXER);
        CHECK_RETURN_RET_DLOG(muxerFilter_ == nullptr, Status::ERROR_NULL_POINTER, "MuxerFilter is nullptr.");
        muxerFilter_->Init(processEventReceiver_, processCallback_);
        muxerFilter_->SetOutputParameter(getuid(), getprocpid(), fd_,
            static_cast<int32_t>(Plugins::OutputFormat::MPEG_4));
        muxerFilter_->SetParameter(muxerFormat_);
        muxerFilter_->SetUserMeta(userMeta_);
    }
    pipeline_->LinkFilters(filter, {muxerFilter_}, outType);
    return Status::OK;
}

void DeferredProcess::RemoveFilter()
{
    MEDIA_INFO_LOG("RemoveFilter is called");
    CHECK_EXECUTE(demuxerFilter_, pipeline_->RemoveHeadFilter(demuxerFilter_));
    CHECK_EXECUTE(videoEncoderFilter_, pipeline_->RemoveHeadFilter(videoEncoderFilter_));
    CHECK_EXECUTE(metaDataFilter_, pipeline_->RemoveHeadFilter(metaDataFilter_));
}

void DeferredProcess::OnStateChanged(StateId state)
{
    curState_ = state;
}

sptr<Surface> DeferredProcess::GetVideoSurface()
{
    if (videoEncoderFilter_) {
        videoSurface_ = videoEncoderFilter_->GetInputSurface();
    }
    return videoSurface_;
}

sptr<Surface> DeferredProcess::GetMetaSurface()
{
    if (metaDataFilter_) {
        metaSurface_ = metaDataFilter_->GetInputMetaSurface();
    }
    return metaSurface_;
}

bool DeferredProcess::IsVideoMime(const std::string& mime)
{
    return mime.find("video/") == 0;
}

bool DeferredProcess::IsAudioMime(const std::string& mime)
{
    return mime.find("audio/") == 0;
}

bool DeferredProcess::IsMetaMime(const std::string& mime)
{
    return mime.find("meta/") == 0;
}

void DeferredProcess::HandleAudioTrack()
{
    int32_t audioId;
    audioFormat_->Get<Tag::REGULAR_TRACK_ID>(audioId);
    int32_t videoId;
    videoFormat_->Get<Tag::REGULAR_TRACK_ID>(videoId);
    int32_t metaId;
    metaDataFormat_->Get<Tag::REGULAR_TRACK_ID>(metaId);
    MEDIA_ERR_LOG("---------- audioId: %{public}d, videoId: %{public}d, metaId: %{public}d,", audioId, videoId, metaId);
}
} // CameraStandard
} // OHOS
// LCOV_EXCL_STOP