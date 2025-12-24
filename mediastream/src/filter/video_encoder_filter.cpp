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

#include "video_encoder_filter.h"

#include "camera_log.h"
#include "cfilter_factory.h"
#include "media_core.h"
#include "muxer_filter.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {
static AutoRegisterCFilter<VideoEncoderFilter> g_registerVideoEncoderFilter("camera.videoencoder",
    CFilterType::VIDEO_ENC,
    [](const std::string& name, const CFilterType type) {
        return std::make_shared<VideoEncoderFilter>(name, CFilterType::VIDEO_ENC);
    });

VideoEncoderFilter::VideoEncoderFilter(std::string name, CFilterType type)
    : CFilter(name, type), name_(name)
{
    MEDIA_DEBUG_LOG("entered.");
}

VideoEncoderFilter::~VideoEncoderFilter()
{
    MEDIA_INFO_LOG("entered.");
    if (mediaCodec_) {
        mediaCodec_->Release();
    }
    mediaCodec_ = nullptr;
}

void VideoEncoderFilter::OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode)
{
    MEDIA_ERR_LOG("AVCodec error happened. ErrorType: %{public}d, errorCode: %{public}d",
        static_cast<int32_t>(errorType), errorCode);
    if (eventReceiver_ != nullptr) {
        eventReceiver_->OnEvent({"video_encoder_filter", FilterEventType::EVENT_ERROR, MSERR_VID_ENC_FAILED});
    }
}

Status VideoEncoderFilter::SetCodecFormat(const std::shared_ptr<Meta> &format)
{
    MEDIA_INFO_LOG("SetCodecFormat");
    std::string codecMimeType;
    CHECK_RETURN_RET(!format->Get<Tag::MIME_TYPE>(codecMimeType), Status::ERROR_INVALID_PARAMETER);
    if (strcmp(codecMimeType.c_str(), codecMimeType_.c_str()) != 0) {
        isUpdateCodecNeeded_ = true;
    }
    CHECK_RETURN_RET(!format->Get<Tag::MIME_TYPE>(codecMimeType_), Status::ERROR_INVALID_PARAMETER);
    return Status::OK;
}

void VideoEncoderFilter::Init(const std::shared_ptr<CEventReceiver> &receiver,
    const std::shared_ptr<CFilterCallback> &callback)
{
    MEDIA_INFO_LOG("VideoEncoderFilter::Init %{public}s", codecMimeType_.c_str());
    eventReceiver_ = receiver;
    filterCallback_ = callback;
    if (!mediaCodec_ || isUpdateCodecNeeded_.load()) {
        if (mediaCodec_) {
            mediaCodec_->Release();
        }
        MEDIA_INFO_LOG("VideoEncoderFilter::Init create mediaCodec");
        mediaCodec_ = std::make_shared<VideoEncoderAdapter>(name_ + "_EncoderAdapter");
        mediaCodec_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
        Status ret = mediaCodec_->Init(codecMimeType_, true);
        if (ret == Status::OK) {
            std::shared_ptr<EncoderAdapterCallback> encoderAdapterCallback =
                std::make_shared<VideoEncoderFilterImplEncoderAdapterCallback>(shared_from_this());
            mediaCodec_->SetEncoderAdapterCallback(encoderAdapterCallback);
            std::shared_ptr<EncoderAdapterKeyFramePtsCallback> encoderAdapterKeyFramePtsCallback =
                std::make_shared<VideoEncoderFilterImplEncoderAdapterKeyFramePtsCallback>(shared_from_this());
            mediaCodec_->SetEncoderAdapterKeyFramePtsCallback(encoderAdapterKeyFramePtsCallback);
        } else if (eventReceiver_ != nullptr) {
            MEDIA_INFO_LOG("Init mediaCodec fail");
            eventReceiver_->OnEvent({"video_encoder_filter", FilterEventType::EVENT_ERROR, MSERR_UNKNOWN});
        }
        surface_ = nullptr;
        isUpdateCodecNeeded_ = false;
    }
}

Status VideoEncoderFilter::Configure(const std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("Configure");
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_UNKNOWN);
    configureParameter_ = parameter;
    return mediaCodec_->Configure(parameter);
}

Status VideoEncoderFilter::SetWatermark(std::shared_ptr<AVBuffer> &waterMarkBuffer)
{
    MEDIA_INFO_LOG("SetWatermark");
    CHECK_RETURN_RET_ELOG(mediaCodec_ == nullptr, Status::ERROR_UNKNOWN, "mediaCodec_ is nullptr");
    return mediaCodec_->SetWatermark(waterMarkBuffer);
}

Status VideoEncoderFilter::SetStopTime()
{
    MEDIA_INFO_LOG("SetStopTime");
    CHECK_RETURN_RET_ELOG(mediaCodec_ == nullptr, Status::ERROR_UNKNOWN, "mediaCodec_ is nullptr");
    return mediaCodec_->SetStopTime();
}

Status VideoEncoderFilter::SetTransCoderMode()
{
    MEDIA_INFO_LOG("SetTransCoderMode");
    isTranscoderMode_ = true;
    mediaCodec_->SetTransCoderMode();
    return Status::OK;
}

sptr<Surface> VideoEncoderFilter::GetInputSurface()
{
    MEDIA_INFO_LOG("GetInputSurface");
    CHECK_RETURN_RET(surface_, surface_);
    if (mediaCodec_ != nullptr) {
        surface_ = mediaCodec_->GetInputSurface();
    }
    return surface_;
}

Status VideoEncoderFilter::DoPrepare()
{
    CHECK_RETURN_RET(filterCallback_ == nullptr, Status::ERROR_NULL_POINTER);
    MEDIA_INFO_LOG("Prepare");
    if (isTranscoderMode_) {
        MEDIA_INFO_LOG("TranscoderMode");
        return filterCallback_->OnCallback(shared_from_this(), CFilterCallBackCommand::NEXT_FILTER_NEEDED,
            CStreamType::ENCODED_VIDEO);
    }
    filterCallback_->OnCallback(shared_from_this(), CFilterCallBackCommand::NEXT_FILTER_NEEDED,
        CStreamType::ENCODED_VIDEO);
    return Status::OK;
}

Status VideoEncoderFilter::DoStart()
{
    MEDIA_INFO_LOG("Start");
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_UNKNOWN);
    return mediaCodec_->Start();
}

Status VideoEncoderFilter::DoPause()
{
    MEDIA_INFO_LOG("Pause");
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_UNKNOWN);
    return mediaCodec_->Pause();
}

Status VideoEncoderFilter::DoResume()
{
    MEDIA_INFO_LOG("Resume");
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_UNKNOWN);
    return mediaCodec_->Resume();
}

Status VideoEncoderFilter::DoStop()
{
    MEDIA_INFO_LOG("Stop enter");
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::OK);
    mediaCodec_->Stop();
    if (onLinkedResultCallback_) {
        MEDIA_INFO_LOG("Stop image filter start");
        onLinkedResultCallback_->OnUpdatedResult(configureParameter_);
    }
    return Status::OK;
}

Status VideoEncoderFilter::Reset()
{
    MEDIA_INFO_LOG("Reset");
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::OK);
    mediaCodec_->Reset();
    return Status::OK;
}

Status VideoEncoderFilter::DoFlush()
{
    MEDIA_INFO_LOG("Flush");
    return mediaCodec_->Flush();
}

Status VideoEncoderFilter::DoRelease()
{
    MEDIA_INFO_LOG("Release");
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::OK);
    return mediaCodec_->Reset();
}

Status VideoEncoderFilter::NotifyEos(int64_t pts)
{
    MEDIA_INFO_LOG("NotifyEos");
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_UNKNOWN);
    return mediaCodec_->NotifyEos(pts);
}

void VideoEncoderFilter::SetParameter(const std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("SetParameter");
    CHECK_RETURN(mediaCodec_ == nullptr);
    bool isEos = false;
    int64_t eosPts = UINT32_MAX;
    if (parameter->Find(Tag::MEDIA_END_OF_STREAM) != parameter->end() &&
        parameter->Get<Tag::MEDIA_END_OF_STREAM>(isEos) &&
        parameter->Get<Tag::USER_FRAME_PTS>(eosPts)) {
        if (isEos) {
            MEDIA_INFO_LOG("lastBuffer PTS: %{public}" PRId64, eosPts);
            NotifyEos(eosPts);
            return;
        }
    }
    mediaCodec_->SetParameter(parameter);
}

void VideoEncoderFilter::GetParameter(std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("GetParameter");
}

Status VideoEncoderFilter::LinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("LinkNext");
    nextFilter_ = nextFilter;
    nextCFiltersMap_[outType].push_back(nextFilter_);
    std::shared_ptr<CFilterLinkCallback> filterLinkCallback =
        std::make_shared<VideoEncoderFilterLinkCallback>(shared_from_this());
    nextFilter->OnLinked(outType, configureParameter_, filterLinkCallback);
    return Status::OK;
}

Status VideoEncoderFilter::UpdateNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UpdateNext");
    return Status::OK;
}

Status VideoEncoderFilter::UnLinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UnLinkNext");
    return Status::OK;
}

CFilterType VideoEncoderFilter::GetFilterType()
{
    return filterType_;
}

Status VideoEncoderFilter::OnLinked(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("OnLinked");
    onLinkedResultCallback_ = callback;
    return Status::OK;
}

Status VideoEncoderFilter::OnUpdated(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("OnUpdated");
    return Status::OK;
}

Status VideoEncoderFilter::OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnUnLinked");
    return Status::OK;
}

void VideoEncoderFilter::OnLinkedResult(const sptr<AVBufferQueueProducer> &outputBufferQueue,
    std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnLinkedResult");
    CHECK_RETURN(mediaCodec_ == nullptr);
    mediaCodec_->SetOutputBufferQueue(outputBufferQueue);
    if (onLinkedResultCallback_) {
        onLinkedResultCallback_->OnLinkedResult(GetInputSurface()); // return surface to image effect filter
    }
}

void VideoEncoderFilter::OnUpdatedResult(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnUpdatedResult");
}

void VideoEncoderFilter::OnUnlinkedResult(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnUnlinkedResult");
}

void VideoEncoderFilter::SetCallingInfo(int32_t appUid, int32_t appPid,
    const std::string &bundleName, uint64_t instanceId)
{
    appUid_ = appUid;
    appPid_ = appPid;
    bundleName_ = bundleName;
    instanceId_ = instanceId;
    if (mediaCodec_) {
        mediaCodec_->SetCallingInfo(appUid, appPid, bundleName, instanceId);
    }
}

void VideoEncoderFilter::OnReportKeyFramePts(std::string KeyFramePts)
{
    MEDIA_INFO_LOG("OnReportKeyFramePts %{public}s enter", KeyFramePts.c_str());
    const std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    userMeta->SetData("com.openharmony.recorder.timestamp", KeyFramePts);
    std::shared_ptr<MuxerFilter> muxerFilter = std::static_pointer_cast<MuxerFilter>(nextFilter_);
    if (muxerFilter != nullptr) {
        muxerFilter->SetUserMeta(userMeta);
        MEDIA_INFO_LOG("SetUserMeta %{public}s", KeyFramePts.c_str());
    } else {
        MEDIA_ERR_LOG("muxerFilter is null");
    }
}

void VideoEncoderFilter::EnableVirtualAperture(bool isVirtualApertureEnabled)
{
    MEDIA_DEBUG_LOG("VideoEncoderFilter::EnableVirtualAperture is called, isVirtualApertureEnabled: %{public}d enter",
                    isVirtualApertureEnabled);
    if (mediaCodec_) {
        mediaCodec_->EnableVirtualAperture(isVirtualApertureEnabled);
    }
}

void VideoEncoderFilter::SetStreamStarted(bool isStreamStarted)
{
    MEDIA_DEBUG_LOG("VideoEncoderFilter::SetStreamStarted is called, isStreamStarted: %{public}d",
                    isStreamStarted);
    if (mediaCodec_) {
        mediaCodec_->SetStreamStarted(isStreamStarted);
    }
}

int64_t VideoEncoderFilter::GetStopTimestamp()
{
    int64_t ts = -1;
    if (mediaCodec_) {
        ts = mediaCodec_->GetStopTimestamp();
    }
    MEDIA_DEBUG_LOG("ts: %{public}" PRId64, ts);
    return ts;
}

void VideoEncoderFilter::GetMuxerFirstFrameTimestamp(int64_t& timestamp)
{
    std::shared_ptr<MuxerFilter> muxerFilter = std::static_pointer_cast<MuxerFilter>(nextFilter_);
    if (muxerFilter != nullptr) {
        muxerFilter->GetMuxerFirstFrameTimestamp(timestamp);
    } else {
        MEDIA_ERR_LOG("muxerFilter is null");
    }
}

void VideoEncoderFilter::SetMuxerFirstFrameTimestamp(int64_t timestamp)
{
    std::shared_ptr<MuxerFilter> muxerFilter = std::static_pointer_cast<MuxerFilter>(nextFilter_);
    if (muxerFilter != nullptr) {
        muxerFilter->SetMuxerFirstFrameTimestamp(timestamp);
    } else {
        MEDIA_ERR_LOG("muxerFilter is null");
    }
}

void VideoEncoderFilter::OnReportFirstFramePts(int64_t firstFramePts)
{
    CHECK_RETURN(eventReceiver_ == nullptr);
    MEDIA_INFO_LOG("OnReportFirstFramePts: %{public}" PRId64, firstFramePts);
    eventReceiver_->OnEvent({"video_encoder_filter", FilterEventType::EVENT_VIDEO_FIRST_FRAME, firstFramePts});
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP