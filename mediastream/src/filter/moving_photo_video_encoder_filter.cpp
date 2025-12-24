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
 
#include "moving_photo_video_encoder_filter.h"
 
#include <iostream>
#include <memory>
#include <string>
#include "camera_log.h"
#include "meta.h"
#include "common/media_core.h"
#include "moving_photo_engine_context.h"
#include "cfilter.h"
#include "cfilter_factory.h"
#include "moving_photo_muxer_filter.h"


// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {

constexpr int32_t BUFFER_ENCODE_EXPIREATION_TIME = 10;
 
static AutoRegisterCFilter<MovingPhotoVideoEncoderFilter> g_registerMovingPhotoVideoEncoderFilter(
    "camera.moving_photo_video_encoder",
    CFilterType::MOVING_PHOTO_VIDEO_ENCODE,
    [](const std::string& name, const CFilterType type) {
        return std::make_shared<MovingPhotoVideoEncoderFilter>(name, CFilterType::MOVING_PHOTO_VIDEO_ENCODE);
    });
 
class MovingPhotoVideoEncoderFilterLinkCallback : public CFilterLinkCallback {
public:
    explicit MovingPhotoVideoEncoderFilterLinkCallback(
        std::shared_ptr<MovingPhotoVideoEncoderFilter> surfaceEncoderFilter)
        : surfaceEncoderFilter_(std::move(surfaceEncoderFilter))
    {
    }
 
    void OnLinkedResult(const sptr<AVBufferQueueProducer> &queue, std::shared_ptr<Meta> &meta) override
    {
        if (auto surfaceEncoderFilter = surfaceEncoderFilter_.lock()) {
            surfaceEncoderFilter->OnLinkedResult(queue, meta);
        } else {
            MEDIA_INFO_LOG("invalid surfaceEncoderFilter");
        }
    }
 
    void OnUnlinkedResult(std::shared_ptr<Meta> &meta) override
    {
        if (auto surfaceEncoderFilter = surfaceEncoderFilter_.lock()) {
            surfaceEncoderFilter->OnUnlinkedResult(meta);
        } else {
            MEDIA_INFO_LOG("invalid surfaceEncoderFilter");
        }
    }
 
    void OnUpdatedResult(std::shared_ptr<Meta> &meta) override
    {
        if (auto surfaceEncoderFilter = surfaceEncoderFilter_.lock()) {
            surfaceEncoderFilter->OnUpdatedResult(meta);
        } else {
            MEDIA_INFO_LOG("invalid surfaceEncoderFilter");
        }
    }
 
private:
    std::weak_ptr<MovingPhotoVideoEncoderFilter> surfaceEncoderFilter_;
};
 
class SurfaceEncoderAdapterCallback : public EncoderAdapterCallback {
public:
    explicit SurfaceEncoderAdapterCallback(std::shared_ptr<MovingPhotoVideoEncoderFilter> surfaceEncoderFilter)
        : surfaceEncoderFilter_(std::move(surfaceEncoderFilter))
    {
    }
 
    void OnError(MediaAVCodec::AVCodecErrorType type, int32_t errorCode)
    {
        if (auto surfaceEncoderFilter = surfaceEncoderFilter_.lock()) {
            surfaceEncoderFilter->OnError(type, errorCode);
        } else {
            MEDIA_DEBUG_LOG("invalid surfaceEncoderFilter");
        }
    }
 
    void OnOutputFormatChanged(const std::shared_ptr<Meta> &format)
    {
    }
 
private:
    std::weak_ptr<MovingPhotoVideoEncoderFilter> surfaceEncoderFilter_;
};
 
class SurfaceEncoderAdapterKeyFramePtsCallback : public EncoderAdapterKeyFramePtsCallback {
public:
    explicit SurfaceEncoderAdapterKeyFramePtsCallback(
        std::shared_ptr<MovingPhotoVideoEncoderFilter> surfaceEncoderFilter)
        : surfaceEncoderFilter_(std::move(surfaceEncoderFilter))
    {
    }
    
    void OnReportKeyFramePts(std::string KeyFramePts) override
    {
        if (auto surfaceEncoderFilter = surfaceEncoderFilter_.lock()) {
            MEDIA_DEBUG_LOG("SurfaceEncoderAdapterKeyFramePtsCallback OnReportKeyFramePts start");
            surfaceEncoderFilter->OnReportKeyFramePts(KeyFramePts);
            MEDIA_DEBUG_LOG("SurfaceEncoderAdapterKeyFramePtsCallback OnReportKeyFramePts end");
        } else {
            MEDIA_INFO_LOG("invalid surfaceEncoderFilter");
        }
    }

    void OnFirstFrameArrival(std::string name, int64_t& startPts) override {}

    void OnReportFirstFramePts(int64_t firstFramePts) override {}

private:
    std::weak_ptr<MovingPhotoVideoEncoderFilter> surfaceEncoderFilter_;
};

void MovingPhotoVideoEncoderFilter::RequestIFrameIfNeed(sptr<VideoBufferWrapper> videoBufferWrapper)
{
    CHECK_RETURN_ELOG(videoBufferWrapper == nullptr, "videoBufferWrapper is nullptr");
    if (videoBufferWrapper->GetTimestamp() - preBufferTimestamp_ > RECORDER_NANOSEC_RANGE) {
        ResetKeyFrameCount();
    } else {
        keyFrameInterval_ = (keyFrameInterval_ == 0 ? RECORDER_KEY_FRAME_INTERVAL : keyFrameInterval_);
    }
    preBufferTimestamp_ = videoBufferWrapper->GetTimestamp();
    MEDIA_DEBUG_LOG("EncodeSurfaceBuffer keyFrameInterval_: %{public}d", keyFrameInterval_);
    if (keyFrameInterval_ == RECORDER_KEY_FRAME_INTERVAL) {
        MEDIA_INFO_LOG("EncodeSurfaceBuffer request i frame");
        MediaAVCodec::Format format = MediaAVCodec::Format();
        format.PutIntValue(MediaDescriptionKey::MD_KEY_REQUEST_I_FRAME, true);
        SetParameter(format.GetMeta());
    }
}

bool MovingPhotoVideoEncoderFilter::EncodeSurfaceBuffer(sptr<VideoBufferWrapper> videoBufferWrapper)
{
    CHECK_RETURN_RET_ELOG(videoBufferWrapper == nullptr, false, "videoBufferWrapper is nullptr");
    RequestIFrameIfNeed(videoBufferWrapper);
    CHECK_RETURN_RET_ELOG(!videoBufferWrapper->Flush2Target(), false, "Flush2Target failed");
    keyFrameInterval_--;
    int32_t times = 10;
    while (times > 0) {
        times--;
        auto avbufferContext = GetAVBufferContext();
        CHECK_RETURN_RET_ELOG(avbufferContext == nullptr, false, "avbufferContext is nullptr");
        std::unique_lock<std::mutex> lock(avbufferContext->outputMutex_);
        bool condRet = avbufferContext->outputCond_.wait_for(
            lock, std::chrono::milliseconds(BUFFER_ENCODE_EXPIREATION_TIME),
            [avbufferContext]() { return !avbufferContext->outputBufferInfoQueue_.empty(); });
        CHECK_CONTINUE_WLOG(avbufferContext->outputBufferInfoQueue_.empty(),
            "Buffer queue is empty, continue, cond ret: %{public}d", condRet);
        sptr<AVBufferInfo> bufferInfo = avbufferContext->outputBufferInfoQueue_.front();
        CHECK_RETURN_RET_ELOG(bufferInfo->avBuffer_->memory_ == nullptr, false, "memory is alloced failed!");
        MEDIA_DEBUG_LOG("Out buffer count: %{public}u, size: %{public}d, flag: %{public}u, pts:%{public}" PRIu64 ", "
            "timestamp:%{public}" PRIu64, avbufferContext->outputFrameCount_, bufferInfo->avBuffer_->memory_->GetSize(),
            bufferInfo->avBuffer_->flag_, bufferInfo->avBuffer_->pts_, videoBufferWrapper->GetTimestamp());
        avbufferContext->outputBufferInfoQueue_.pop();
        avbufferContext->outputFrameCount_++;
        lock.unlock();
        std::lock_guard<std::mutex> encodeLock(encoderMutex_);
        if (bufferInfo->avBuffer_->flag_ == AVCODEC_BUFFER_FLAGS_CODEC_DATA) {
            std::shared_ptr<Media::AVBuffer> IDRBuffer = bufferInfo->GetCopyAVBuffer();
            videoBufferWrapper->SetEncodedBuffer(IDRBuffer);
            videoBufferWrapper->MarkIDRFrame();
            successFrame_ = false;
        } else if (bufferInfo->avBuffer_->flag_ == AVCODEC_BUFFER_FLAGS_SYNC_FRAME) {
            auto tempBuffer = bufferInfo->AddCopyAVBuffer(videoBufferWrapper->GetEncodedBuffer());
            CHECK_PRINT_ELOG(tempBuffer == nullptr, "EncodeSurfaceBuffer AddCopyAVBuffer failed");
            CHECK_EXECUTE(tempBuffer, videoBufferWrapper->SetEncodedBuffer(tempBuffer));
            successFrame_ = true;
        } else if (bufferInfo->avBuffer_->flag_ == AVCODEC_BUFFER_FLAGS_NONE) {
            std::shared_ptr<Media::AVBuffer> PBuffer = bufferInfo->GetCopyAVBuffer();
            videoBufferWrapper->SetEncodedBuffer(PBuffer);
            successFrame_ = true;
        } else {
            MEDIA_ERR_LOG("Flag is not acceptted number: %{public}u", bufferInfo->avBuffer_->flag_);
            Status ret = ReleaseOutputBuffer(bufferInfo->bufferIndex_);
            CHECK_BREAK_WLOG(ret != Status::OK, "ReleaseOutputBuffer failed");
            continue;
        }
        Status ret = ReleaseOutputBuffer(bufferInfo->bufferIndex_);
        CHECK_BREAK_WLOG(ret != Status::OK, "ReleaseOutputBuffer failed");
        CHECK_RETURN_RET(successFrame_, true);
    }
    return false;
}
 
void MovingPhotoVideoEncoderFilter::EncodeVideoBuffer(
    sptr<VideoBufferWrapper> videoBufferWrapper, EncodeCallback encodeCallback)
{
    if (!taskPtr_) {
        taskPtr_ = std::make_shared<Task>("VideoEncoder", groupId_, TaskType::VIDEO, TaskPriority::HIGH, false);
    }
 
    auto thisPtr = shared_from_this();
    taskPtr_->SubmitJobOnce([thisPtr, videoBufferWrapper, encodeCallback]{
        CAMERA_SYNC_TRACE;
        CHECK_RETURN_ELOG(videoBufferWrapper == nullptr, "videoBufferWrapper is nullptr");
        MEDIA_DEBUG_LOG("MovingPhotoVideoEncoderFilter::EncodeVideoBuffer buffer timestamp %{public}" PRId64,
            videoBufferWrapper->GetTimestamp());
        CHECK_RETURN_ELOG(thisPtr == nullptr, "thisPtr is nullptr");
        bool encodeResult = thisPtr->EncodeSurfaceBuffer(videoBufferWrapper);
        CHECK_PRINT_ELOG(!encodeResult, "MovingPhotoVideoEncoderFilter::EncodeVideoBuffer Failed");
        videoBufferWrapper->DetachBufferFromOutputSurface();
        videoBufferWrapper->SetEncodeResult(encodeResult);
        videoBufferWrapper->SetFinishEncode();
        if (encodeCallback) {
            encodeCallback(videoBufferWrapper, encodeResult);
        }
    });
}
 
MovingPhotoVideoEncoderFilter::MovingPhotoVideoEncoderFilter(std::string name, CFilterType type): CFilter(name, type)
{
    MEDIA_INFO_LOG("MovingPhotoVideoEncoderFilter create");
}
 
MovingPhotoVideoEncoderFilter::~MovingPhotoVideoEncoderFilter()
{
    MEDIA_INFO_LOG("MovingPhotoVideoEncoderFilter destroy");
}
 
void MovingPhotoVideoEncoderFilter::OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode)
{
    MEDIA_ERR_LOG("AVCodec error happened. ErrorType: %{public}d, errorCode: %{public}d",
        static_cast<int32_t>(errorType), errorCode);
}
 
Status MovingPhotoVideoEncoderFilter::SetCodecFormat(const std::shared_ptr<Meta> &format)
{
    MEDIA_INFO_LOG("SetCodecFormat");
    std::string codecMimeType;
    CHECK_RETURN_RET(!format->Get<Tag::MIME_TYPE>(codecMimeType), Status::ERROR_INVALID_PARAMETER);
    MEDIA_INFO_LOG("SetCodecFormat type = %{public}s", codecMimeType.c_str());
    if (strcmp(codecMimeType.c_str(), codecMimeType_.c_str()) != 0) {
        isUpdateCodecNeeded_ = true;
    }
    CHECK_RETURN_RET(!format->Get<Tag::MIME_TYPE>(codecMimeType_), Status::ERROR_INVALID_PARAMETER);
    return Status::OK;
}
 
void MovingPhotoVideoEncoderFilter::Init(const std::shared_ptr<CEventReceiver> &receiver,
    const std::shared_ptr<CFilterCallback> &callback)
{
    MEDIA_INFO_LOG("MovingPhotoVideoEncoderFilter::Init E");
    eventReceiver_ = receiver;
    filterCallback_ = callback;
    if (!mediaCodec_ || isUpdateCodecNeeded_.load()) {
        if (mediaCodec_) {
            mediaCodec_->Release();
        }
        mediaCodec_ = std::make_shared<VideoEncoderAdapter>();
        mediaCodec_->EnableMovingPhotoMode(true);
        mediaCodec_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
        Status ret = mediaCodec_->Init(codecMimeType_, true);
        if (ret == Status::OK) {
            std::shared_ptr<EncoderAdapterCallback> encoderAdapterCallback =
                std::make_shared<SurfaceEncoderAdapterCallback>(shared_from_this());
            mediaCodec_->SetEncoderAdapterCallback(encoderAdapterCallback);
            std::shared_ptr<EncoderAdapterKeyFramePtsCallback> encoderAdapterKeyFramePtsCallback =
                std::make_shared<SurfaceEncoderAdapterKeyFramePtsCallback>(shared_from_this());
            mediaCodec_->SetEncoderAdapterKeyFramePtsCallback(encoderAdapterKeyFramePtsCallback);
        } else if (eventReceiver_ != nullptr) {
            MEDIA_INFO_LOG("Init mediaCodec fail");
        }
        surface_ = nullptr;
        isUpdateCodecNeeded_ = false;
    }
}
 
Status MovingPhotoVideoEncoderFilter::Configure(const std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("Configure");
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_UNKNOWN);
    configureParameter_ = parameter;
    return mediaCodec_->Configure(parameter);
}
 
Status MovingPhotoVideoEncoderFilter::SetWatermark(std::shared_ptr<AVBuffer> &waterMarkBuffer)
{
    MEDIA_INFO_LOG("SetWatermark");
    CHECK_RETURN_RET_ELOG(mediaCodec_ == nullptr, Status::ERROR_UNKNOWN, "mediaCodec_ is nullptr");
    return mediaCodec_->SetWatermark(waterMarkBuffer);
}
 
Status MovingPhotoVideoEncoderFilter::SetStopTime()
{
    MEDIA_INFO_LOG("SetStopTime");
    CHECK_RETURN_RET_ELOG(mediaCodec_ == nullptr, Status::ERROR_UNKNOWN, "mediaCodec_ is nullptr");
    return mediaCodec_->SetStopTime();
}
 
sptr<AVBufferContext> MovingPhotoVideoEncoderFilter::GetAVBufferContext()
{
    CHECK_RETURN_RET(avbufferContext_, avbufferContext_);
    CHECK_RETURN_RET_ELOG(mediaCodec_ == nullptr, avbufferContext_, "mediaCodec_ is nullptr");
    avbufferContext_ = mediaCodec_->GetAVBufferContext();
    return avbufferContext_;
}
 
Status MovingPhotoVideoEncoderFilter::SetTransCoderMode()
{
    MEDIA_INFO_LOG("SetTransCoderMode");
    isTranscoderMode_ = true;
    mediaCodec_->SetTransCoderMode();
    return Status::OK;
}
 
sptr<Surface> MovingPhotoVideoEncoderFilter::GetInputSurface()
{
    MEDIA_INFO_LOG("GetInputSurface");
    CHECK_RETURN_RET(surface_, surface_);
    CHECK_EXECUTE(mediaCodec_, surface_ = mediaCodec_->GetInputSurface());
    return surface_;
}
 
Status MovingPhotoVideoEncoderFilter::DoPrepare()
{
    MEDIA_INFO_LOG("MovingPhotoVideoEncoderFilter::DoPrepare E");
    CHECK_RETURN_RET(filterCallback_ == nullptr, Status::ERROR_NULL_POINTER);
    filterCallback_->OnCallback(
        shared_from_this(), CFilterCallBackCommand::NEXT_FILTER_NEEDED, CStreamType::ENCODED_VIDEO);
    return Status::OK;
}
 
Status MovingPhotoVideoEncoderFilter::DoStart()
{
    MEDIA_INFO_LOG("MovingPhotoVideoEncoderFilter::DoStart E");
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_UNKNOWN);
    return mediaCodec_->Start();
}
 
Status MovingPhotoVideoEncoderFilter::ReleaseOutputBuffer(uint32_t index)
{
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_UNKNOWN);
    return mediaCodec_->ReleaseOutputBuffer(index);
}
 
Status MovingPhotoVideoEncoderFilter::DoPause()
{
    MEDIA_INFO_LOG("Pause");
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_UNKNOWN);
    return mediaCodec_->Pause();
}
 
Status MovingPhotoVideoEncoderFilter::DoResume()
{
    MEDIA_INFO_LOG("Resume");
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_UNKNOWN);
    return mediaCodec_->Resume();
}
 
Status MovingPhotoVideoEncoderFilter::DoStop()
{
    MEDIA_INFO_LOG("Stop enter");
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::OK);
    mediaCodec_->Stop();
    return Status::OK;
}
 
Status MovingPhotoVideoEncoderFilter::Reset()
{
    MEDIA_INFO_LOG("Reset");
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::OK);
    mediaCodec_->Reset();
    return Status::OK;
}
 
Status MovingPhotoVideoEncoderFilter::DoFlush()
{
    MEDIA_INFO_LOG("Flush");
    return mediaCodec_->Flush();
}
 
Status MovingPhotoVideoEncoderFilter::DoRelease()
{
    MEDIA_INFO_LOG("Release");
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::OK);
    return mediaCodec_->Reset();
}
 
Status MovingPhotoVideoEncoderFilter::NotifyEos(int64_t pts)
{
    MEDIA_INFO_LOG("NotifyEos");
    CHECK_RETURN_RET(mediaCodec_ == nullptr, Status::ERROR_UNKNOWN);
    return mediaCodec_->NotifyEos(pts);
}
 
void MovingPhotoVideoEncoderFilter::SetParameter(const std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("SetParameter");
    CHECK_RETURN(mediaCodec_ == nullptr);
    bool isEos = false;
    int64_t eosPts = UINT32_MAX;
    if (parameter->Find(Tag::MEDIA_END_OF_STREAM) != parameter->end() &&
        parameter->Get<Tag::MEDIA_END_OF_STREAM>(isEos) &&
        parameter->Get<Tag::USER_FRAME_PTS>(eosPts)) {
        if (isEos) {
            MEDIA_INFO_LOG("lastBuffer PTS: %{public} " PRId64, eosPts);
            NotifyEos(eosPts);
            return;
        }
    }
    mediaCodec_->SetParameter(parameter);
}
 
void MovingPhotoVideoEncoderFilter::GetParameter(std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("GetParameter");
}
 
Status MovingPhotoVideoEncoderFilter::LinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("MovingPhotoVideoEncoderFilter::LinkNext filterType:%{public}d",
        (int32_t)nextFilter->GetCFilterType());
    nextFilter_ = nextFilter;
    nextCFiltersMap_[outType].push_back(nextFilter_);
    std::shared_ptr<CFilterLinkCallback> filterLinkCallback =
        std::make_shared<MovingPhotoVideoEncoderFilterLinkCallback>(shared_from_this());
    nextFilter->OnLinked(outType, configureParameter_, filterLinkCallback);
    return Status::OK;
}
 
Status MovingPhotoVideoEncoderFilter::UpdateNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UpdateNext");
    return Status::OK;
}
 
Status MovingPhotoVideoEncoderFilter::UnLinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UnLinkNext");
    return Status::OK;
}
 
CFilterType MovingPhotoVideoEncoderFilter::GetFilterType()
{
    return filterType_;
}
 
Status MovingPhotoVideoEncoderFilter::OnLinked(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("MovingPhotoVideoEncoderFilter::OnLinked E");
    onLinkedResultCallback_ = callback;
    return Status::OK;
}
 
Status MovingPhotoVideoEncoderFilter::OnUpdated(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("OnUpdated");
    return Status::OK;
}
 
Status MovingPhotoVideoEncoderFilter::OnUnLinked(
    CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnUnLinked");
    return Status::OK;
}
 
void MovingPhotoVideoEncoderFilter::OnLinkedResult(const sptr<AVBufferQueueProducer> &outputBufferQueue,
    std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("MovingPhotoVideoEncoderFilter::OnLinkedResult E");
    CHECK_RETURN(mediaCodec_ == nullptr);
    mediaCodec_->SetOutputBufferQueue(outputBufferQueue);
    if (onLinkedResultCallback_) {
        onLinkedResultCallback_->OnLinkedResult(nullptr, meta);
    }
}
 
void MovingPhotoVideoEncoderFilter::OnUpdatedResult(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnUpdatedResult");
}
 
void MovingPhotoVideoEncoderFilter::OnUnlinkedResult(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnUnlinkedResult");
}
 
void MovingPhotoVideoEncoderFilter::SetCallingInfo(int32_t appUid, int32_t appPid,
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
 
void MovingPhotoVideoEncoderFilter::OnReportKeyFramePts(std::string KeyFramePts)
{

}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP