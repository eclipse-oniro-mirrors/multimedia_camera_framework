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

#include "video_encoder_adapter.h"

#include "camera_log.h"
#include "media_description.h"
#include "media_types.h"
#include <cstdint>

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {
namespace {
    constexpr uint32_t TIME_OUT_MS = 1000;
    constexpr uint32_t NS_PER_US = 1000;
    constexpr int64_t SEC_TO_NS = 1000000000;
    constexpr uint32_t STOP_TIME_OUT_MS = 1000;
    // Codec wait timeout with no video frame received
    constexpr uint32_t AVCODEC_ERR_TIMEOUT_NO_FRAME_RECEIVED = 50001;
}
using namespace MediaAVCodec;

VideoEncoderAdapter::VideoEncoderAdapter()
{
    MEDIA_DEBUG_LOG("VideoEncoderAdapter::VideoEncoderAdapter constructor is called");
}

VideoEncoderAdapter::VideoEncoderAdapter(std::string name) : name_(name)
{
    MEDIA_DEBUG_LOG("VideoEncoderAdapter::VideoEncoderAdapter constructor with name is called");
}

VideoEncoderAdapter::~VideoEncoderAdapter()
{
    MEDIA_INFO_LOG("encoder adapter destroy");
    if (codecServer_) {
        codecServer_->Release();
    }
    codecServer_ = nullptr;
}

Status VideoEncoderAdapter::Init(const std::string &mime, bool isEncoder)
{
    MEDIA_INFO_LOG("Init mime: %{public}s", mime.c_str());
    codecMimeType_ = mime;
    Format format;
    std::shared_ptr<Media::Meta> callerInfo = std::make_shared<Media::Meta>();
    callerInfo->SetData(Media::Tag::AV_CODEC_FORWARD_CALLER_PID, appPid_);
    callerInfo->SetData(Media::Tag::AV_CODEC_FORWARD_CALLER_UID, appUid_);
    callerInfo->SetData(Media::Tag::AV_CODEC_FORWARD_CALLER_PROCESS_NAME, bundleName_);
    format.SetMeta(callerInfo);
    int32_t ret = VideoEncoderFactory::CreateByMime(mime, format, codecServer_);
    MEDIA_INFO_LOG("VideoEncoderAdapter::Init CreateByMime errorCode %{public}d", ret);
    if (!codecServer_) {
        MEDIA_DEBUG_LOG("Create codecServer failed");
        SetFaultEvent("VideoEncoderAdapter::Init Create codecServer failed", ret);
        return Status::ERROR_UNKNOWN;
    }
    if (!releaseBufferTask_) {
        releaseBufferTask_ = std::make_shared<Task>("VideoEncoderAdapter");
        releaseBufferTask_->RegisterJob([this] {
            ReleaseBuffer();
            return 0;
        });
    }
    return Status::OK;
}

void VideoEncoderAdapter::ConfigureGeneralFormat(Format &format, const std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("ConfigureGeneralFormat");
    if (meta->Find(Tag::VIDEO_WIDTH) != meta->end()) {
        int32_t videoWidth;
        meta->Get<Tag::VIDEO_WIDTH>(videoWidth);
        format.PutIntValue(MediaDescriptionKey::MD_KEY_WIDTH, videoWidth);
    }
    if (meta->Find(Tag::VIDEO_HEIGHT) != meta->end()) {
        int32_t videoHeight;
        meta->Get<Tag::VIDEO_HEIGHT>(videoHeight);
        format.PutIntValue(MediaDescriptionKey::MD_KEY_HEIGHT, videoHeight);
    }
    if (meta->Find(Tag::VIDEO_CAPTURE_RATE) != meta->end()) {
        double videoCaptureRate;
        meta->Get<Tag::VIDEO_CAPTURE_RATE>(videoCaptureRate);
        format.PutDoubleValue(MediaDescriptionKey::MD_KEY_CAPTURE_RATE, videoCaptureRate);
    }
    if (meta->Find(Tag::MEDIA_BITRATE) != meta->end()) {
        int64_t mediaBitrate;
        meta->Get<Tag::MEDIA_BITRATE>(mediaBitrate);
        format.PutLongValue(MediaDescriptionKey::MD_KEY_BITRATE, mediaBitrate);
    }
    if (meta->Find(Tag::VIDEO_FRAME_RATE) != meta->end()) {
        double videoFrameRate;
        meta->Get<Tag::VIDEO_FRAME_RATE>(videoFrameRate);
        videoFrameRate_ = static_cast<int32_t>(videoFrameRate);
        MEDIA_INFO_LOG("videoFrameRate_: %{public}d", videoFrameRate_);
        format.PutDoubleValue(MediaDescriptionKey::MD_KEY_FRAME_RATE, videoFrameRate);
    }
    if (meta->Find(Tag::MIME_TYPE) != meta->end()) {
        std::string mimeType;
        meta->Get<Tag::MIME_TYPE>(mimeType);
        format.PutStringValue(MediaDescriptionKey::MD_KEY_CODEC_MIME, mimeType);
    }
    if (meta->Find(Tag::VIDEO_H265_PROFILE) != meta->end()) {
        Plugins::HEVCProfile h265Profile;
        meta->Get<Tag::VIDEO_H265_PROFILE>(h265Profile);
        format.PutIntValue(MediaDescriptionKey::MD_KEY_PROFILE, h265Profile);
    }
}

void VideoEncoderAdapter::ConfigureEnableFormat(Format &format, const std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("ConfigureEnableFormat");
    if (meta->Find(Tag::VIDEO_ENCODER_ENABLE_WATERMARK) != meta->end()) {
        bool enableWatermark = false;
        meta->Get<Tag::VIDEO_ENCODER_ENABLE_WATERMARK>(enableWatermark);
        format.PutIntValue(Tag::VIDEO_ENCODER_ENABLE_WATERMARK, enableWatermark);
    }
}

Status VideoEncoderAdapter::Configure(const std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("Configure");
    CAMERA_SYNC_TRACE;
    Format format = Format();
    ConfigureGeneralFormat(format, meta);
    ConfigureAboutRGBA(format, meta);
    ConfigureAboutEnableTemporalScale(format, meta);
    ConfigureEnableFormat(format, meta);
    ConfigureAuxiliaryFormat(format, meta);
    ConfigureQualityFormat(format, meta);
    ConfigureBFrameFormat(format, meta);
    if (!codecServer_) {
        SetFaultEvent("VideoEncoderAdapter::Configure, CodecServer is null");
        return Status::ERROR_UNKNOWN;
    }
    int32_t ret = static_cast<int32_t>(Status::OK);
    if (!isTransCoderMode_) {
        std::shared_ptr<MediaCodecParameterWithAttrCallback> droppedFramesCallback =
        std::make_shared<DroppedFramesCallback>(shared_from_this());
        ret = codecServer_->SetCallback(droppedFramesCallback);
        if (ret != 0) {
            MEDIA_INFO_LOG("Set dropped Frames Callback failed");
            SetFaultEvent("DroppedFramesCallback::DroppedFramesCallback error", ret);
            return Status::ERROR_UNKNOWN;
        }
    }
    if (isTransCoderMode_) {
        format.PutIntValue(Tag::VIDEO_FRAME_RATE_ADAPTIVE_MODE, true);
    }
    ret = codecServer_->Configure(format);
    if (ret != 0) {
        SetFaultEvent("VideoEncoderAdapter::Configure error", ret);
    }
    return ret == 0 ? Status::OK : Status::ERROR_UNKNOWN;
}

Status VideoEncoderAdapter::SetWatermark(std::shared_ptr<AVBuffer> &waterMarkBuffer)
{
    MEDIA_INFO_LOG("SetWaterMark");
    if (!codecServer_) {
        MEDIA_INFO_LOG("CodecServer is null");
        SetFaultEvent("VideoEncoderAdapter::setWatermark, CodecServer is null");
        return Status::ERROR_UNKNOWN;
    }
    int ret = codecServer_->SetCustomBuffer(waterMarkBuffer);
    CHECK_RETURN_RET_ELOG(ret != 0, Status::ERROR_UNKNOWN, "SetCustomBuffer error");
    return Status::OK;
}

Status VideoEncoderAdapter::SetStopTime()
{
    GetCurrentTime(stopTime_);
    MEDIA_INFO_LOG("SetStopTime: %{public}" PRId64, stopTime_);
    return Status::OK;
}

Status VideoEncoderAdapter::SetOutputBufferQueue(const sptr<AVBufferQueueProducer> &bufferQueueProducer)
{
    MEDIA_INFO_LOG("SetOutputBufferQueue");
    outputBufferQueueProducer_ = bufferQueueProducer;
    return Status::OK;
}

Status VideoEncoderAdapter::SetEncoderAdapterCallback(
    const std::shared_ptr<EncoderAdapterCallback> &encoderAdapterCallback)
{
    MEDIA_INFO_LOG("SetEncoderAdapterCallback");
    std::shared_ptr<MediaCodecCallback> videoEncoderAdapterCallback =
        std::make_shared<VideoEncoderAdapterImplMediaCodecCallback>(shared_from_this());
    encoderAdapterCallback_ = encoderAdapterCallback;
    if (!codecServer_) {
        SetFaultEvent("VideoEncoderAdapter::SetEncoderAdapterCallback, CodecServer is null");
        return Status::ERROR_UNKNOWN;
    }
    int32_t ret = codecServer_->SetCallback(videoEncoderAdapterCallback);
    CHECK_RETURN_RET(ret == 0, Status::OK);
    SetFaultEvent("VideoEncoderAdapter::SetEncoderAdapterCallback error", ret);
    return Status::ERROR_UNKNOWN;
}

Status VideoEncoderAdapter::SetEncoderAdapterKeyFramePtsCallback(
    const std::shared_ptr<EncoderAdapterKeyFramePtsCallback> &encoderAdapterKeyFramePtsCallback)
{
    MEDIA_INFO_LOG("SetEncoderAdapterKeyFramePtsCallback");
    encoderAdapterKeyFramePtsCallback_ = encoderAdapterKeyFramePtsCallback;
    return Status::OK;
}

Status VideoEncoderAdapter::SetTransCoderMode()
{
    MEDIA_INFO_LOG("SetTransCoderMode");
    isTransCoderMode_ = true;
    return Status::OK;
}

sptr<Surface> VideoEncoderAdapter::GetInputSurface()
{
    CHECK_RETURN_RET_ELOG(codecServer_ == nullptr, nullptr, "codecServer_ is nullptr");
    return codecServer_->CreateInputSurface();
}

Status VideoEncoderAdapter::Start()
{
    MEDIA_INFO_LOG("Start");
    CAMERA_SYNC_TRACE;
    if (!codecServer_) {
        SetFaultEvent("VideoEncoderAdapter::Start, CodecServer is null");
        return Status::ERROR_UNKNOWN;
    }
    int32_t ret;
    isThreadExit_ = false;
    hasReceivedEOS_ = false;
    if (releaseBufferTask_) {
        releaseBufferTask_->Start();
    }
    ret = codecServer_->Start();
    isStart_ = true;
    isStartKeyFramePts_ = true;
    if (ret == 0) {
        curState_ = ProcessStateCode::RECORDING;
        return Status::OK;
    } else {
        SetFaultEvent("VideoEncoderAdapter::Start error", ret);
        curState_ = ProcessStateCode::ERROR;
        return Status::ERROR_UNKNOWN;
    }
}

Status VideoEncoderAdapter::Stop()
{
    MEDIA_INFO_LOG("Stop");
    CAMERA_SYNC_TRACE;
    if (stopTime_ < 0) {
        GetCurrentTime(stopTime_);
    }
    isStopKeyFramePts_ = true;
    MEDIA_INFO_LOG("Stop time: %{public}" PRId64, stopTime_);
    // operate stop when it is paused state.
    if (curState_ == ProcessStateCode::PAUSED && !isTransCoderMode_) {
        stopTime_ = pauseTime_;
        // current frame is not the last frame before the pasue time, wait for stop
        if (currentKeyFramePts_ <= pauseTime_ - (SEC_TO_NS / videoFrameRate_)) {
            MEDIA_DEBUG_LOG("paused state -> stop, wait for stop.");
            HandleWaitforStop();
        }
        // else stop directly
        AddStopPts();
    }
    // operate stop when it is recording state.
    if (curState_ == ProcessStateCode::RECORDING && !isTransCoderMode_
        && !isMovingPhotoMode_ && isStreamStarted_) {
        MEDIA_DEBUG_LOG("recording state -> stop, wait for stop.");
        HandleWaitforStop();
        AddStopPts();
    }

    if (releaseBufferTask_) {
        {
            std::lock_guard<std::mutex> lock(releaseBufferMutex_);
            isThreadExit_ = true;
        }
        releaseBufferCondition_.notify_all();
        releaseBufferTask_->Stop();
        MEDIA_INFO_LOG("releaseBufferTask_ Stop");
    }
    CHECK_RETURN_RET(!codecServer_, Status::OK);
    int32_t ret = codecServer_->Stop();
    MEDIA_INFO_LOG("codecServer_ Stop");
    isStart_ = false;
    if (ret == 0) {
        curState_ = ProcessStateCode::STOPPED;
        return Status::OK;
    } else {
        SetFaultEvent("VideoEncoderAdapter::Stop error", ret);
        curState_ = ProcessStateCode::ERROR;
        return Status::ERROR_UNKNOWN;
    }
}

Status VideoEncoderAdapter::Pause()
{
    MEDIA_INFO_LOG("Pause");
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET(isTransCoderMode_, Status::OK);
    std::lock_guard<std::mutex> lock(checkFramesMutex_);
    GetCurrentTime(pauseTime_);
    CHECK_RETURN_RET_ELOG(pauseTime_ <= 0, Status::ERROR_UNKNOWN, "GetCurrentTime pauseTime_ <= 0");
    MEDIA_INFO_LOG("Pause time: %{public}" PRId64, pauseTime_);
    if (pauseResumeQueue_.empty() ||
        (pauseResumeQueue_.back().second == StateCode::RESUME && pauseResumeQueue_.back().first <= pauseTime_)) {
        pauseResumeQueue_.push_back({pauseTime_, StateCode::PAUSE});
        pauseResumeQueue_.push_back({std::numeric_limits<int64_t>::max(), StateCode::RESUME});
        pauseResumePts_.push_back({pauseTime_, StateCode::PAUSE});
        pauseResumePts_.push_back({std::numeric_limits<int64_t>::max(), StateCode::RESUME});
    }
    curState_ = ProcessStateCode::PAUSED;
    return Status::OK;
}

Status VideoEncoderAdapter::Resume()
{
    MEDIA_INFO_LOG("Resume");
    CAMERA_SYNC_TRACE;
    if (isTransCoderMode_) {
        isResume_ = true;
        return Status::OK;
    }
    std::lock_guard<std::mutex> lock(checkFramesMutex_);
    GetCurrentTime(resumeTime_);
    CHECK_RETURN_RET_ILOG(resumeTime_ <= 0, Status::ERROR_UNKNOWN, "GetCurrentTime resumeTime_ <= 0");
    MEDIA_INFO_LOG("resume time: %{public}" PRId64, resumeTime_);
    if (pauseResumeQueue_.empty()) {
        MEDIA_INFO_LOG("Status Error, no pause before resume");
        return Status::ERROR_UNKNOWN;
    }
    if (pauseResumeQueue_.back().second == StateCode::RESUME) {
        pauseResumeQueue_.back().first = std::min(resumeTime_, pauseResumeQueue_.back().first);
        pauseResumePts_.back().first = std::min(resumeTime_, pauseResumePts_.back().first);
    }
    if (pauseTime_ != -1) {
        totalPauseTime_ = totalPauseTime_ + resumeTime_ - pauseTime_;
        MEDIA_INFO_LOG("total pause time: %{public}" PRId64, totalPauseTime_);
        // total pause time (without checkFramesPauseTime)
        totalPauseTimeQueue_.push_back(totalPauseTime_);
    }
    curState_ = ProcessStateCode::RECORDING;
    pauseTime_ = -1;
    resumeTime_ = -1;
    return Status::OK;
}

Status VideoEncoderAdapter::Flush()
{
    MEDIA_INFO_LOG("Flush");
    if (!codecServer_) {
        SetFaultEvent("VideoEncoderAdapter::Flush, CodecServer is null");
        return Status::ERROR_UNKNOWN;
    }
    int32_t ret = codecServer_->Flush();
    if (ret != 0) {
        SetFaultEvent("VideoEncoderAdapter::Flush error", ret);
        curState_ = ProcessStateCode::ERROR;
        return Status::ERROR_UNKNOWN;
    }
    return Status::OK;
}

Status VideoEncoderAdapter::Reset()
{
    MEDIA_INFO_LOG("Reset");
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET(!codecServer_, Status::OK);
    int32_t ret = codecServer_->Reset();
    startBufferTime_ = -1;
    stopTime_ = -1;
    pauseTime_ = -1;
    resumeTime_ = -1;
    totalPauseTime_ = 0;
    isStart_ = false;
    isStartKeyFramePts_ = false;
    pauseResumeQueue_.clear();
    pauseResumePts_.clear();
    if (ret == 0) {
        curState_ = ProcessStateCode::IDLE;
        return Status::OK;
    } else {
        SetFaultEvent("VideoEncoderAdapter::Reset error", ret);
        curState_ = ProcessStateCode::ERROR;
        return Status::ERROR_UNKNOWN;
    }
}

Status VideoEncoderAdapter::Release()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("VideoEncoderAdapter::Release is called");
    CHECK_RETURN_RET(!codecServer_, Status::OK);
    int32_t ret = codecServer_->Release();
    if (ret != 0) {
        SetFaultEvent("VideoEncoderAdapter::Release error", ret);
        return Status::ERROR_UNKNOWN;
    }
    return Status::OK;
}

Status VideoEncoderAdapter::NotifyEos(int64_t pts)
{
    MEDIA_INFO_LOG("NotifyEos");
    if (!codecServer_) {
        SetFaultEvent("VideoEncoderAdapter::NotifyEos, CodecServer is null");
        return Status::ERROR_UNKNOWN;
    }
    int32_t ret = 0;
    MEDIA_INFO_LOG("lastBuffer PTS: %{public}" PRId64 " current PTS: %{public}" PRId64, pts, currentPts_.load());
    eosPts_ = pts;
    if (!isTransCoderMode_ || currentPts_.load() >= eosPts_.load()) {
        MEDIA_INFO_LOG("Notify encoder eos");
        ret = codecServer_->NotifyEos();
    }
    if (ret != 0) {
        SetFaultEvent("VideoEncoderAdapter::NotifyEos error", ret);
        return Status::ERROR_UNKNOWN;
    }
    return Status::OK;
}

Status VideoEncoderAdapter::SetParameter(const std::shared_ptr<Meta> &parameter)
{
    MEDIA_INFO_LOG("SetParameter");
    CAMERA_SYNC_TRACE;
    if (!codecServer_) {
        SetFaultEvent("VideoEncoderAdapter::SetParameter, CodecServer is null");
        return Status::ERROR_UNKNOWN;
    }
    Format format = Format();

    bool isRequestIFrame = false;
    parameter->GetData(Tag::VIDEO_REQUEST_I_FRAME, isRequestIFrame);
    if (isRequestIFrame) {
        MEDIA_INFO_LOG("VideoEncoderAdapter::SetParameter request i-frame");
        format.PutIntValue(MediaDescriptionKey::MD_KEY_REQUEST_I_FRAME, true);
    }

    int32_t ret = codecServer_->SetParameter(format);
    if (ret != 0) {
        SetFaultEvent("VideoEncoderAdapter::SetParameter error", ret);
        return Status::ERROR_UNKNOWN;
    }
    return Status::OK;
}

std::shared_ptr<Meta> VideoEncoderAdapter::GetOutputFormat()
{
    MEDIA_INFO_LOG("GetOutputFormat is not supported");
    return nullptr;
}

void VideoEncoderAdapter::TransCoderOnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    if (buffer->pts_ >= eosPts_.load() && codecServer_) {
        MEDIA_INFO_LOG("Notify encoder eos");
        codecServer_->NotifyEos();
    }
    int32_t size = buffer->memory_->GetSize();
    std::shared_ptr<AVBuffer> emptyOutputBuffer;
    AVBufferConfig avBufferConfig;
    avBufferConfig.size = size;
    avBufferConfig.memoryType = MemoryType::SHARED_MEMORY;
    avBufferConfig.memoryFlag = MemoryFlag::MEMORY_READ_WRITE;
    Status status = outputBufferQueueProducer_->RequestBuffer(emptyOutputBuffer, avBufferConfig, TIME_OUT_MS);
    CHECK_RETURN_ILOG(status != Status::OK, "RequestBuffer fail.");
    CHECK_RETURN_ILOG(emptyOutputBuffer == nullptr, "emptyOutputBuffer is nullptr");
    std::shared_ptr<AVMemory> &bufferMem = emptyOutputBuffer->memory_;
    CHECK_RETURN_ILOG(emptyOutputBuffer->memory_ == nullptr, "emptyOutputBuffer->memory_ is nullptr");
    bufferMem->Write(buffer->memory_->GetAddr(), size, 0);
    *(emptyOutputBuffer->meta_) = *(buffer->meta_);
    emptyOutputBuffer->pts_ = buffer->pts_;
    emptyOutputBuffer->flag_ = buffer->flag_;
    outputBufferQueueProducer_->PushBuffer(emptyOutputBuffer, true);
    {
        std::lock_guard<std::mutex> lock(releaseBufferMutex_);
        indexs_.push_back(index);
    }
    releaseBufferCondition_.notify_all();
    MEDIA_DEBUG_LOG("OnOutputBufferAvailable end");
}

void VideoEncoderAdapter::OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    int32_t size = buffer->memory_ ? buffer->memory_->GetSize() : -1;
    MEDIA_INFO_LOG("buffer received from codec, filterName: %{public}s, pts: %{public}" PRId64 ", id:%{public}" PRIu64
                   ", size:%{public}d, flag:%{public}u",
        name_.c_str(), buffer->pts_, buffer->GetUniqueId(), size, buffer->flag_);
    currentPts_ = currentPts_.load() < buffer->pts_? buffer->pts_ : currentPts_.load();
    CAMERA_SYNC_TRACE;
    if (isMovingPhotoMode_) {
        MovingPhotoOnOutputBufferAvailable(index, buffer);
        return;
    }

    if (isTransCoderMode_) {
        TransCoderOnOutputBufferAvailable(index, buffer);
        return;
    }
    if (isVirtualApertureEnabled_) {
        CHECK_RETURN_ELOG(buffer->memory_ == nullptr, "buffer->memory_ is nullptr, OnOutputBufferAvailable fail");
        int32_t size = buffer->memory_->GetSize();
        std::shared_ptr<AVBuffer> outputBuffer;
        AVBufferConfig avBufferConfig;
        avBufferConfig.size = size;
        avBufferConfig.memoryType = MemoryType::SHARED_MEMORY;
        avBufferConfig.memoryFlag = MemoryFlag::MEMORY_READ_WRITE;
        Status status = outputBufferQueueProducer_->RequestBuffer(outputBuffer, avBufferConfig, TIME_OUT_MS);
        CHECK_RETURN_ELOG(status != Status::OK, "RequestBuffer fail.");
        CHECK_RETURN_ELOG(outputBuffer == nullptr, "outputBuffer is nullptr.");
        std::shared_ptr<AVMemory>& bufferMem = outputBuffer->memory_;
        CHECK_RETURN_ELOG(outputBuffer->memory_ == nullptr, "outputBuffer->memory_ is nullptr");
        if (size <= 0) {
            bufferMem->Reset();
        } else {
            bufferMem->Write(buffer->memory_->GetAddr(), size, 0);
        }
        *(outputBuffer->meta_) = *(buffer->meta_);
        outputBuffer->pts_ = buffer->pts_ / NS_PER_US;
        outputBuffer->flag_ = buffer->flag_;
        outputBufferQueueProducer_->PushBuffer(outputBuffer, true);
        MEDIA_INFO_LOG("buffer pushed to muxer, filterName: %{public}s, pts: %{public}" PRId64 ", id:%{public}" PRIu64
                       ", size:%{public}d, flag:%{public}u",
            name_.c_str(), outputBuffer->pts_, outputBuffer->GetUniqueId(), outputBuffer->memory_->GetSize(),
            outputBuffer->flag_);
    }
    {
        std::lock_guard<std::mutex> lock(releaseBufferMutex_);
        indexs_.push_back(index);
    }
    releaseBufferCondition_.notify_all();
    if (buffer->flag_ == AVCODEC_BUFFER_FLAG_EOS) {
        MEDIA_INFO_LOG("EOS received, ready to stop.");
        hasReceivedEOS_ = true;
        std::unique_lock<std::mutex> lock(stopMutex_);
        stopCondition_.notify_all();
    }
}

void VideoEncoderAdapter::ReleaseBuffer()
{
    MEDIA_INFO_LOG("ReleaseBuffer");
    while (true) {
        CHECK_BREAK_ILOG(isThreadExit_, "Exit ReleaseBuffer thread.");
        std::vector<uint32_t> indexs;
        {
            std::unique_lock<std::mutex> lock(releaseBufferMutex_);
            releaseBufferCondition_.wait(lock, [this] {
                return isThreadExit_ || !indexs_.empty();
            });
            indexs = indexs_;
            indexs_.clear();
        }
        for (auto &index : indexs) {
            codecServer_->ReleaseOutputBuffer(index);
        }
    }
    MEDIA_INFO_LOG("ReleaseBuffer end");
}

void VideoEncoderAdapter::ConfigureAboutRGBA(Format &format, const std::shared_ptr<Meta> &meta)
{
    Plugins::VideoPixelFormat pixelFormat = Plugins::VideoPixelFormat::NV12;
    if (meta->Find(Tag::VIDEO_PIXEL_FORMAT) != meta->end()) {
        meta->Get<Tag::VIDEO_PIXEL_FORMAT>(pixelFormat);
    }
    format.PutIntValue(MediaDescriptionKey::MD_KEY_PIXEL_FORMAT, static_cast<int32_t>(pixelFormat));

    if (meta->Find(Tag::VIDEO_ENCODE_BITRATE_MODE) != meta->end()) {
        Plugins::VideoEncodeBitrateMode videoEncodeBitrateMode;
        meta->Get<Tag::VIDEO_ENCODE_BITRATE_MODE>(videoEncodeBitrateMode);
        format.PutIntValue(MediaDescriptionKey::MD_KEY_VIDEO_ENCODE_BITRATE_MODE, videoEncodeBitrateMode);
    }
}

void VideoEncoderAdapter::ConfigureAboutEnableTemporalScale(Format &format,
    const std::shared_ptr<Meta> &meta)
{
    if (meta->Find(Tag::VIDEO_ENCODER_ENABLE_TEMPORAL_SCALABILITY) != meta->end()) {
        bool enableTemporalScale;
        meta->Get<Tag::VIDEO_ENCODER_ENABLE_TEMPORAL_SCALABILITY>(enableTemporalScale);
        CHECK_RETURN_ILOG(!enableTemporalScale, "video encoder enableTemporalScale is false!");

        bool isSupported = true;
        if (isSupported) {
            MEDIA_INFO_LOG("VIDEO_ENCODER_TEMPORAL_SCALABILITY is supported!");
            format.PutIntValue(MediaDescriptionKey::OH_MD_KEY_VIDEO_ENCODER_ENABLE_TEMPORAL_SCALABILITY,
                1);
        } else {
            MEDIA_INFO_LOG("VIDEO_ENCODER_TEMPORAL_SCALABILITY is not supported!");
        }
    }
}

void VideoEncoderAdapter::ConfigureAuxiliaryFormat(Format &format, const std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("ConfigureAuxiliaryFormat");
    if (meta->Find(Tag::MEDIA_TYPE) != meta->end()) {
        Plugins::MediaType mediaType;
        meta->Get<Tag::MEDIA_TYPE>(mediaType);
        format.PutIntValue(MediaDescriptionKey::MD_KEY_TRACK_TYPE, static_cast<int32_t>(mediaType));
    }
    if (meta->Find(Tag::TRACK_REFERENCE_TYPE) != meta->end()) {
        std::string trackRefType;
        meta->Get<Tag::TRACK_REFERENCE_TYPE>(trackRefType);
        format.PutStringValue(MediaDescriptionKey::MD_KEY_TRACK_REFERENCE_TYPE, trackRefType);
    }
    if (meta->Find(Tag::TRACK_DESCRIPTION) != meta->end()) {
        std::string trackDesciption;
        meta->Get<Tag::TRACK_DESCRIPTION>(trackDesciption);
        format.PutStringValue(MediaDescriptionKey::MD_KEY_TRACK_DESCRIPTION, trackDesciption);
    }
    if (meta->Find(Tag::REFERENCE_TRACK_IDS) != meta->end()) {
        std::vector<int32_t> refTrackIds;
        meta->Get<Tag::REFERENCE_TRACK_IDS>(refTrackIds);
        format.PutIntBuffer(MediaDescriptionKey::MD_KEY_REFERENCE_TRACK_IDS, refTrackIds.data(), refTrackIds.size());
    }
}

void VideoEncoderAdapter::ConfigureQualityFormat(Format &format, const std::shared_ptr<Meta> &meta)
{
    if (meta->Find(Tag::VIDEO_ENCODE_QUALITY) != meta->end()) {
        int32_t encodeQuality;
        meta->Get<Tag::VIDEO_ENCODE_QUALITY>(encodeQuality);
        format.PutIntValue(MediaDescriptionKey::MD_KEY_QUALITY, encodeQuality);
    }
    if (meta->Find(Tag::VIDEO_ENCODER_QP_MIN) != meta->end()) {
        int32_t qpMin;
        meta->Get<Tag::VIDEO_ENCODER_QP_MIN>(qpMin);
        format.PutIntValue("video_encoder_qp_min", qpMin);
    }
    if (meta->Find(Tag::VIDEO_ENCODER_QP_MAX) != meta->end()) {
        int32_t qpMax;
        meta->Get<Tag::VIDEO_ENCODER_QP_MAX>(qpMax);
        format.PutIntValue("video_encoder_qp_max", qpMax);
    }
}

void VideoEncoderAdapter::ConfigureBFrameFormat(MediaAVCodec::Format& format, const std::shared_ptr<Meta>& meta)
{
    MEDIA_INFO_LOG("ConfigureBFrameFormat");
    if (meta->Find(Tag::VIDEO_ENCODER_ENABLE_B_FRAME) != meta->end()) {
        bool enableBFrame;
        meta->GetData(Tag::VIDEO_ENCODER_ENABLE_B_FRAME, enableBFrame);
        if (enableBFrame) {
            format.PutIntValue(Tag::VIDEO_ENCODER_ENABLE_B_FRAME, enableBFrame);
            format.PutIntValue(Tag::VIDEO_ENCODE_B_FRAME_GOP_MODE,
                Plugins::VideoEncodeBFrameGopMode::VIDEO_ENCODE_GOP_ADAPTIVE_B_MODE);
        }
    }
}

void VideoEncoderAdapter::SetFaultEvent(const std::string &errMsg, int32_t ret)
{
    SetFaultEvent(errMsg + ", ret = " + std::to_string(ret));
}

void VideoEncoderAdapter::SetFaultEvent(const std::string &errMsg)
{
    MEDIA_ERR_LOG("VideoEncoderAdapter::SetFaultEvent is called, %{public}s", errMsg.c_str());
}

void VideoEncoderAdapter::SetCallingInfo(int32_t appUid, int32_t appPid,
    const std::string &bundleName, uint64_t instanceId)
{
    appUid_ = appUid;
    appPid_ = appPid;
    instanceId_ = instanceId;
    bundleName_ = bundleName;
}

void VideoEncoderAdapter::OnInputParameterWithAttrAvailable(uint32_t index, std::shared_ptr<Format> &attribute,
    std::shared_ptr<Format> &parameter)
{
    if (isTransCoderMode_) {
        MEDIA_DEBUG_LOG("isTransCoderMode");
        parameter->PutIntValue(Tag::VIDEO_ENCODER_PER_FRAME_DISCARD, false);
        CHECK_RETURN_ELOG(!codecServer_, "codecServer_ is null");
        codecServer_->QueueInputParameter(index);
        return;
    }
    std::lock_guard<std::mutex> lock(checkFramesMutex_);
    int64_t currentPts = 0;
    attribute->GetLongValue(Tag::MEDIA_TIME_STAMP, currentPts);
    bool isDroppedFrames = CheckFrames(currentPts, checkFramesPauseTime_);
    UpdateStartBufferTime(currentPts);
    MEDIA_INFO_LOG("name: %{public}s,\tcurrentPts: %{public} " PRId64
        ", checkFramesPauseTime: %{public}" PRId64 ", isDroppedFrames: %{public}d",
        name_.c_str(), currentPts, checkFramesPauseTime_, isDroppedFrames);
    {
        std::lock_guard<std::mutex> mappingLock(mappingPtsMutex_);
        // adjustPts means timestamps after resume time are translated to corresponding ones after pause time
        int64_t adjustPts = currentPts - totalPauseTimeQueue_[0] + checkFramesPauseTime_;
        if (!isDroppedFrames) {
            int64_t mappingTime = adjustPts - startBufferTime_;
            MEDIA_DEBUG_LOG("name: %{public}s, mappingTime: %{public}" PRId64, name_.c_str(), mappingTime);
            preKeyFramePts_ = currentKeyFramePts_;
            currentKeyFramePts_ = currentPts;
            AddStartPts(currentPts);
            AddPauseResumePts(currentPts);
            parameter->PutLongValue(Tag::VIDEO_ENCODE_SET_FRAME_PTS, mappingTime);
        }
        lastBufferTime_ = currentPts;
    }
    parameter->PutIntValue(Tag::VIDEO_ENCODER_PER_FRAME_DISCARD, isDroppedFrames);
    CHECK_RETURN_ELOG(!codecServer_, "codecServer_ is null");
    codecServer_->QueueInputParameter(index);
    CHECK_RETURN_ELOG(videoFrameRate_ == 0, "videoFrameRate_ = 0, invalid value.");
    if (stopTime_ != -1 && currentPts > stopTime_ - (SEC_TO_NS / videoFrameRate_)) {
        MEDIA_INFO_LOG("currentPts > stopTime, send EOS.");
        int32_t ret = codecServer_->NotifyEos();
        if (ret != 0) {
            MEDIA_ERR_LOG("OnInputParameterWithAttrAvailable codecServer_->NotifyEos() failed!");
        }
    }
}

bool VideoEncoderAdapter::CheckFrames(int64_t currentPts, int64_t &checkFramesPauseTime)
{
    CHECK_RETURN_RET(pauseResumeQueue_.empty(), false);
    auto stateCode = pauseResumeQueue_[0].second;
    MEDIA_DEBUG_LOG("CheckFrames stateCode: %{public}d, time: %{public}" PRId64,
        static_cast<int32_t>(stateCode), pauseResumeQueue_[0].first);
    // means not dropped frames when less than pause time
    CHECK_RETURN_RET(stateCode == StateCode::PAUSE && currentPts < pauseResumeQueue_[0].first, false);
    // means dropped frames when less than resume time
    CHECK_RETURN_RET(stateCode == StateCode::RESUME && currentPts < pauseResumeQueue_[0].first, true);
    // resumetime后的第一帧，放到pausepts后的第一帧
    if (stateCode == StateCode::PAUSE) {
        // pausetime与上一帧之间的帧间隔
        int64_t interFrameCount = ((pauseResumeQueue_[0].first - lastBufferTime_) + (SEC_TO_NS / videoFrameRate_) - 1) /
            (SEC_TO_NS / videoFrameRate_);
        // pausetime与本应该收到的下一帧的差
        checkFramesPauseTime = checkFramesPauseTime + (SEC_TO_NS / videoFrameRate_) * interFrameCount -
            (pauseResumeQueue_[0].first - lastBufferTime_);
    } else {
        if (!totalPauseTimeQueue_.empty()) {
            // after resume pop totalPauseTime
            totalPauseTimeQueue_.pop_front();
        }
        // resumetime之后第一帧与resumetime的差
        checkFramesPauseTime = checkFramesPauseTime - (currentPts - pauseResumeQueue_[0].first);
    }
    pauseResumeQueue_.pop_front();
    return CheckFrames(currentPts, checkFramesPauseTime);
}

void VideoEncoderAdapter::GetCurrentTime(int64_t &currentTime)
{
    struct timespec timestamp = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &timestamp);
    currentTime = static_cast<int64_t>(timestamp.tv_sec) * SEC_TO_NS + static_cast<int64_t>(timestamp.tv_nsec);
}

void VideoEncoderAdapter::AddStartPts(int64_t currentPts)
{
    // start time
    if (isStartKeyFramePts_) {
        keyFramePts_ += std::to_string(currentPts / NS_PER_US) + ",";
        isStartKeyFramePts_ = false;
        MEDIA_INFO_LOG("AddStartPts success %{public}s end", keyFramePts_.c_str());
        CHECK_RETURN_ELOG(encoderAdapterKeyFramePtsCallback_ == nullptr,
            "encoderAdapterKeyFramePtsCallback_ is null, can't report firstFramePts");
        encoderAdapterKeyFramePtsCallback_->OnReportFirstFramePts(currentPts);
    }
}

void VideoEncoderAdapter::AddStopPts()
{
    // stop time
    MEDIA_DEBUG_LOG("AddStopPts enter");
    if (isStopKeyFramePts_) {
        if (currentKeyFramePts_ > stopTime_) {
            keyFramePts_ += std::to_string(preKeyFramePts_ / NS_PER_US);
            MEDIA_INFO_LOG("AddStopPts preKeyFramePts_ %{public}s end", keyFramePts_.c_str());
        } else {
            keyFramePts_ += std::to_string(currentKeyFramePts_ / NS_PER_US);
            MEDIA_INFO_LOG("AddStopPts currentKeyFramePts_ %{public}s end", keyFramePts_.c_str());
        }
        isStopKeyFramePts_ = false;
        if (encoderAdapterKeyFramePtsCallback_) {
            encoderAdapterKeyFramePtsCallback_->OnReportKeyFramePts(keyFramePts_);
        }
        keyFramePts_.clear();
    }
}

bool VideoEncoderAdapter::AddPauseResumePts(int64_t currentPts)
{
    CHECK_RETURN_RET(pauseResumePts_.empty(), false);
    auto stateCode = pauseResumePts_[0].second;
    MEDIA_DEBUG_LOG("CheckFrames stateCode: %{public}d, time: %{public}" PRId64,
        static_cast<int32_t>(stateCode), pauseResumePts_[0].first);
    // means not dropped frames when less than pause time
    CHECK_RETURN_RET(stateCode == StateCode::PAUSE && currentPts < pauseResumePts_[0].first, false);
    // means dropped frames when less than resume time
    CHECK_RETURN_RET(stateCode == StateCode::RESUME && currentPts < pauseResumePts_[0].first, true);
    if (stateCode == StateCode::PAUSE) {
        MEDIA_DEBUG_LOG("AddPausePts %{public}s start", keyFramePts_.c_str());
        keyFramePts_ += std::to_string(preKeyFramePts_ / NS_PER_US) + ",";
        MEDIA_DEBUG_LOG("AddPausePts %{public}s end", keyFramePts_.c_str());
    }
    if (stateCode == StateCode::RESUME) {
        MEDIA_DEBUG_LOG("AddResumePts %{public}s start", keyFramePts_.c_str());
        keyFramePts_ += std::to_string(currentKeyFramePts_ / NS_PER_US) + ",";
        if (encoderAdapterKeyFramePtsCallback_) {
            encoderAdapterKeyFramePtsCallback_->OnReportFirstFramePts(currentKeyFramePts_);
        } else {
            MEDIA_ERR_LOG("encoderAdapterKeyFramePtsCallback_ is null, can't report firstFramePts");
        }
        MEDIA_DEBUG_LOG("AddResumePts %{public}s end", keyFramePts_.c_str());
    }
    pauseResumePts_.pop_front();
    return AddPauseResumePts(currentPts);
}

void VideoEncoderAdapter::HandleWaitforStop()
{
    // Determine whether to end directly or wait STOP_TIME_OUT_MS
    std::unique_lock<std::mutex> lock(stopMutex_);
    CHECK_RETURN_ILOG(hasReceivedEOS_, "SurfaceEncoderAdapter::HandleWaitforStop, EOS has received, directly stop");
    std::cv_status waitStatus = stopCondition_.wait_for(lock, std::chrono::milliseconds(STOP_TIME_OUT_MS));
    // Waiting timeout with no video frame received
    if (waitStatus == std::cv_status::timeout && currentKeyFramePts_ == -1) {
        MEDIA_ERR_LOG("Codec wait timeout with no video frame received");
        encoderAdapterCallback_->OnError(AVCodecErrorType::AVCODEC_ERROR_INTERNAL,
            AVCODEC_ERR_TIMEOUT_NO_FRAME_RECEIVED);
    }
}

bool VideoEncoderAdapter::GetIsTransCoderMode()
{
    return isTransCoderMode_;
}

void VideoEncoderAdapter::MovingPhotoOnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    CHECK_RETURN_ELOG(avbufferContext_ == nullptr, "avbufferContext_ is nullptr");
    std::unique_lock<std::mutex> lock(avbufferContext_->outputMutex_);
    avbufferContext_->outputBufferInfoQueue_.emplace(new AVBufferInfo(index, buffer));
    avbufferContext_->outputCond_.notify_all();
}

Status VideoEncoderAdapter::ReleaseOutputBuffer(uint32_t index)
{
    int32_t ret = codecServer_->ReleaseOutputBuffer(index);
    CHECK_RETURN_RET_ELOG(
        ret != 0, Status::ERROR_UNKNOWN, "VideoEncoderAdapter::ReleaseOutputBuffer error %{public}d", ret);
    return Status::OK;
}

void VideoEncoderAdapter::UpdateStartBufferTime(int64_t currentPts)
{
    int64_t firstFrameTimestamp = currentPts;
    if (startBufferTime_ == -1) {
        // main track set ts to muxer, aux track get ts from muxer
        CHECK_EXECUTE(encoderAdapterKeyFramePtsCallback_,
                      encoderAdapterKeyFramePtsCallback_->OnFirstFrameArrival(name_, firstFrameTimestamp));
        // ensure track's frame ts
        CHECK_EXECUTE(firstFrameTimestamp > 0, startBufferTime_ = firstFrameTimestamp);
        MEDIA_INFO_LOG("name: %{public}s, startBufferTime_: %{public}" PRId64 ", firstFrameTimestamp: %{public}" PRId64
                       ", currentPts : %{public}" PRId64,
                       name_.c_str(), startBufferTime_, firstFrameTimestamp, currentPts);
    }
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP