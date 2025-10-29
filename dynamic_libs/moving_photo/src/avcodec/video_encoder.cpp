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

#include "video_encoder.h"
#include <cstdint>
#include <string>
#include <unordered_map>
#include "frame_record.h"
#include "surface_type.h"
#include "external_window.h"
#include "avcodec_common.h"
#include "native_avbuffer.h"
#include "utils/camera_log.h"
#include <chrono>
#include <fcntl.h>
#include <cinttypes>
#include <unistd.h>
#include <memory>
#include <sync_fence.h>
#include "native_mfmagic.h"
#include "media_description.h"

namespace OHOS {
namespace CameraStandard {

constexpr size_t THREE_HUNDRED_NUM = 300;
constexpr size_t EIGHT_NUM = 8;
constexpr size_t NINE_NUM = 9;

VideoEncoder::~VideoEncoder()
{
    MEDIA_INFO_LOG("~VideoEncoder enter");
    Release();
}

VideoEncoder::VideoEncoder(VideoCodecType type, ColorSpace colorSpace) : videoCodecType_(type),
    isHdr_(IsHdr(colorSpace))
{
    MEDIA_INFO_LOG("VideoEncoder enter");
}

bool VideoEncoder::IsHdr(ColorSpace colorSpace)
{
    std::vector<ColorSpace> hdrColorSpaces = {BT2020_HLG, BT2020_PQ, BT2020_HLG_LIMIT,
                                             BT2020_PQ_LIMIT};
    auto it = std::find(hdrColorSpaces.begin(), hdrColorSpaces.end(), colorSpace);
    return it != hdrColorSpaces.end();
}

int32_t VideoEncoder::Create(const std::string &codecMime)
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    avCodecProxy_ = AVCodecProxy::CreateAVCodecProxy();
    CHECK_RETURN_RET_ELOG(avCodecProxy_ == nullptr, 1, "avCodecProxy_ is nullptr");
    auto ret = avCodecProxy_->CreateAVCodecVideoEncoder(codecMime);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Create AVCodecVideoEncoder failed, ret: %{public}d", ret);
    return 0;
}

int32_t VideoEncoder::Config()
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_RETURN_RET_ELOG(avCodecProxy_ == nullptr, 1, "avCodecProxy_ is nullptr");
    std::unique_lock<std::mutex> contextLock(contextMutex_);
    context_ = new VideoCodecUserData;
    // Configure video encoder
    int32_t ret = Configure();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Configure failed");
    // SetCallback for video encoder
    ret = SetCallback();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Set callback failed");
    contextLock.unlock();
    return 0;
}

int32_t VideoEncoder::Start()
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
     // Prepare video encoder
    CHECK_RETURN_RET_ELOG(avCodecProxy_ == nullptr, 1, "avCodecProxy_ is nullptr");
    int ret = avCodecProxy_->AVCodecVideoEncoderPrepare();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Prepare failed, ret: %{public}d", ret);
    // Start video encoder
    ret = avCodecProxy_->AVCodecVideoEncoderStart();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Start failed, ret: %{public}d", ret);
    isStarted_ = true;
    return 0;
}

int32_t VideoEncoder::GetSurface()
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_RETURN_RET_ELOG(avCodecProxy_ == nullptr, 1, "avCodecProxy_ is nullptr");
    std::lock_guard<std::mutex> surfaceLock(surfaceMutex_);
    codecSurface_ = avCodecProxy_->CreateInputSurface();
    CHECK_RETURN_RET_ELOG(codecSurface_ == nullptr, 1, "Surface is null");
    codecSurface_->SetQueueSize(EIGHT_NUM);
    return 0;
}

int32_t VideoEncoder::ReleaseSurfaceBuffer(sptr<FrameRecord> frameRecord)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(frameRecord->GetSurfaceBuffer() == nullptr, 1,
        "SurfaceBuffer is released %{public}s", frameRecord->GetFrameId().c_str());
    sptr<SurfaceBuffer> releaseBuffer;
    int32_t ret = DetachCodecBuffer(releaseBuffer, frameRecord);
    CHECK_RETURN_RET_ELOG(ret != SURFACE_ERROR_OK, ret, " %{public}s ReleaseSurfaceBuffer failed",
        frameRecord->GetFrameId().c_str());
    frameRecord->SetSurfaceBuffer(releaseBuffer);
    // after request surfaceBuffer
    frameRecord->NotifyBufferRelease();
    MEDIA_INFO_LOG("release codec surface buffer end");
    return 0;
}

int32_t VideoEncoder::DetachCodecBuffer(sptr<SurfaceBuffer> &surfaceBuffer, sptr<FrameRecord> frameRecord)
{
    CHECK_RETURN_RET_ELOG(frameRecord == nullptr, 1, "frameRecord is null");
    std::lock_guard<std::mutex> lock(surfaceMutex_);
    CHECK_RETURN_RET_ELOG(codecSurface_ == nullptr, 1, "codecSurface_ is null");
    sptr<SyncFence> syncFence = SyncFence::INVALID_FENCE;
    BufferRequestConfig requestConfig = {
        .width = frameRecord->GetFrameSize()->width,
        .height = frameRecord->GetFrameSize()->height,
        .strideAlignment = 0x8, // default stride is 8 Bytes.
        .format = frameRecord->GetFormat(),
        .usage = frameRecord->GetUsage(),
        .timeout = 0,
    };
    SurfaceError ret = codecSurface_->RequestBuffer(surfaceBuffer, syncFence, requestConfig);
    CHECK_RETURN_RET_ELOG(ret != SURFACE_ERROR_OK, ret, "RequestBuffer failed. %{public}d", ret);
    constexpr uint32_t waitForEver = -1;
    (void)syncFence->Wait(waitForEver);
    CHECK_RETURN_RET_ELOG(surfaceBuffer == nullptr, ret, "Failed to request codec Buffer");
    ret = codecSurface_->DetachBufferFromQueue(surfaceBuffer);
    CHECK_RETURN_RET_ELOG(ret != SURFACE_ERROR_OK, ret, "Failed to detach buffer %{public}d", ret);
    return ret;
}

int32_t VideoEncoder::PushInputData(sptr<CodecAVBufferInfo> info)
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_RETURN_RET_ELOG(avCodecProxy_ == nullptr, 1, "avCodecProxy_ is nullptr");
    int32_t ret = AV_ERR_OK;
    ret = OH_AVBuffer_SetBufferAttr(info->buffer, &info->attr);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Set avbuffer attr failed, ret: %{public}d", ret);
    ret = avCodecProxy_->QueueInputBuffer(info->bufferIndex);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Push input data failed, ret: %{public}d", ret);
    return 0;
    // LCOV_EXCL_STOP
}

int32_t VideoEncoder::NotifyEndOfStream()
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_RETURN_RET_ELOG(avCodecProxy_ == nullptr, 1, "avCodecProxy_ is nullptr");
    int32_t ret = avCodecProxy_->AVCodecVideoEncoderNotifyEos();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1,
        "Notify end of stream failed, ret: %{public}d", ret);
    return 0;
}

int32_t VideoEncoder::FreeOutputData(uint32_t bufferIndex)
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_RETURN_RET_ELOG(avCodecProxy_ == nullptr, 1, "avCodecProxy_ is nullptr");
    int32_t ret = avCodecProxy_->ReleaseOutputBuffer(bufferIndex);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1,
        "Free output data failed, ret: %{public}d", ret);
    return 0;
    // LCOV_EXCL_STOP
}

int32_t VideoEncoder::Stop()
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_RETURN_RET_ELOG(avCodecProxy_ == nullptr, 1, "avCodecProxy_ is nullptr");
    int32_t ret = avCodecProxy_->AVCodecVideoEncoderStop();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Stop failed, ret: %{public}d", ret);
    isStarted_ = false;
    return 0;
}

void VideoEncoder::SetVideoCodec(const std::shared_ptr<Size>& size, int32_t rotation)
{
    MEDIA_INFO_LOG("VideoEncoder SetVideoCodec E videoCodecType_ = %{public}d", videoCodecType_);
    size_ = size;
    rotation_ = rotation;
    videoCodecType_ = VideoCodecType::VIDEO_ENCODE_TYPE_HEVC;
    Create(MIME_VIDEO_HEVC.data());
    Config();
    GetSurface();
    MEDIA_INFO_LOG("VideoEncoder SetVideoCodec X");
}

void VideoEncoder::RestartVideoCodec(shared_ptr<Size> size, int32_t rotation)
{
    // LCOV_EXCL_START
    Release();
    size_ = size;
    rotation_ = rotation;
    MEDIA_INFO_LOG("VideoEncoder videoCodecType_ = %{public}d", videoCodecType_);
    if (videoCodecType_ == VideoCodecType::VIDEO_ENCODE_TYPE_AVC) {
        Create(MIME_VIDEO_AVC.data());
    } else if (videoCodecType_ == VideoCodecType::VIDEO_ENCODE_TYPE_HEVC) {
        Create(MIME_VIDEO_HEVC.data());
    }
    Config();
    GetSurface();
    Start();
    // LCOV_EXCL_STOP
}

bool VideoEncoder::EnqueueBuffer(sptr<FrameRecord> frameRecord)
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("EnqueueBuffer timestamp : %{public}s", frameRecord->GetFrameId().c_str());
    CHECK_EXECUTE(!isStarted_ || avCodecProxy_ == nullptr || size_ == nullptr,
        RestartVideoCodec(frameRecord->GetFrameSize(), frameRecord->GetRotation()));
    sptr<SurfaceBuffer> buffer = frameRecord->GetSurfaceBuffer();
    CHECK_RETURN_RET_ELOG(buffer == nullptr, false, "Enqueue video buffer is empty");
    std::lock_guard<std::mutex> lock(surfaceMutex_);
    CHECK_RETURN_RET_ELOG(codecSurface_ == nullptr, false, "codecSurface_ is null");
    SurfaceError surfaceRet = codecSurface_->AttachBufferToQueue(buffer);
    if (surfaceRet != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("Failed to attach buffer, surfaceRet: %{public}d", surfaceRet);
        // notify release buffer when attach failed
        frameRecord->NotifyBufferRelease();
        return false;
    }
    constexpr int32_t invalidFence = -1;
    BufferFlushConfig flushConfig = {
        .damage = {
            .w = buffer->GetWidth(),
            .h = buffer->GetHeight(),
        },
        .timestamp = frameRecord->GetTimeStamp(),
    };
    surfaceRet = codecSurface_->FlushBuffer(buffer, invalidFence, flushConfig);
    CHECK_RETURN_RET_ELOG(surfaceRet != 0, false, "FlushBuffer failed");
    MEDIA_DEBUG_LOG("Success frame id is : %{public}s", frameRecord->GetFrameId().c_str());
    return true;
    // LCOV_EXCL_STOP
}

bool VideoEncoder::ProcessFrameRecord(sptr<VideoCodecAVBufferInfo> bufferInfo, sptr<FrameRecord> frameRecord)
{
    MEDIA_DEBUG_LOG("enter VideoEncoder::ProcessFrameRecord");
    if (bufferInfo->buffer->flag_ == AVCODEC_BUFFER_FLAGS_CODEC_DATA) {
        // first return IDR frame
        std::shared_ptr<Media::AVBuffer> IDRBuffer = bufferInfo->GetCopyAVBuffer();
        frameRecord->CacheBuffer(IDRBuffer);
        frameRecord->SetIDRProperty(true);
        return true;
    } else if (bufferInfo->buffer->flag_ == AVCODEC_BUFFER_FLAGS_SYNC_FRAME) {
        // then return I frame
        std::shared_ptr<Media::AVBuffer> tempBuffer = bufferInfo->AddCopyAVBuffer(frameRecord->encodedBuffer);
        if (tempBuffer != nullptr) {
            frameRecord->encodedBuffer = tempBuffer;
        }
        return true;
    } else if (bufferInfo->buffer->flag_ == AVCODEC_BUFFER_FLAGS_NONE) {
        // return P frame
        std::shared_ptr<Media::AVBuffer> PBuffer = bufferInfo->GetCopyAVBuffer();
        frameRecord->CacheBuffer(PBuffer);
        frameRecord->SetIDRProperty(false);
        return true;
    } else {
        return false;
    }
}

bool VideoEncoder::EncodeSurfaceBuffer(sptr<FrameRecord> frameRecord)
{
    // LCOV_EXCL_START
    {
        std::unique_lock<std::mutex> enqueueLock(enqueueMutex_);
        enqueueCond_.wait_for(
            enqueueLock, std::chrono::milliseconds(BUFFER_ENCODE_EXPIREATION_TIME), [this, frameRecord]() {
                // 取出当前最小时间戳
                std::lock_guard<std::mutex> tsLock(tsMutex_);
                if (!tsVec_.empty()) {
                    current_min_timestamp = tsVec_.top();
                }
                return current_min_timestamp == frameRecord->GetTimeStamp();
            });
        if (!EnqueueBuffer(frameRecord)) {
            std::lock_guard<std::mutex> tsLock(tsMutex_);
            if (!tsVec_.empty()) {
                tsVec_.pop();
                enqueueCond_.notify_all();
            } else {
                current_min_timestamp = INT64_MAX;
            }
            MEDIA_INFO_LOG(
                "EncodeSurfaceBuffer::timestamp:%{public}" PRIu64 ",enqueuefalse", frameRecord->GetTimeStamp());
            return false;
        } else {
            std::lock_guard<std::mutex> tsLock(tsMutex_);
            if (!tsVec_.empty()) {
                tsVec_.pop();
                enqueueCond_.notify_all();
            } else {
                current_min_timestamp = INT64_MAX;
            }
            MEDIA_INFO_LOG(
                "EncodeSurfaceBuffer::timestamp:%{public}" PRIu64 ",enqueuesuccess", frameRecord->GetTimeStamp());
            enqueueCond_.notify_all();
        }
    }
    std::unique_lock<std::mutex> contextLock(contextMutex_);
    CHECK_RETURN_RET_ELOG(context_ == nullptr, false, "VideoEncoder has been released");
    std::unique_lock<std::mutex> lock(context_->outputMutex_);
    auto frameRef = context_->outputBufferInfoQueue_.find(frameRecord->GetTimeStamp());
    context_->outputCond_.wait_for(
        lock, std::chrono::milliseconds(BUFFER_ENCODE_EXPIREATION_TIME), [this, &frameRef, frameRecord]() {
            frameRef = context_->outputBufferInfoQueue_.find(frameRecord->GetTimeStamp());
            return !isStarted_ || frameRef != context_->outputBufferInfoQueue_.end();
        });
    if (frameRef == context_->outputBufferInfoQueue_.end()) {
        std::unique_lock<std::mutex> overTimeLock(overTimeMutex_);
        overTimeVec.insert(frameRecord->GetTimeStamp());
        MEDIA_ERR_LOG("Failed frame id is : %{public}s", frameRecord->GetFrameId().c_str());
        return false;
    }
    sptr<VideoCodecAVBufferInfo> bufferInfoVec = frameRef->second;
    CHECK_RETURN_RET_ELOG(bufferInfoVec->buffer->memory_ == nullptr, false, "memory is alloced failed!");
    MEDIA_INFO_LOG("Out buffer count: %{public}u, size: %{public}d, flag: %{public}u, pts:%{public}" PRIu64 ", "
                   "timestamp:%{public}" PRIu64,
        context_->outputFrameCount_, bufferInfoVec->buffer->memory_->GetSize(), bufferInfoVec->buffer->flag_,
        bufferInfoVec->buffer->pts_, frameRecord->GetTimeStamp());
    context_->outputBufferInfoQueue_.erase(frameRecord->GetTimeStamp());
    context_->outputFrameCount_++;
    lock.unlock();
    contextLock.unlock();
    {
        std::lock_guard<std::mutex> encodeLock(encoderMutex_);
        CHECK_RETURN_RET_ELOG(!isStarted_ || avCodecProxy_ == nullptr || !avCodecProxy_->IsVideoEncoderExisted(),
            false, "EncodeSurfaceBuffer when encoder stop!");
    }
    if (bufferInfoVec->buffer->flag_ & AVCODEC_BUFFER_FLAGS_SYNC_FRAME) {
        std::shared_ptr<Media::AVBuffer> IDRBuffer = bufferInfoVec->GetCopyAVBuffer();
        frameRecord->CacheBuffer(IDRBuffer);
        frameRecord->SetIDRProperty(true);
        frameRecord->SetMuxerIndex(bufferInfoVec->muxerIndex_);
    } else if (bufferInfoVec->buffer->flag_ == AVCODEC_BUFFER_FLAGS_NONE) {
        // return P/B frame
        std::shared_ptr<Media::AVBuffer> PBuffer = bufferInfoVec->GetCopyAVBuffer();
        frameRecord->CacheBuffer(PBuffer);
        frameRecord->SetIDRProperty(false);
        frameRecord->SetMuxerIndex(bufferInfoVec->muxerIndex_);
    } else {
        MEDIA_ERR_LOG("Flag is not acceptted number: %{public}u", bufferInfoVec->buffer->flag_);
        int32_t ret = FreeOutputData(bufferInfoVec->bufferIndex);
        CHECK_RETURN_RET_WLOG(ret != 0, false, "FreeOutputData failed");
    }
    int32_t ret = FreeOutputData(bufferInfoVec->bufferIndex);
    CHECK_RETURN_RET_WLOG(ret != 0, false, "First FreeOutputData failed");
    MEDIA_DEBUG_LOG("Success frame id is : %{public}s, refCount: %{public}d", frameRecord->GetFrameId().c_str(),
        frameRecord->GetSptrRefCount());
    return true;
    // LCOV_EXCL_STOP
}

int32_t VideoEncoder::Release()
{
    {
        std::lock_guard<std::mutex> lock(encoderMutex_);
        CHECK_EXECUTE(avCodecProxy_ && avCodecProxy_->IsVideoEncoderExisted(),
            avCodecProxy_->AVCodecVideoEncoderRelease());
        avCodecProxy_.reset();
    }
    std::unique_lock<std::mutex> contextLock(contextMutex_);
    isStarted_ = false;
    return 0;
}

void VideoEncoder::TsVecInsert(int64_t timestamp)
{
    std::lock_guard<std::mutex> tsLock(tsMutex_);
    tsVec_.push(timestamp);
}

void VideoEncoder::CallBack::OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode)
{
    (void)errorCode;
    MEDIA_ERR_LOG("On decoder error, error code: %{public}d", errorCode);
}

std::shared_ptr<AVBuffer> VideoEncoder::CopyAVBuffer(std::shared_ptr<AVBuffer> &inputBuffer)
{
    // deep copy input buffer to output buffer
    auto allocator = Media::AVAllocatorFactory::CreateSharedAllocator(Media::MemoryFlag::MEMORY_READ_WRITE);
    CHECK_RETURN_RET_ELOG(allocator == nullptr, nullptr, "create allocator failed");
    std::shared_ptr<Media::AVBuffer> destBuffer = Media::AVBuffer::CreateAVBuffer(allocator,
        inputBuffer->memory_->GetCapacity());
    CHECK_RETURN_RET_ELOG(destBuffer == nullptr, nullptr, "destBuffer is null");
    auto sourceAddr = inputBuffer->memory_->GetAddr();
    auto destAddr = destBuffer->memory_->GetAddr();
    errno_t cpyRet = memcpy_s(reinterpret_cast<void *>(destAddr), inputBuffer->memory_->GetSize(),
        reinterpret_cast<void *>(sourceAddr), inputBuffer->memory_->GetSize());
    CHECK_PRINT_ELOG(0 != cpyRet, "CodecBufferInfo memcpy_s failed. %{public}d", cpyRet);
    destBuffer->pts_ = inputBuffer->pts_;
    destBuffer->flag_ = inputBuffer->flag_;
    destBuffer->memory_->SetSize(inputBuffer->memory_->GetSize());
    return destBuffer;
}

std::shared_ptr<AVBuffer> VideoEncoder::GetXpsBuffer()
{
    if (XpsBuffer_ == nullptr) {
        MEDIA_ERR_LOG("Xpsbuffer is not assigned!");
    }
    return XpsBuffer_;
}

void VideoEncoder::SetXpsBuffer(std::shared_ptr<AVBuffer> XpsBuffer)
{
    if (XpsBuffer == nullptr) {
        MEDIA_ERR_LOG("VideoEncoder::SetXpsBuffer: Xpsbuffer is not assigned!");
    }
    XpsBuffer_ = XpsBuffer;
}

void VideoEncoder::CallBack::OnOutputFormatChanged(const Format &format)
{
    MEDIA_ERR_LOG("OnCodecFormatChange");
}

void VideoEncoder::CallBack::OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    MEDIA_DEBUG_LOG("OnInputBufferAvailable");
}

void VideoEncoder::CallBack::OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    // LCOV_EXCL_START
    auto encoder = videoEncoder_.lock();
    MEDIA_DEBUG_LOG("OnOutputBufferAvailable,index:%{public}u, pts:%{public}" PRIu64
                    ",flag:%{public}d, bufferIndex:%{public}" PRIu64 ",dts:%{public}" PRIu64
                    "keyFrameInterval_:%{public}d",
        index, buffer->pts_, buffer->flag_, encoder->muxerIndex, buffer->dts_, encoder->keyFrameInterval_);
    std::unique_lock<std::mutex> overTimeLock(encoder->overTimeMutex_);
    std::unordered_set<int64_t>::iterator oTref = encoder->overTimeVec.find(buffer->pts_);
    if (oTref != encoder->overTimeVec.end()) {
        encoder->overTimeVec.erase(oTref);
        encoder->FreeOutputData(index);
        return;
    }
    overTimeLock.unlock();
    CHECK_RETURN_ELOG(encoder == nullptr, "encoder is nullptr");
    CHECK_RETURN_ELOG(encoder->context_ == nullptr, "encoder context is nullptr");
    std::unique_lock<std::mutex> lock(encoder->context_->outputMutex_);
    if (buffer->flag_ & AVCODEC_BUFFER_FLAGS_CODEC_DATA) {
        encoder->SetXpsBuffer(encoder->CopyAVBuffer(buffer));
        encoder->FreeOutputData(index);
    } else {
        sptr<VideoCodecAVBufferInfo> AVBufferInfo = new VideoCodecAVBufferInfo(index, encoder->muxerIndex, buffer);
        encoder->context_->outputBufferInfoQueue_[buffer->pts_] = AVBufferInfo;
        encoder->muxerIndex++;
        encoder->context_->outputCond_.notify_all();
    }
    // LCOV_EXCL_STOP
}

void VideoEncoder::inputCallback::OnInputParameterWithAttrAvailable(uint32_t index, std::shared_ptr<Format> attribute,
                                                                    std::shared_ptr<Format> parameter)
{
    // LCOV_EXCL_START
    CHECK_RETURN_ELOG(parameter == nullptr, "Invalid null format pointers received.");
    int64_t currentPts = 0;
    attribute->GetLongValue(Tag::MEDIA_TIME_STAMP, currentPts);
    auto videoencoder_ = videoEncoder_.lock();
        if (currentPts - videoencoder_->preFrameTimestamp_ > NANOSEC_RANGE) {
        videoencoder_->keyFrameInterval_ = KEY_FRAME_INTERVAL;
    } else {
        videoencoder_->keyFrameInterval_ =
            (videoencoder_->keyFrameInterval_ == 0 ? KEY_FRAME_INTERVAL : videoencoder_->keyFrameInterval_);
    }
    if (videoencoder_->keyFrameInterval_ == NINE_NUM) {
        parameter->PutIntValue(MediaDescriptionKey::MD_KEY_REQUEST_I_FRAME, true);
        MEDIA_INFO_LOG("OnInputParameterWithAttrAvailable index:%{public}u, currentPts: %{public}" PRId64
                       ", keyFrameInterval: %{public}u",
            index, currentPts, videoencoder_->keyFrameInterval_);
    }
    videoencoder_->keyFrameInterval_--;
    videoencoder_->preFrameTimestamp_ = currentPts;
    videoencoder_->avCodecProxy_->QueueInputParameter(index);
    // LCOV_EXCL_STOP
}

int32_t VideoEncoder::SetCallback()
{
    // LCOV_EXCL_START
    int32_t ret = AV_ERR_OK;
    auto callback = make_shared<CallBack>(weak_from_this());
    CHECK_RETURN_RET_ELOG(avCodecProxy_ == nullptr, 1, "avCodecProxy_ is nullptr");
    ret = avCodecProxy_->AVCodecVideoEncoderSetCallback(callback);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Set callback failed, ret: %{public}d", ret);
    return 0;
    // LCOV_EXCL_STOP
}

int32_t VideoEncoder::Configure()
{
    MediaAVCodec::Format format = MediaAVCodec::Format();
    int32_t bitrate = static_cast<int32_t>(pow(float(size_->width) * float(size_->height) / DEFAULT_SIZE,
        VIDEO_BITRATE_CONSTANT) * BITRATE_22M);
    bitrate_ = videoCodecType_ == VideoCodecType::VIDEO_ENCODE_TYPE_AVC
        ? static_cast<int32_t>(bitrate * HEVC_TO_AVC_FACTOR) : bitrate;
    MEDIA_INFO_LOG("Current resolution is : %{public}d*%{public}d, encode type : %{public}d, set bitrate : %{public}d",
        size_->width, size_->height, videoCodecType_, bitrate_);
    BframeAbility_ = avCodecProxy_->IsBframeSurported();
    MEDIA_DEBUG_LOG("BframeAbility:%{public}d", BframeAbility_);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_WIDTH, size_->width);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_HEIGHT, size_->height);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_ROTATION_ANGLE, rotation_);
    format.PutDoubleValue(MediaDescriptionKey::MD_KEY_FRAME_RATE, VIDEO_FRAME_RATE);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_VIDEO_ENCODE_BITRATE_MODE, MediaAVCodec::SQR);
    format.PutIntValue(Tag::VIDEO_ENCODER_ENABLE_B_FRAME, BframeAbility_);
    if (BframeAbility_) {
        format.PutIntValue(Media::Tag::VIDEO_ENCODE_B_FRAME_GOP_MODE,
            static_cast<int32_t>(Media::Plugins::VideoEncodeBFrameGopMode::VIDEO_ENCODE_GOP_H3B_MODE));
    }
    format.PutLongValue(MediaDescriptionKey::MD_KEY_BITRATE, bitrate_);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_PIXEL_FORMAT, VIDOE_PIXEL_FORMAT);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_I_FRAME_INTERVAL, THREE_HUNDRED_NUM);
    if (videoCodecType_ == VideoCodecType::VIDEO_ENCODE_TYPE_HEVC && isHdr_) {
        format.PutIntValue(MediaDescriptionKey::MD_KEY_PROFILE, MediaAVCodec::HEVC_PROFILE_MAIN_10);
    }
    CHECK_RETURN_RET_ELOG(avCodecProxy_ == nullptr, 1, "avCodecProxy_ is nullptr");
    int ret = avCodecProxy_->AVCodecVideoEncoderConfigure(format);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Config failed, ret: %{public}d", ret);
    return 0;
}

int32_t VideoEncoder::GetEncoderBitrate()
{
    return bitrate_;
}
} // CameraStandard
} // OHOS