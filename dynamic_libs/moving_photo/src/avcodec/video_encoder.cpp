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
#include "utils/camera_log.h"
#include <sync_fence.h>
#include "native_mfmagic.h"
#include "media_description.h"
#include "avcodec_list.h"

namespace OHOS {
namespace CameraStandard {

VideoEncoder::~VideoEncoder()
{
    MEDIA_INFO_LOG("~VideoEncoder enter");
    CHECK_PRINT_ILOG(codecSurface_, "codecSurface refCount %{public}d", codecSurface_->GetSptrRefCount());
    Release();
}
VideoEncoder::VideoEncoder(VideoCodecType type, ColorSpace colorSpace) : videoCodecType_(type),
    isHdr_(IsHdr(colorSpace))
{
    rotation_ = 0;
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
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(encoderMutex_);
    encoder_ = VideoEncoderFactory::CreateByMime(codecMime);
    CHECK_RETURN_RET_ELOG(encoder_ == nullptr, 1, "Create failed");
    return 0;
    // LCOV_EXCL_STOP
}

int32_t VideoEncoder::Config()
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_RETURN_RET_ELOG(encoder_ == nullptr, 1, "Encoder is null");
    // LCOV_EXCL_START
    std::unique_lock<std::mutex> contextLock(contextMutex_);
    context_ = new VideoCodecUserData;
    // Configure video encoder
    int32_t ret = Configure();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Configure failed");
    // SetCallback for video encoder
    ret = SetCallback();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Set callback failed");
    contextLock.unlock();
    // LCOV_EXCL_STOP
    return 0;
}

int32_t VideoEncoder::Start()
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
     // Prepare video encoder
    CHECK_RETURN_RET_ELOG(encoder_ == nullptr, 1, "Encoder is null");
    int ret = encoder_->Prepare();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Prepare failed, ret: %{public}d", ret);
    // Start video encoder
    ret = encoder_->Start();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Start failed, ret: %{public}d", ret);
    isStarted_ = true;
    // LCOV_EXCL_START
    return 0;
    // LCOV_EXCL_STOP
}

int32_t VideoEncoder::GetSurface()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_RETURN_RET_ELOG(encoder_ == nullptr, 1, "Encoder is null");
    std::lock_guard<std::mutex> surfaceLock(surfaceMutex_);
    codecSurface_ = encoder_->CreateInputSurface();
    CHECK_RETURN_RET_ELOG(codecSurface_ == nullptr, 1, "Surface is null");
    codecSurface_->SetQueueSize(CODEC_SURFACE_SIZE);
    return 0;
    // LCOV_EXCL_STOP
}

int32_t VideoEncoder::ReleaseSurfaceBuffer(sptr<FrameRecord> frameRecord)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(frameRecord->GetSurfaceBuffer() == nullptr, 1, "SurfaceBuffer is released %{public}s",
        frameRecord->GetFrameId().c_str());
    sptr<SurfaceBuffer> releaseBuffer;
    int32_t ret = DetachCodecBuffer(releaseBuffer, frameRecord);
    CHECK_RETURN_RET_ELOG(
        ret != SURFACE_ERROR_OK, ret, " %{public}s ReleaseSurfaceBuffer failed", frameRecord->GetFrameId().c_str());
    // LCOV_EXCL_START
    frameRecord->SetSurfaceBuffer(releaseBuffer);
    // after request surfaceBuffer
    frameRecord->NotifyBufferRelease();
    MEDIA_INFO_LOG("release codec surface buffer end");
    return 0;
    // LCOV_EXCL_STOP
}

int32_t VideoEncoder::DetachCodecBuffer(sptr<SurfaceBuffer> &surfaceBuffer, sptr<FrameRecord> frameRecord)
{
    CHECK_RETURN_RET_ELOG(frameRecord == nullptr, 1, "frameRecord is null");
    std::lock_guard<std::mutex> lock(surfaceMutex_);
    CHECK_RETURN_RET_ELOG(codecSurface_ == nullptr, 1, "codecSurface_ is null");
    // LCOV_EXCL_START
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
    // LCOV_EXCL_STOP
}

int32_t VideoEncoder::PushInputData(sptr<CodecAVBufferInfo> info)
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_RETURN_RET_ELOG(encoder_ == nullptr, 1, "Encoder is null");
    int32_t ret = AV_ERR_OK;
    ret = OH_AVBuffer_SetBufferAttr(info->buffer, &info->attr);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Set avbuffer attr failed, ret: %{public}d", ret);
    ret = encoder_->QueueInputBuffer(info->bufferIndex);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Push input data failed, ret: %{public}d", ret);
    return 0;
    // LCOV_EXCL_STOP
}

int32_t VideoEncoder::NotifyEndOfStream()
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_RETURN_RET_ELOG(encoder_ == nullptr, 1, "Encoder is null");
    int32_t ret = encoder_->NotifyEos();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Notify end of stream failed, ret: %{public}d", ret);
    // LCOV_EXCL_START
    return 0;
    // LCOV_EXCL_STOP
}

int32_t VideoEncoder::FreeOutputData(uint32_t bufferIndex)
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_RETURN_RET_ELOG(encoder_ == nullptr, 1, "Encoder is null");
    int32_t ret = encoder_->ReleaseOutputBuffer(bufferIndex);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Free output data failed, ret: %{public}d", ret);
    return 0;
    // LCOV_EXCL_STOP
}

int32_t VideoEncoder::Stop()
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_RETURN_RET_ELOG(encoder_ == nullptr, 1, "Encoder is null");
    int32_t ret = encoder_->Stop();
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Stop failed, ret: %{public}d", ret);
    // LCOV_EXCL_START
    isStarted_ = false;
    return 0;
    // LCOV_EXCL_STOP
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

bool VideoEncoder::EncodeSurfaceBuffer(sptr<FrameRecord> frameRecord)
{
    // LCOV_EXCL_START
    {
        std::unique_lock<std::mutex> enqueueLock(enqueueMutex_);
        enqueueCond_.wait_for(enqueueLock, std::chrono::milliseconds(QUEUE_WAIT_TIME), [this, frameRecord]() {
            // 取出当前最小时间戳
            std::lock_guard<std::mutex> tsLock(tsMutex_);
            if (!tsVec_.empty()) {
                currentMinTimestamp = tsVec_.top();
            }
            return currentMinTimestamp == frameRecord->GetTimeStamp();
        });
        auto EnqueueRet = EnqueueBuffer(frameRecord);
        std::unique_lock<std::mutex> tsLock(tsMutex_);
        if (!tsVec_.empty()) {
            tsVec_.pop();
            tsLock.unlock();
            enqueueCond_.notify_all();
        }
        MEDIA_DEBUG_LOG("EncodeSurfaceBuffer::timestamp:%{public}" PRIu64 ", enqueue result:%{public}d",
            frameRecord->GetTimeStamp(), EnqueueRet);
        CHECK_RETURN_RET_ELOG(
            !EnqueueRet, false, "EnqueueBuffer failed,timestamp::%{public}" PRIu64, frameRecord->GetTimeStamp());
    }
    std::unique_lock<std::mutex> contextLock(contextMutex_);
    CHECK_RETURN_RET_ELOG(context_ == nullptr, false, "VideoEncoder has been released");
    std::map<int64_t, sptr<VideoCodecAVBufferInfo>>::iterator frameRef;
    contextCond_.wait_for(
        contextLock, std::chrono::milliseconds(BUFFER_ENCODE_EXPIREATION_TIME), [this, &frameRef, frameRecord]() {
            std::unique_lock<std::mutex> lock(context_->outputMutex_);
            frameRef = context_->outputBufferInfoMap_.find(frameRecord->GetTimeStamp());
            return !isStarted_ || frameRef != context_->outputBufferInfoMap_.end();
        });
    std::unique_lock<std::mutex> lock(context_->outputMutex_);
    if (frameRef == context_->outputBufferInfoMap_.end()) {
        std::unique_lock<std::mutex> overTimeLock(overTimeMutex_);
        overTimeSet.insert(frameRecord->GetTimeStamp());
        MEDIA_ERR_LOG("Failed frame id is : %{public}s", frameRecord->GetFrameId().c_str());
        return false;
    }
    sptr<VideoCodecAVBufferInfo> bufferInfo = frameRef->second;
    CHECK_RETURN_RET_ELOG(bufferInfo->buffer->memory_ == nullptr, false, "memory is alloced failed!");
    uint32_t seqNum = 0;
    CHECK_EXECUTE(frameRecord->GetSurfaceBuffer() != nullptr, seqNum = frameRecord->GetSurfaceBuffer()->GetSeqNum());
    MEDIA_INFO_LOG("Out buffer count: %{public}u, size: %{public}d, flag: %{public}u, pts:%{public}" PRIu64 ", "
                   "timestamp:%{public}" PRIu64 ", SeqNum: %{public}" PRIu32,
        context_->outputFrameCount_, bufferInfo->buffer->memory_->GetSize(), bufferInfo->buffer->flag_,
        bufferInfo->buffer->pts_, frameRecord->GetTimeStamp(), seqNum);
    context_->outputBufferInfoMap_.erase(frameRecord->GetTimeStamp());
    context_->outputFrameCount_++;
    lock.unlock();
    contextLock.unlock();
    {
        std::lock_guard<std::mutex> encodeLock(encoderMutex_);
        CHECK_RETURN_RET_ELOG(!isStarted_ || encoder_ == nullptr, false, "EncodeSurfaceBuffer when encoder stop!");
    }
    if (bufferInfo->buffer->flag_ & AVCODEC_BUFFER_FLAGS_SYNC_FRAME) {
        std::shared_ptr<Media::AVBuffer> IDRBuffer = bufferInfo->GetCopyAVBuffer();
        frameRecord->CacheBuffer(IDRBuffer);
        frameRecord->SetIDRProperty(true);
        frameRecord->SetMuxerIndex(bufferInfo->muxerIndex_);
    } else if (bufferInfo->buffer->flag_ == AVCODEC_BUFFER_FLAGS_NONE) {
        // return P/B frame
        std::shared_ptr<Media::AVBuffer> PBuffer = bufferInfo->GetCopyAVBuffer();
        frameRecord->CacheBuffer(PBuffer);
        frameRecord->SetIDRProperty(false);
        frameRecord->SetMuxerIndex(bufferInfo->muxerIndex_);
    } else {
        MEDIA_ERR_LOG("Flag is not acceptted number: %{public}u", bufferInfo->buffer->flag_);
        int32_t ret = FreeOutputData(bufferInfo->bufferIndex);
        CHECK_RETURN_RET_WLOG(ret != 0, false, "FreeOutputData failed");
        return false;
    }
    int32_t ret = FreeOutputData(bufferInfo->bufferIndex);
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
        if (encoder_ != nullptr) {
            encoder_->Release();
        };
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
    // LCOV_EXCL_START
    (void)errorCode;
    MEDIA_ERR_LOG("On decoder error, error code: %{public}d", errorCode);
    // LCOV_EXCL_STOP
}

void VideoEncoder::CallBack::OnOutputFormatChanged(const Format &format)
{
    // LCOV_EXCL_START
    MEDIA_ERR_LOG("OnCodecFormatChange");
    // LCOV_EXCL_STOP
}

std::shared_ptr<AVBuffer> VideoEncoder::CopyAVBuffer(std::shared_ptr<AVBuffer>& inputBuffer)
{
    // deep copy input buffer to output buffer
    auto allocator = Media::AVAllocatorFactory::CreateSharedAllocator(Media::MemoryFlag::MEMORY_READ_WRITE);
    CHECK_RETURN_RET_ELOG(allocator == nullptr, nullptr, "create allocator failed");
    CHECK_RETURN_RET_ELOG(inputBuffer->memory_ == nullptr, nullptr, "memory is alloced failed!");
    std::shared_ptr<Media::AVBuffer> destBuffer =
        Media::AVBuffer::CreateAVBuffer(allocator, inputBuffer->memory_->GetCapacity());
    CHECK_RETURN_RET_ELOG(destBuffer == nullptr, nullptr, "destBuffer is null");
    auto sourceAddr = inputBuffer->memory_->GetAddr();
    auto destAddr = destBuffer->memory_->GetAddr();
    errno_t cpyRet = memcpy_s(reinterpret_cast<void*>(destAddr), inputBuffer->memory_->GetSize(),
        reinterpret_cast<void*>(sourceAddr), inputBuffer->memory_->GetSize());
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

void VideoEncoder::CallBack::OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("OnInputBufferAvailable");
    // LCOV_EXCL_STOP
}

void VideoEncoder::CallBack::OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    // LCOV_EXCL_START
    auto encoder = videoEncoder_.lock();
    CHECK_RETURN_ELOG(encoder == nullptr, "encoder is nullptr");
    MEDIA_DEBUG_LOG("OnOutputBufferAvailable,index:%{public}u, pts:%{public}" PRIu64
                    ",flag:%{public}d, bufferIndex:%{public}" PRId64 ",dts:%{public}" PRIu64,
        index, buffer->pts_, buffer->flag_, encoder->muxerIndex, buffer->dts_);
    std::unique_lock<std::mutex> overTimeLock(encoder->overTimeMutex_);
    std::unordered_set<int64_t>::iterator oTref = encoder->overTimeSet.find(buffer->pts_);
    if (oTref != encoder->overTimeSet.end()) {
        encoder->overTimeSet.erase(oTref);
        encoder->FreeOutputData(index);
        return;
    }
    overTimeLock.unlock();
    CHECK_RETURN_ELOG(encoder->context_ == nullptr, "encoder context is nullptr");
    std::unique_lock<std::mutex> lock(encoder->context_->outputMutex_);
    if (buffer->flag_ & AVCODEC_BUFFER_FLAGS_CODEC_DATA) {
        encoder->SetXpsBuffer(encoder->CopyAVBuffer(buffer));
        encoder->FreeOutputData(index);
    } else {
        sptr<VideoCodecAVBufferInfo> AVBufferInfo = new VideoCodecAVBufferInfo(index, encoder->muxerIndex, buffer);
        encoder->context_->outputBufferInfoMap_[buffer->pts_] = AVBufferInfo;
        encoder->muxerIndex++;
        encoder->contextCond_.notify_all();
    }
    // LCOV_EXCL_STOP
}

int32_t VideoEncoder::SetCallback()
{
    // LCOV_EXCL_START
    int32_t ret = AV_ERR_OK;
    auto callback = make_shared<CallBack>(weak_from_this());
    CHECK_RETURN_RET_ELOG(encoder_ == nullptr, 1, "Encoder is null");
    ret = encoder_->SetCallback(callback);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Set callback failed, ret: %{public}d", ret);
    return 0;
    // LCOV_EXCL_STOP
}

int32_t VideoEncoder::Configure()
{
    // LCOV_EXCL_START
    MediaAVCodec::Format format = MediaAVCodec::Format();
    int32_t bitrate = static_cast<int32_t>(pow(float(size_->width) * float(size_->height) / DEFAULT_SIZE,
        VIDEO_BITRATE_CONSTANT) * BITRATE_22M);
    bitrate_ = videoCodecType_ == VideoCodecType::VIDEO_ENCODE_TYPE_AVC
        ? static_cast<int32_t>(bitrate * HEVC_TO_AVC_FACTOR) : bitrate;
    MEDIA_INFO_LOG("Current resolution is : %{public}d*%{public}d, encode type : %{public}d, set bitrate : %{public}d",
        size_->width, size_->height, videoCodecType_, bitrate_);
    BframeAbility_ = IsBframeSupported();
    MEDIA_INFO_LOG("BframeAbility:%{public}d", BframeAbility_);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_WIDTH, size_->width);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_HEIGHT, size_->height);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_ROTATION_ANGLE, rotation_);
    format.PutDoubleValue(MediaDescriptionKey::MD_KEY_FRAME_RATE, VIDEO_FRAME_RATE);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_VIDEO_ENCODE_BITRATE_MODE, MediaAVCodec::SQR);
    format.PutIntValue(Media::Tag::VIDEO_ENCODER_ENABLE_B_FRAME, BframeAbility_);
    if (BframeAbility_) {
        format.PutIntValue(Media::Tag::VIDEO_ENCODE_B_FRAME_GOP_MODE,
            static_cast<int32_t>(Media::Plugins::VideoEncodeBFrameGopMode::VIDEO_ENCODE_GOP_H3B_MODE));
    }
    format.PutLongValue(MediaDescriptionKey::MD_KEY_BITRATE, bitrate_);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_PIXEL_FORMAT, VIDOE_PIXEL_FORMAT);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_I_FRAME_INTERVAL, KEY_I_FRAME_INTERVAL);
    bool isHevcAndHdrEnabled = videoCodecType_ == VideoCodecType::VIDEO_ENCODE_TYPE_HEVC && isHdr_;
    if (isHevcAndHdrEnabled) {
        format.PutIntValue(MediaDescriptionKey::MD_KEY_PROFILE, MediaAVCodec::HEVC_PROFILE_MAIN_10);
    }
    CHECK_RETURN_RET_ELOG(encoder_ == nullptr, 1, "Encoder is null");
    int ret = encoder_->Configure(format);
    CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, 1, "Config failed, ret: %{public}d", ret);
    return 0;
    // LCOV_EXCL_STOP
}

bool VideoEncoder::IsBframeSupported()
{
    auto codecList = MediaAVCodec::AVCodecListFactory::CreateAVCodecList();
    CHECK_RETURN_RET_ELOG(codecList == nullptr, false, "CodecList is nullptr.");
    MediaAVCodec::CapabilityData* capabilityData =
        codecList->GetCapability("video/hevc", true, MediaAVCodec::AVCodecCategory::AVCODEC_HARDWARE);
    CHECK_RETURN_RET_ELOG(capabilityData == nullptr, false, "CapabilityData is nullptr.");
    auto codecInfo = std::make_shared<MediaAVCodec::AVCodecInfo>(capabilityData);
    bool isBFrame = codecInfo->IsFeatureSupported(MediaAVCodec::AVCapabilityFeature::VIDEO_ENCODER_B_FRAME);
    return isBFrame;
}

int32_t VideoEncoder::GetEncoderBitrate()
{
    return bitrate_;
}
} // CameraStandard
} // OHOS