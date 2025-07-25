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

bool VideoEncoder::EnqueueBuffer(sptr<FrameRecord> frameRecord, int32_t keyFrameInterval)
{
    // LCOV_EXCL_START
    CHECK_EXECUTE(!isStarted_ || avCodecProxy_ == nullptr || size_ == nullptr,
        RestartVideoCodec(frameRecord->GetFrameSize(), frameRecord->GetRotation()));
    if (keyFrameInterval == KEY_FRAME_INTERVAL) {
        std::lock_guard<std::mutex> lock(encoderMutex_);
        MediaAVCodec::Format format = MediaAVCodec::Format();
        format.PutIntValue(MediaDescriptionKey::MD_KEY_REQUEST_I_FRAME, true);
        CHECK_RETURN_RET_ELOG(avCodecProxy_ == nullptr, false, "avCodecProxy_ is nullptr");
        int32_t ret = avCodecProxy_->AVCodecVideoEncoderSetParameter(format);
        CHECK_RETURN_RET_ELOG(ret != AV_ERR_OK, false, "SetParameter failed, ret: %{public}d", ret);
    }
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
        successFrame_ = false;
        return true;
    } else if (bufferInfo->buffer->flag_ == AVCODEC_BUFFER_FLAGS_SYNC_FRAME) {
        // then return I frame
        std::shared_ptr<Media::AVBuffer> tempBuffer = bufferInfo->AddCopyAVBuffer(frameRecord->encodedBuffer);
        if (tempBuffer != nullptr) {
            frameRecord->encodedBuffer = tempBuffer;
        }
        successFrame_ = true;
        return true;
    } else if (bufferInfo->buffer->flag_ == AVCODEC_BUFFER_FLAGS_NONE) {
        // return P frame
        std::shared_ptr<Media::AVBuffer> PBuffer = bufferInfo->GetCopyAVBuffer();
        frameRecord->CacheBuffer(PBuffer);
        frameRecord->SetIDRProperty(false);
        successFrame_ = true;
        return true;
    } else {
        return false;
    }
}

bool VideoEncoder::EncodeSurfaceBuffer(sptr<FrameRecord> frameRecord)
{
    // LCOV_EXCL_START
    if (frameRecord->GetTimeStamp() - preFrameTimestamp_ > NANOSEC_RANGE) {
        keyFrameInterval_ = KEY_FRAME_INTERVAL;
    } else {
        keyFrameInterval_ = (keyFrameInterval_ == 0 ? KEY_FRAME_INTERVAL : keyFrameInterval_);
    }
    preFrameTimestamp_ = frameRecord->GetTimeStamp();
    CHECK_RETURN_RET(!EnqueueBuffer(frameRecord, keyFrameInterval_), false);
    keyFrameInterval_--;
    int32_t retryCount = 5;
    while (retryCount > 0) {
        retryCount--;
        std::unique_lock<std::mutex> contextLock(contextMutex_);
        CHECK_RETURN_RET_ELOG(context_ == nullptr, false, "VideoEncoder has been released");
        std::unique_lock<std::mutex> lock(context_->outputMutex_);
        bool condRet = context_->outputCond_.wait_for(lock, std::chrono::milliseconds(BUFFER_ENCODE_EXPIREATION_TIME),
            [this]() { return !isStarted_ || !context_->outputBufferInfoQueue_.empty(); });
        CHECK_CONTINUE_WLOG(context_->outputBufferInfoQueue_.empty(),
            "Buffer queue is empty, continue, cond ret: %{public}d", condRet);
        sptr<VideoCodecAVBufferInfo> bufferInfo = context_->outputBufferInfoQueue_.front();
        MEDIA_INFO_LOG("Out buffer count: %{public}u, size: %{public}d, flag: %{public}u, pts:%{public}" PRIu64 ", "
            "timestamp:%{public}" PRIu64, context_->outputFrameCount_, bufferInfo->buffer->memory_->GetSize(),
            bufferInfo->buffer->flag_, bufferInfo->buffer->pts_, frameRecord->GetTimeStamp());
        context_->outputBufferInfoQueue_.pop();
        context_->outputFrameCount_++;
        lock.unlock();
        contextLock.unlock();
        std::lock_guard<std::mutex> encodeLock(encoderMutex_);
        CHECK_RETURN_RET_ELOG(!isStarted_ || avCodecProxy_ == nullptr || !avCodecProxy_->IsVideoEncoderExisted(),
            false, "EncodeSurfaceBuffer when encoder stop!");
        condRet = ProcessFrameRecord(bufferInfo, frameRecord);
        if (condRet == false) {
            MEDIA_ERR_LOG("Flag is not acceptted number: %{public}u", bufferInfo->buffer->flag_);
            int32_t ret = FreeOutputData(bufferInfo->bufferIndex);
            CHECK_BREAK_WLOG(ret != 0, "FreeOutputData failed");
            continue;
        }
        int32_t ret = FreeOutputData(bufferInfo->bufferIndex);
        CHECK_BREAK_WLOG(ret != 0, "FreeOutputData failed");
        if (successFrame_) {
            MEDIA_DEBUG_LOG("Success frame id is : %{public}s, refCount: %{public}d",
                frameRecord->GetFrameId().c_str(), frameRecord->GetSptrRefCount());
            return true;
        }
    }
    MEDIA_ERR_LOG("Failed frame id is : %{public}s", frameRecord->GetFrameId().c_str());
    return false;
    // LCOV_EXCL_STOP
}

int32_t VideoEncoder::Release()
{
    {
        std::lock_guard<std::mutex> lock(encoderMutex_);
        CHECK_EXECUTE(avCodecProxy_ && avCodecProxy_->IsVideoEncoderExisted(),
            avCodecProxy_->AVCodecVideoEncoderRelease());
        CameraDynamicLoader::FreeDynamicLibDelayed(AV_CODEC_SO, LIB_DELAYED_UNLOAD_TIME);
        avCodecProxy_.reset();
    }
    std::unique_lock<std::mutex> contextLock(contextMutex_);
    isStarted_ = false;
    return 0;
}

void VideoEncoder::CallBack::OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode)
{
    (void)errorCode;
    MEDIA_ERR_LOG("On decoder error, error code: %{public}d", errorCode);
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
    MEDIA_DEBUG_LOG("OnOutputBufferAvailable");
    auto encoder = videoEncoder_.lock();
    CHECK_RETURN_ELOG(encoder == nullptr, "encoder is nullptr");
    CHECK_RETURN_ELOG(encoder->context_ == nullptr, "encoder context is nullptr");
    std::unique_lock<std::mutex> lock(encoder->context_->outputMutex_);
    encoder->context_->outputBufferInfoQueue_.emplace(new VideoCodecAVBufferInfo(index, buffer));
    encoder->context_->outputCond_.notify_all();
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
    format.PutIntValue(MediaDescriptionKey::MD_KEY_WIDTH, size_->width);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_HEIGHT, size_->height);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_ROTATION_ANGLE, rotation_);
    format.PutDoubleValue(MediaDescriptionKey::MD_KEY_FRAME_RATE, VIDEO_FRAME_RATE);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_VIDEO_ENCODE_BITRATE_MODE, MediaAVCodec::SQR);
    format.PutLongValue(MediaDescriptionKey::MD_KEY_BITRATE, bitrate_);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_PIXEL_FORMAT, VIDOE_PIXEL_FORMAT);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_I_FRAME_INTERVAL, INT_MAX);
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