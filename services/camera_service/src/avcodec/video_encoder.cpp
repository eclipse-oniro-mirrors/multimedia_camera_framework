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
#include "camera_log.h"
#include <sync_fence.h>
#include "native_mfmagic.h"
#include "media_description.h"

namespace OHOS {
namespace CameraStandard {

VideoEncoder::~VideoEncoder()
{
    MEDIA_INFO_LOG("~VideoEncoder enter");
    if (codecSurface_) {
        MEDIA_INFO_LOG("codecSurface refCount %{public}d", codecSurface_->GetSptrRefCount());
    }
    Release();
}

VideoEncoder::VideoEncoder(VideoCodecType type) : videoCodecType_(type)
{
    rotation_ = 0;
    MEDIA_INFO_LOG("VideoEncoder enter");
}

int32_t VideoEncoder::Create(const std::string &codecMime)
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    encoder_ = VideoEncoderFactory::CreateByMime(codecMime);
    CHECK_ERROR_RETURN_RET_LOG(encoder_ == nullptr, 1, "Create failed");
    return 0;
}

int32_t VideoEncoder::Config()
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_AND_RETURN_RET_LOG(encoder_ != nullptr, 1, "Encoder is null");
    std::unique_lock<std::mutex> contextLock(contextMutex_);
    context_ = new VideoCodecUserData;
    // Configure video encoder
    int32_t ret = Configure();
    CHECK_ERROR_RETURN_RET_LOG(ret != AV_ERR_OK, 1, "Configure failed");
    // SetCallback for video encoder
    ret = SetCallback();
    CHECK_ERROR_RETURN_RET_LOG(ret != AV_ERR_OK, 1, "Set callback failed");
    contextLock.unlock();
    return 0;
}

int32_t VideoEncoder::Start()
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_AND_RETURN_RET_LOG(encoder_ != nullptr, 1, "Encoder is null");
     // Prepare video encoder
    int ret = encoder_->Prepare();
    CHECK_ERROR_RETURN_RET_LOG(ret != AV_ERR_OK, 1, "Prepare failed, ret: %{public}d", ret);
    // Start video encoder
    ret = encoder_->Start();
    CHECK_ERROR_RETURN_RET_LOG(ret != AV_ERR_OK, 1, "Start failed, ret: %{public}d", ret);
    isStarted_ = true;
    return 0;
}

int32_t VideoEncoder::GetSurface()
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_ERROR_RETURN_RET_LOG(encoder_ == nullptr, 1, "Encoder is null");
    std::lock_guard<std::mutex> surfaceLock(surfaceMutex_);
    codecSurface_ = encoder_->CreateInputSurface();
    CHECK_ERROR_RETURN_RET_LOG(codecSurface_ == nullptr, 1, "Surface is null");
    return 0;
}

int32_t VideoEncoder::ReleaseSurfaceBuffer(sptr<FrameRecord> frameRecord)
{
    CAMERA_SYNC_TRACE;
    CHECK_AND_RETURN_RET_LOG(frameRecord->GetSurfaceBuffer() != nullptr, 1,
        "SurfaceBuffer is released %{public}s", frameRecord->GetFrameId().c_str());
    sptr<SurfaceBuffer> releaseBuffer;
    int32_t ret = DetachCodecBuffer(releaseBuffer, frameRecord);
    CHECK_ERROR_RETURN_RET_LOG(ret != SURFACE_ERROR_OK, ret, " %{public}s ReleaseSurfaceBuffer failed",
        frameRecord->GetFrameId().c_str());
    frameRecord->SetSurfaceBuffer(releaseBuffer);
    // after request surfaceBuffer
    frameRecord->NotifyBufferRelease();
    MEDIA_INFO_LOG("release codec surface buffer end");
    return 0;
}

int32_t VideoEncoder::DetachCodecBuffer(sptr<SurfaceBuffer> &surfaceBuffer, sptr<FrameRecord> frameRecord)
{
    CHECK_ERROR_RETURN_RET_LOG(frameRecord == nullptr, 1, "frameRecord is null");
    std::lock_guard<std::mutex> lock(surfaceMutex_);
    CHECK_ERROR_RETURN_RET_LOG(codecSurface_ == nullptr, 1, "codecSurface_ is null");
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
    CHECK_ERROR_RETURN_RET_LOG(ret != SURFACE_ERROR_OK, ret, "RequestBuffer failed. %{public}d", ret);
    constexpr uint32_t waitForEver = -1;
    (void)syncFence->Wait(waitForEver);
    CHECK_ERROR_RETURN_RET_LOG(surfaceBuffer == nullptr, ret, "Failed to request codec Buffer");
    ret = codecSurface_->DetachBufferFromQueue(surfaceBuffer);
    CHECK_ERROR_RETURN_RET_LOG(ret != SURFACE_ERROR_OK, ret, "Failed to detach buffer %{public}d", ret);
    return ret;
}

int32_t VideoEncoder::PushInputData(sptr<CodecAVBufferInfo> info)
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_AND_RETURN_RET_LOG(encoder_ != nullptr, 1, "Decoder is null");
    int32_t ret = AV_ERR_OK;
    ret = OH_AVBuffer_SetBufferAttr(info->buffer, &info->attr);
    CHECK_ERROR_RETURN_RET_LOG(ret != AV_ERR_OK, 1, "Set avbuffer attr failed, ret: %{public}d", ret);
    ret = encoder_->QueueInputBuffer(info->bufferIndex);
    CHECK_ERROR_RETURN_RET_LOG(ret != AV_ERR_OK, 1, "Push input data failed, ret: %{public}d", ret);
}

int32_t VideoEncoder::NotifyEndOfStream()
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_ERROR_RETURN_RET_LOG(encoder_ == nullptr, 1, "Encoder is null");
    int32_t ret = encoder_->NotifyEos();
    CHECK_ERROR_RETURN_RET_LOG(ret != AV_ERR_OK, 1,
        "Notify end of stream failed, ret: %{public}d", ret);
    return 0;
}

int32_t VideoEncoder::FreeOutputData(uint32_t bufferIndex)
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_AND_RETURN_RET_LOG(encoder_ != nullptr, 1, "Encoder is null");
    int32_t ret = encoder_->ReleaseOutputBuffer(bufferIndex);
    CHECK_ERROR_RETURN_RET_LOG(ret != AV_ERR_OK, 1,
        "Free output data failed, ret: %{public}d", ret);
    return 0;
}

int32_t VideoEncoder::Stop()
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_ERROR_RETURN_RET_LOG(encoder_ == nullptr, 1, "Encoder is null");
    int ret = encoder_->Stop();
    CHECK_ERROR_RETURN_RET_LOG(ret != AV_ERR_OK, 1, "Stop failed, ret: %{public}d", ret);
    isStarted_ = false;
    return 0;
}

void VideoEncoder::RestartVideoCodec(shared_ptr<Size> size, int32_t rotation)
{
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
}

bool VideoEncoder::EnqueueBuffer(sptr<FrameRecord> frameRecord, int32_t keyFrameInterval)
{
    if (!isStarted_ || encoder_ == nullptr || size_ == nullptr) {
        RestartVideoCodec(frameRecord->GetFrameSize(), frameRecord->GetRotation());
    }
    if (keyFrameInterval == KEY_FRAME_INTERVAL) {
        std::lock_guard<std::mutex> lock(encoderMutex_);
        MediaAVCodec::Format format = MediaAVCodec::Format();
        format.PutIntValue(MediaDescriptionKey::MD_KEY_REQUEST_I_FRAME, true);
        encoder_->SetParameter(format);
    }
    sptr<SurfaceBuffer> buffer = frameRecord->GetSurfaceBuffer();
    if (buffer == nullptr) {
        MEDIA_ERR_LOG("Enqueue video buffer is empty");
        return false;
    }
    std::lock_guard<std::mutex> lock(surfaceMutex_);
    CHECK_AND_RETURN_RET_LOG(codecSurface_ != nullptr, false, "codecSurface_ is null");
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
    CHECK_AND_RETURN_RET_LOG(surfaceRet == 0, false, "FlushBuffer failed");
    MEDIA_DEBUG_LOG("Success frame id is : %{public}s", frameRecord->GetFrameId().c_str());
    return true;
}

bool VideoEncoder::EncodeSurfaceBuffer(sptr<FrameRecord> frameRecord)
{
    if (frameRecord->GetTimeStamp() - preFrameTimestamp_ > NANOSEC_RANGE) {
        keyFrameInterval_ = KEY_FRAME_INTERVAL;
    } else {
        keyFrameInterval_ = (keyFrameInterval_ == 0 ? KEY_FRAME_INTERVAL : keyFrameInterval_);
    }
    preFrameTimestamp_ = frameRecord->GetTimeStamp();
    if (!EnqueueBuffer(frameRecord, keyFrameInterval_)) {
        return false;
    }
    keyFrameInterval_--;
    int32_t retryCount = 5;
    while (retryCount > 0) {
        retryCount--;
        std::unique_lock<std::mutex> contextLock(contextMutex_);
        CHECK_AND_RETURN_RET_LOG(context_ != nullptr, false, "VideoEncoder has been released");
        std::unique_lock<std::mutex> lock(context_->outputMutex_);
        bool condRet = context_->outputCond_.wait_for(lock, std::chrono::milliseconds(BUFFER_ENCODE_EXPIREATION_TIME),
            [this]() { return !isStarted_ || !context_->outputBufferInfoQueue_.empty(); });
        CHECK_AND_CONTINUE_LOG(!context_->outputBufferInfoQueue_.empty(),
            "Buffer queue is empty, continue, cond ret: %{public}d", condRet);
        sptr<VideoCodecAVBufferInfo> bufferInfo = context_->outputBufferInfoQueue_.front();
        MEDIA_INFO_LOG("Out buffer count: %{public}u, size: %{public}d, flag: %{public}u, pts:%{public}" PRIu64 ", "
            "timestamp:%{public}" PRIu64, context_->outputFrameCount_, bufferInfo->buffer->memory_->GetSize(),
            bufferInfo->buffer->flag_, bufferInfo->buffer->pts_, frameRecord->GetTimeStamp());
        context_->outputBufferInfoQueue_.pop();
        context_->outputFrameCount_++;
        lock.unlock();
        contextLock.unlock();
        td::lock_guard<std::mutex> encodeLock(encoderMutex_);
        CHECK_ERROR_RETURN_RET_LOG(!isStarted_ || encoder_ == nullptr, false, "EncodeSurfaceBuffer when encoder stop!");
        if (bufferInfo->buffer->flag_ == AVCODEC_BUFFER_FLAGS_CODEC_DATA) {
            // first return IDR frame
            std::shared_ptr<Media::AVBuffer> IDRBuffer = bufferInfo->GetCopyAVBuffer();
            frameRecord->CacheBuffer(IDRBuffer);
            frameRecord->SetIDRProperty(true);
            successFrame_ = false;
        } else if (bufferInfo->buffer->flag_ == AVCODEC_BUFFER_FLAGS_SYNC_FRAME) {
            // then return I frame
            std::shared_ptr<Media::AVBuffer> tempBuffer = bufferInfo->AddCopyAVBuffer(frameRecord->encodedBuffer);
            if (tempBuffer != nullptr) {
                frameRecord->encodedBuffer = tempBuffer;
            }
            successFrame_ = true;
        } else if (bufferInfo->buffer->flag_ == AVCODEC_BUFFER_FLAGS_NONE) {
            // return P frame
            std::shared_ptr<Media::AVBuffer> PBuffer = bufferInfo->GetCopyAVBuffer();
            frameRecord->CacheBuffer(PBuffer);
            frameRecord->SetIDRProperty(false);
            successFrame_ = true;
        } else {
            MEDIA_ERR_LOG("Flag is not acceptted number: %{public}u", bufferInfo->buffer->flag_);
            int32_t ret = FreeOutputData(bufferInfo->bufferIndex);
            CHECK_AND_BREAK_LOG(ret == 0, "FreeOutputData failed");
            continue;
        }
        int32_t ret = FreeOutputData(bufferInfo->bufferIndex);
        CHECK_AND_BREAK_LOG(ret == 0, "FreeOutputData failed");
        if (successFrame_) {
            MEDIA_DEBUG_LOG("Success frame id is : %{public}s, refCount: %{public}d",
                frameRecord->GetFrameId().c_str(), frameRecord->GetSptrRefCount());
            return true;
        }
    }
    MEDIA_ERR_LOG("Failed frame id is : %{public}s", frameRecord->GetFrameId().c_str());
    return false;
}

int32_t VideoEncoder::Release()
{
    {
        std::lock_guard<std::mutex> lock(encoderMutex_);
        if (encoder_ != nullptr) {
            encoder_->Release();
        }
    }
    std::unique_lock<std::mutex> contextLock(contextMutex_);
    isStarted_ = false;
    return 0;
}

void VideoEncoder::CallBack::OnError(AVCodecErrorType errorType, int32_t errorCode)
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
    MEDIA_DEBUG_LOG("OnOutputBufferAvailable");
    auto encoder = videoEncoder_.lock();
    CHECK_ERROR_RETURN_LOG(encoder == nullptr, "encoder is nullptr");
    CHECK_ERROR_RETURN_LOG(encoder->context_ == nullptr, "encoder context is nullptr");
    std::unique_lock<std::mutex> lock(encoder->context_->outputMutex_);
    encoder->context_->outputBufferInfoQueue_.emplace(new VideoCodecAVBufferInfo(index, buffer));
    encoder->context_->outputCond_.notify_all();
}

int32_t VideoEncoder::SetCallback()
{
    int32_t ret = AV_ERR_OK;
    auto callback = make_shared<CallBack>(weak_from_this());
    ret = encoder_->SetCallback(callback);
    CHECK_ERROR_RETURN_RET_LOG(ret != AV_ERR_OK, 1, "Set callback failed, ret: %{public}d", ret);
    return 0;
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
    format.PutIntValue(MediaDescriptionKey::MD_KEY_VIDEO_ENCODE_BITRATE_MODE, VBR);
    format.PutLongValue(MediaDescriptionKey::MD_KEY_BITRATE, bitrate_);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_PIXEL_FORMAT, VIDOE_PIXEL_FORMAT);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_I_FRAME_INTERVAL, INT_MAX);
    int ret = encoder_->Configure(format);
    CHECK_ERROR_RETURN_RET_LOG(ret != AV_ERR_OK, 1, "Config failed, ret: %{public}d", ret);
    return 0;
}
} // CameraStandard
} // OHOS