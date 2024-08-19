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
#include "sample_callback.h"
#include "camera_log.h"
#include <chrono>
#include <fcntl.h>
#include <cinttypes>
#include <unistd.h>
#include <memory>
#include <sync_fence.h>
#include "surface_utils.h"
#include <cinttypes>

namespace OHOS {
namespace CameraStandard {

VideoEncoder::VideoEncoder()
{
    MEDIA_INFO_LOG("VideoEncoder enter");
    keyFrameInterval_ = KEY_FRMAE_INTERVAL;
}

VideoEncoder::~VideoEncoder()
{
    MEDIA_INFO_LOG("~VideoEncoder enter");
    Release();
}

int32_t VideoEncoder::Create(const std::string &codecMime)
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    encoder_ = OH_VideoEncoder_CreateByMime(codecMime.data());
    CHECK_AND_RETURN_RET_LOG(encoder_ != nullptr, 1, "Create failed");
    return 0;
}

int32_t VideoEncoder::Config()
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_AND_RETURN_RET_LOG(encoder_ != nullptr, 1, "Encoder is null");
    std::unique_lock<std::mutex> contextLock(contextMutex_);
    context_ = new CodecUserData;
    // Configure video encoder
    int32_t ret = Configure();
    CHECK_AND_RETURN_RET_LOG(ret == 0, 1, "Configure failed");
    // SetCallback for video encoder
    ret = SetCallback(context_);
    CHECK_AND_RETURN_RET_LOG(ret == 0, 1, "Set callback failed");
    contextLock.unlock();
    return 0;
}

int32_t VideoEncoder::Start()
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_AND_RETURN_RET_LOG(encoder_ != nullptr, 1, "Encoder is null");
     // Prepare video encoder
    int ret = OH_VideoEncoder_Prepare(encoder_);
    CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, 1, "Prepare failed, ret: %{public}d", ret);
    // Start video encoder
    ret = OH_VideoEncoder_Start(encoder_);
    CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, 1, "Start failed, ret: %{public}d", ret);
    isStarted_ = true;
    return 0;
}

int32_t VideoEncoder::GetSurface()
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    OHNativeWindow *nativeWindow;
    CHECK_AND_RETURN_RET_LOG(encoder_ != nullptr, 1, "Encoder is null");
    int ret = OH_VideoEncoder_GetSurface(encoder_, &nativeWindow);
    CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, 1, "Get surface failed, ret: %{public}d", ret);
    uint64_t  surfaceId;
    ret = OH_NativeWindow_GetSurfaceId(nativeWindow, &surfaceId);
    CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, 1, "Get surfaceId failed, ret: %{public}d", ret);
    sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(surfaceId);
    CHECK_AND_RETURN_RET_LOG(surface != nullptr, 1, "Surface is null");
    surfaceMutex_.lock();
    codecSurface_ = surface;
    surfaceMutex_.unlock();
    return 0;
}

int32_t VideoEncoder::ReleaseSurfaceBuffer(sptr<FrameRecord> frameRecord)
{
    CHECK_AND_RETURN_RET_LOG(frameRecord->GetSurfaceBuffer() != nullptr, 1,
        "SurfaceBuffer is released %{public}s", frameRecord->GetFrameId().c_str());
    sptr<SyncFence> syncFence = SyncFence::INVALID_FENCE;
    BufferRequestConfig requestConfig = {
        .width = frameRecord->GetSurfaceBuffer()->GetWidth(),
        .height = frameRecord->GetSurfaceBuffer()->GetHeight(),
        .strideAlignment = 0x8, // default stride is 8 Bytes.
        .format = frameRecord->GetSurfaceBuffer()->GetFormat(),
        .usage = frameRecord->GetSurfaceBuffer()->GetUsage(),
        .timeout = 0,
    };
    sptr<SurfaceBuffer> releaseBuffer;
    {
        std::lock_guard<std::mutex> lock(surfaceMutex_);
        CHECK_AND_RETURN_RET_LOG(codecSurface_ != nullptr, 1, "codecSurface_ is null");
        SurfaceError ret = codecSurface_->RequestBuffer(releaseBuffer, syncFence, requestConfig);
        if (ret != SURFACE_ERROR_OK) {
            MEDIA_ERR_LOG("RequestBuffer failed. %{public}d", ret);
            return ret;
        }
        constexpr uint32_t waitForEver = -1;
        (void)syncFence->Wait(waitForEver);

        if (!releaseBuffer) {
            MEDIA_ERR_LOG("Failed to requestBuffer, %{public}s", frameRecord->GetFrameId().c_str());
            return ret;
        }
        ret = codecSurface_->DetachBufferFromQueue(releaseBuffer);
        if (ret != SURFACE_ERROR_OK) {
            MEDIA_ERR_LOG("Failed to detach buffer");
            return ret;
        }
    }
    frameRecord->SetSurfaceBuffer(releaseBuffer);
    // after request surfaceBuffer
    frameRecord->NotifyBufferRelease();
    MEDIA_INFO_LOG("release codec surface buffer end");
    return 0;
}

int32_t VideoEncoder::PushInputData(sptr<CodecAVBufferInfo> info)
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_AND_RETURN_RET_LOG(encoder_ != nullptr, 1, "Decoder is null");
    int32_t ret = AV_ERR_OK;
    ret = OH_AVBuffer_SetBufferAttr(info->buffer, &info->attr);
    CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, 1, "Set avbuffer attr failed, ret: %{public}d", ret);
    ret = OH_VideoEncoder_PushInputBuffer(encoder_, info->bufferIndex);
    CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, 1, "Push input data failed, ret: %{public}d", ret);
    return 0;
}

int32_t VideoEncoder::NotifyEndOfStream()
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_AND_RETURN_RET_LOG(encoder_ != nullptr, 1, "Encoder is null");
    int32_t ret = OH_VideoEncoder_NotifyEndOfStream(encoder_);
    CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, 1,
        "Notify end of stream failed, ret: %{public}d", ret);
    return 0;
}

int32_t VideoEncoder::FreeOutputData(uint32_t bufferIndex)
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_AND_RETURN_RET_LOG(encoder_ != nullptr, 1, "Encoder is null");
    int32_t ret = OH_VideoEncoder_FreeOutputBuffer(encoder_, bufferIndex);
    CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, 1,
        "Free output data failed, ret: %{public}d", ret);
    return 0;
}

int32_t VideoEncoder::Stop()
{
    std::lock_guard<std::mutex> lock(encoderMutex_);
    CHECK_AND_RETURN_RET_LOG(encoder_ != nullptr, 1, "Encoder is null");
    int ret = OH_VideoEncoder_Flush(encoder_);
    CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, 1, "Flush failed, ret: %{public}d", ret);
    ret = OH_VideoEncoder_Stop(encoder_);
    CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, 1, "Stop failed, ret: %{public}d", ret);
    isStarted_ = false;
    return 0;
}

void VideoEncoder::RestartVideoCodec(shared_ptr<Size> size, int32_t rotation)
{
    Release();
    size_ = size;
    rotation_ = rotation;
    Create(MIME_VIDEO_AVC.data());
    Config();
    GetSurface();
    Start();
}

bool VideoEncoder::EnqueueBuffer(sptr<FrameRecord> frameRecord, int32_t keyFrameInterval)
{
    if (!isStarted_ || encoder_ == nullptr || size_ == nullptr) {
        RestartVideoCodec(frameRecord->GetFrameSize(), frameRecord->GetRotation());
    }
    if (keyFrameInterval == KEY_FRMAE_INTERVAL) {
        std::lock_guard<std::mutex> lock(encoderMutex_);
        OH_AVFormat *format = OH_AVFormat_Create();
        OH_AVFormat_SetIntValue(format, OH_MD_KEY_REQUEST_I_FRAME, true);
        OH_VideoEncoder_SetParameter(encoder_, format);
        OH_AVFormat_Destroy(format);
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
    keyFrameInterval_ = (keyFrameInterval_ == 0 ? KEY_FRMAE_INTERVAL : keyFrameInterval_);
    if (!EnqueueBuffer(frameRecord, keyFrameInterval_)) {
        return false;
    }
    int32_t needRestoreNumber = (keyFrameInterval_ % KEY_FRMAE_INTERVAL == 0 ? IDR_FRAME_COUNT : 1);
    keyFrameInterval_--;
    int32_t retryCount = 10;
    while (retryCount > 0) {
        retryCount--;
        MEDIA_DEBUG_LOG("EncodeSurfaceBuffer needRestoreNumber %{public}d", needRestoreNumber);
        std::unique_lock<std::mutex> contextLock(contextMutex_);
        CHECK_AND_RETURN_RET_LOG(context_ != nullptr, false, "VideoEncoder has been released");
        std::unique_lock<std::mutex> lock(context_->outputMutex_);
        bool condRet = context_->outputCond_.wait_for(lock, std::chrono::milliseconds(BUFFER_ENCODE_EXPIREATION_TIME),
            [this]() { return !isStarted_ || !context_->outputBufferInfoQueue_.empty(); });
        CHECK_AND_CONTINUE_LOG(!context_->outputBufferInfoQueue_.empty(),
            "Buffer queue is empty, continue, cond ret: %{public}d", condRet);
        sptr<CodecAVBufferInfo> bufferInfo = context_->outputBufferInfoQueue_.front();
        MEDIA_INFO_LOG("Out buffer count: %{public}u, size: %{public}d, flag: %{public}u, pts:%{public}" PRId64,
            context_->outputFrameCount_, bufferInfo->attr.size, bufferInfo->attr.flags, bufferInfo->attr.pts);
        context_->outputBufferInfoQueue_.pop();
        context_->outputFrameCount_++;
        lock.unlock();
        contextLock.unlock();
        if (needRestoreNumber == IDR_FRAME_COUNT && bufferInfo->attr.flags == AVCODEC_BUFFER_FLAGS_CODEC_DATA) {
            // first return IDR frame
            OH_AVBuffer *IDRBuffer = bufferInfo->GetCopyAVBuffer();
            frameRecord->CacheBuffer(IDRBuffer);
            frameRecord->SetIDRProperty(true);
        } else if (needRestoreNumber == 1 && bufferInfo->attr.flags == AVCODEC_BUFFER_FLAGS_SYNC_FRAME) {
            // then return I frame
            OH_AVBuffer *tempBuffer = bufferInfo->AddCopyAVBuffer(frameRecord->encodedBuffer);
            if (tempBuffer != nullptr) {
                frameRecord->encodedBuffer = tempBuffer;
            }
        } else if (bufferInfo->attr.flags == AVCODEC_BUFFER_FLAGS_NONE) {
            // return P frame
            OH_AVBuffer *PBuffer = bufferInfo->GetCopyAVBuffer();
            frameRecord->CacheBuffer(PBuffer);
            frameRecord->SetIDRProperty(false);
        } else {
            MEDIA_ERR_LOG("Flag is not acceptted number: %{public}d", needRestoreNumber);
            int32_t ret = FreeOutputData(bufferInfo->bufferIndex);
            CHECK_AND_BREAK_LOG(ret == 0, "FreeOutputData failed");
            continue;
        }
        int32_t ret = FreeOutputData(bufferInfo->bufferIndex);
        CHECK_AND_BREAK_LOG(ret == 0, "FreeOutputData failed");
        if (--needRestoreNumber == 0) {
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
            OH_VideoEncoder_Destroy(encoder_);
            encoder_ = nullptr;
        }
    }
    std::unique_lock<std::mutex> contextLock(contextMutex_);
    if (context_ != nullptr) {
        delete context_;
        context_ = nullptr;
    }
    isStarted_ = false;
    return 0;
}

int32_t VideoEncoder::SetCallback(CodecUserData *codecUserData)
{
    int32_t ret = AV_ERR_OK;
    ret = OH_VideoEncoder_RegisterCallback(encoder_,
        {SampleCallback::OnCodecError, SampleCallback::OnCodecFormatChange,
         SampleCallback::OnNeedInputBuffer, SampleCallback::OnNewOutputBuffer}, codecUserData);
    CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, 1, "Set callback failed, ret: %{public}d", ret);
    return 0;
}

int32_t VideoEncoder::Configure()
{
    OH_AVFormat *format = OH_AVFormat_Create();
    CHECK_AND_RETURN_RET_LOG(format != nullptr, 1, "AVFormat create failed");

    OH_AVFormat_SetIntValue(format, OH_MD_KEY_WIDTH, size_->width);
    OH_AVFormat_SetIntValue(format, OH_MD_KEY_HEIGHT, size_->height);
    OH_AVFormat_SetIntValue(format, OH_MD_KEY_ROTATION, rotation_);
    OH_AVFormat_SetDoubleValue(format, OH_MD_KEY_FRAME_RATE, VIDOE_FRAME_RATE);
    OH_AVFormat_SetIntValue(format, OH_MD_KEY_VIDEO_ENCODE_BITRATE_MODE, CBR);
    OH_AVFormat_SetLongValue(format, OH_MD_KEY_BITRATE, BITRATE_30M);
    OH_AVFormat_SetIntValue(format, OH_MD_KEY_PIXEL_FORMAT, VIDOE_PIXEL_FORMAT);
    OH_AVFormat_SetIntValue(format, OH_MD_KEY_I_FRAME_INTERVAL, INT_MAX);

    int ret = OH_VideoEncoder_Configure(encoder_, format);
    OH_AVFormat_Destroy(format);
    format = nullptr;
    CHECK_AND_RETURN_RET_LOG(ret == AV_ERR_OK, 1, "Config failed, ret: %{public}d", ret);

    return 0;
}
} // CameraStandard
} // OHOS