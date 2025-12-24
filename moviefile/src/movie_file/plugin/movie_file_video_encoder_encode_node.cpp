/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "movie_file_video_encoder_encode_node.h"

#include <memory>

#include "avcodec_errors.h"
#include "avcodec_info.h"
#include "camera_log.h"
#include "media_description.h"
#include "movie_file_common_const.h"
#include "native_avcodec_audiocodec.h"
#include "sync_fence.h"

namespace OHOS {
namespace CameraStandard {
namespace {
constexpr int32_t ENCODER_SURFACE_MAX_QUEUE_SIZE = 16;

}
using namespace MediaAVCodec;
MovieFileVideoEncoderEncodeNode::MovieFileVideoEncoderEncodeNodeEncoderCallback::
    MovieFileVideoEncoderEncodeNodeEncoderCallback(MovieFileVideoEncoderEncodeNode* encodeNode)
    : encodeNode_(encodeNode) {};
MovieFileVideoEncoderEncodeNode::MovieFileVideoEncoderEncodeNodeEncoderCallback::
    ~MovieFileVideoEncoderEncodeNodeEncoderCallback()
{}
void MovieFileVideoEncoderEncodeNode::MovieFileVideoEncoderEncodeNodeEncoderCallback::OnError(
    AVCodecErrorType errorType, int32_t errorCode)
{}

void MovieFileVideoEncoderEncodeNode::MovieFileVideoEncoderEncodeNodeEncoderCallback::OnOutputFormatChanged(
    const Format& format)
{}

void MovieFileVideoEncoderEncodeNode::MovieFileVideoEncoderEncodeNodeEncoderCallback::OnInputBufferAvailable(
    uint32_t index, std::shared_ptr<AVBuffer> buffer)
{}

void MovieFileVideoEncoderEncodeNode::MovieFileVideoEncoderEncodeNodeEncoderCallback::OnOutputBufferAvailable(
    uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    std::lock_guard<std::mutex> lock(encodeNodeMutex_);
    if (!encodeNode_) {
        // 该是否需要处理buffer释放，需要经过测试验证
        return;
    }
    encodeNode_->OnOutputBufferAvailable(index, buffer);
}

void MovieFileVideoEncoderEncodeNode::MovieFileVideoEncoderEncodeNodeEncoderCallback::Release()
{
    std::lock_guard<std::mutex> lock(encodeNodeMutex_);
    encodeNode_ = nullptr;
}

MovieFileVideoEncoderEncodeNode::MovieFileVideoEncoderEncodeNode(VideoEncoderConfig& config)
{
    encoder_ = MediaAVCodec::VideoEncoderFactory::CreateByMime(config.mimeType);
    CHECK_RETURN_ELOG(!encoder_, "MovieFileVideoEncoderEncodeNode create encoder fail");
    // Config encoder
    MediaAVCodec::Format format = MediaAVCodec::Format();

    MEDIA_INFO_LOG("Current resolution is :%{public}d*%{public}d bitrate:%{public}d rotation:%{public}d "
        "isHdr:%{public}d mineType:%{public}s framerate:%{public}d isBFrame:%{public}d",
        config.width, config.height, config.videoBitrate, config.rotation, config.isHdr, config.mimeType.c_str(),
        config.frameRate, config.isBFrame);

    format.PutIntValue(MediaDescriptionKey::MD_KEY_WIDTH, config.width);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_HEIGHT, config.height);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_ROTATION_ANGLE, config.rotation);
    format.PutDoubleValue(MediaDescriptionKey::MD_KEY_FRAME_RATE, config.frameRate);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_VIDEO_ENCODE_BITRATE_MODE, SQR);
    format.PutLongValue(MediaDescriptionKey::MD_KEY_BITRATE, config.videoBitrate);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_PIXEL_FORMAT, AV_PIXEL_FORMAT_NV21);
    format.PutIntValue(MediaDescriptionKey::MD_KEY_REQUEST_I_FRAME, true);
    // hdr 必须配合 hevc 编码否则忽略 hdr
    if (config.isHdr && config.mimeType == std::string(CodecMimeType::VIDEO_HEVC)) {
        format.PutIntValue(MediaDescriptionKey::MD_KEY_PROFILE, HEVC_PROFILE_MAIN_10);
        format.PutIntValue(MediaDescriptionKey::MD_KEY_VIDEO_IS_HDR_VIVID, true);
    }
    if (config.isBFrame) {
        format.PutIntValue(Media::Tag::VIDEO_ENCODER_ENABLE_B_FRAME, config.isBFrame);
    }
    int ret = encoder_->Configure(format);
    CHECK_RETURN_ELOG(ret != AVCS_ERR_OK, "MovieFileVideoEncoderEncodeNode configure encoder fail:%{public}d", ret);

    encoderCallback_ = std::make_shared<MovieFileVideoEncoderEncodeNodeEncoderCallback>(this);
    ret = encoder_->SetCallback(encoderCallback_);
    CHECK_RETURN_ELOG(ret != AVCS_ERR_OK, "MovieFileVideoEncoderEncodeNode set callback failed, ret: %{public}d", ret);

    // GetSurface
    codecSurface_ = encoder_->CreateInputSurface();
    codecSurface_->SetQueueSize(ENCODER_SURFACE_MAX_QUEUE_SIZE);
    CHECK_RETURN_ELOG(
        !codecSurface_, "MovieFileVideoEncoderEncodeNode CreateInputSurface failed, ret: %{public}d", ret);

    // Prepare video encoder
    ret = encoder_->Prepare();
    CHECK_RETURN_ELOG(ret != AVCS_ERR_OK, "MovieFileVideoEncoderEncodeNode prepare failed, ret: %{public}d", ret);
    // Start video encoder
    ret = encoder_->Start();
    CHECK_RETURN_ELOG(ret != AVCS_ERR_OK, "MovieFileVideoEncoderEncodeNode start failed, ret: %{public}d", ret);
}

MovieFileVideoEncoderEncodeNode::~MovieFileVideoEncoderEncodeNode()
{
    MEDIA_INFO_LOG("MovieFileVideoEncoderEncodeNode::~MovieFileVideoEncoderEncodeNode");
    if (encoder_) {
        encoder_->NotifyEos();
    }
    if (encoderCallback_) {
        encoderCallback_->Release();
    }
    if (codecSurface_) {
        codecSurface_->CleanCache(true);
    }
    if (encoder_) {
        encoder_->Release();
    }
}

bool MovieFileVideoEncoderEncodeNode::AttachBuffer(PipelineSurfaceBufferData data)
{
    MEDIA_DEBUG_LOG("MovieFileVideoEncoderEncodeNode AttachBuffer");
    SurfaceError surfaceRet = codecSurface_->AttachBufferToQueue(data.surfaceBuffer);
    CHECK_RETURN_RET_ELOG(surfaceRet != SURFACE_ERROR_OK, false,
        "MovieFileVideoEncoderEncodeNode Failed to attach buffer, surfaceRet: %{public}d", surfaceRet);
    constexpr int32_t invalidFence = -1;
    BufferFlushConfig flushConfig = {
            .damage = {
                .w = data.surfaceBuffer->GetWidth(),
                .h = data.surfaceBuffer->GetHeight(),
            },
            .timestamp = data.timestamp
        };
    surfaceRet = codecSurface_->FlushBuffer(data.surfaceBuffer, invalidFence, flushConfig);

    MEDIA_DEBUG_LOG(
        "MovieFileVideoEncoderEncodeNode::AttachBuffer buffer size:%{public}d", data.surfaceBuffer->GetSize());

    CHECK_RETURN_RET_ELOG(surfaceRet != 0, false, "MovieFileVideoEncoderEncodeNode FlushBuffer failed");
    return true;
}

void MovieFileVideoEncoderEncodeNode::DetachBuffer(PipelineSurfaceBufferData data)
{
    auto inputSurfaceBuffer = data.surfaceBuffer;
    sptr<SyncFence> syncFence = SyncFence::INVALID_FENCE;
    BufferRequestConfig requestConfig = {
        .width = inputSurfaceBuffer->GetWidth(),
        .height = inputSurfaceBuffer->GetHeight(),
        .format = inputSurfaceBuffer->GetFormat(),
        .usage = inputSurfaceBuffer->GetUsage(),
        .timeout = 0,
        .colorGamut = inputSurfaceBuffer->GetSurfaceBufferColorGamut(),
        .transform = inputSurfaceBuffer->GetSurfaceBufferTransform(),
    };
    sptr<SurfaceBuffer> outBuffer; // 用于销毁，传出类型不用处理
    SurfaceError ret = codecSurface_->RequestBuffer(outBuffer, syncFence, requestConfig);
    CHECK_RETURN_ELOG(ret != SURFACE_ERROR_OK, "RequestBuffer failed. %{public}d", ret);
    constexpr uint32_t waitForEver = -1;
    syncFence->Wait(waitForEver);
    CHECK_RETURN_ELOG(outBuffer == nullptr, "Failed to request codec Buffer");
    ret = codecSurface_->DetachBufferFromQueue(outBuffer);

    MEDIA_DEBUG_LOG("MovieFileVideoEncoderEncodeNode::DetachBuffer buffer size:%{public}d", outBuffer->GetSize());
    CHECK_RETURN_ELOG(ret != SURFACE_ERROR_OK, "Failed to detach buffer %{public}d", ret);
}

void MovieFileVideoEncoderEncodeNode::HandleReceivedOutBuffers(
    std::list<std::shared_ptr<AVEncoderAVBufferInfo>>& receivedOutBuffers,
    std::list<std::shared_ptr<AVEncoderAVBufferInfo>>& receivedIDRBuffers,
    std::list<AVEncoderAVBufferInfo>& returnBuffers)
{
    for (auto& currentBuffer : receivedOutBuffers) {
        CHECK_CONTINUE_ELOG(currentBuffer == nullptr,
            "MovieFileVideoEncoderEncodeNode::HandleReceivedOutBuffers currentBuffer is null");
        MEDIA_DEBUG_LOG(
            "MovieFileVideoEncoderEncodeNode::HandleReceivedOutBuffers buffer flag:%{public}d pts:%{public}" PRIi64,
            currentBuffer->buffer->flag_, currentBuffer->buffer->pts_);
        auto avBuffer = currentBuffer->buffer;
        if (avBuffer->flag_ == AVCODEC_BUFFER_FLAGS_CODEC_DATA) {
            // 收到了IDR帧，需要等待 I 帧
            auto returnBuffer = CopyPipelineVideoEncodedBuffer(currentBuffer);
            returnBuffer->isIDRFrame = true;
            receivedIDRBuffers.emplace_back(returnBuffer);
        } else if (avBuffer->flag_ == AVCODEC_BUFFER_FLAGS_SYNC_FRAME) {
            // 收到了I帧
            if (!receivedIDRBuffers.empty()) {
                auto idrFrame = receivedIDRBuffers.front();
                receivedIDRBuffers.pop_front();
                auto result = AddCopyIDRBufferAVBuffer(idrFrame, currentBuffer);
                CHECK_RETURN_ELOG(result == nullptr, "AddCopyIDRBufferAVBuffer is null");
                returnBuffers.emplace_back(*result);
                MEDIA_DEBUG_LOG("MovieFileVideoEncoderEncodeNode::HandleReceivedOutBuffers buffer add copy idr buffer, "
                                "pts:%{public}" PRIi64,
                    returnBuffers.back().buffer->pts_);
            } else {
                returnBuffers.emplace_back(*CopyPipelineVideoEncodedBuffer(currentBuffer));
            }
        } else {
            returnBuffers.emplace_back(*CopyPipelineVideoEncodedBuffer(currentBuffer));
        }
        if (currentBuffer != nullptr) {
            ReleaseAVEncoderAVBuffer(*currentBuffer);
        }
    }
}

std::list<AVEncoderAVBufferInfo> MovieFileVideoEncoderEncodeNode::DequeueBuffer()
{
    // 编码器可能会输出多个buffer结果，这里进行循环处理
    std::list<AVEncoderAVBufferInfo> returnBuffers = {};
    std::list<std::shared_ptr<AVEncoderAVBufferInfo>> receivedIDROutBuffers = {};
    while (true) {
        std::list<std::shared_ptr<AVEncoderAVBufferInfo>> receivedOutBuffers = {};
        {
            // 以下代码在锁的范围内
            std::unique_lock<std::mutex> lock(outputMutex_);
            if (!receivedIDROutBuffers.empty() || GetPipelinePressure() <= 5) {
                bool isWakeUp =
                    outputCond_.wait_for(lock, std::chrono::milliseconds(MOVIE_FILE_BUFFER_ENCODE_WAIT_IFRAME_TIME),
                        [this]() { return !avEncoderOutBufferInfos_.empty(); });
                if (!isWakeUp && !receivedIDROutBuffers.empty()) {
                    // 等待I帧超时，清空所有IDR帧避免阻塞其他帧处理
                    receivedIDROutBuffers.clear();
                }
            }
            if (avEncoderOutBufferInfos_.empty()) {
                break;
            }
            receivedOutBuffers.splice(receivedOutBuffers.end(), avEncoderOutBufferInfos_);
        }
        HandleReceivedOutBuffers(receivedOutBuffers, receivedIDROutBuffers, returnBuffers);
    }
    return returnBuffers;
}

std::unique_ptr<UnifiedPipelineVideoEncodedBuffer> MovieFileVideoEncoderEncodeNode::ProcessBuffer(
    std::unique_ptr<UnifiedPipelineSurfaceBuffer> bufferIn)
{
    CHECK_RETURN_RET(!bufferIn || !encoder_ || !codecSurface_, nullptr);

    auto data = bufferIn->UnwrapData();

    if (requestIFrameCount_ < 5) { // 前5帧都请求I帧，避免丢帧后画面异常
        MediaAVCodec::Format format = MediaAVCodec::Format();
        format.PutIntValue(MediaDescriptionKey::MD_KEY_REQUEST_I_FRAME, true);
        encoder_->SetParameter(format);
        requestIFrameCount_++;
    }

    // 将buffer塞进编码器
    CHECK_RETURN_RET_ELOG(!AttachBuffer(data), nullptr, "AttachBuffer fail");
    AVEncoderPackagedAVBufferInfo returnPackagedBuffer = {};
    returnPackagedBuffer.infos.splice(returnPackagedBuffer.infos.end(), DequeueBuffer());

    // 清除编码器中塞入的buffer
    DetachBuffer(data);
    auto encodedBuffer =
        std::make_unique<UnifiedPipelineVideoEncodedBuffer>(BufferType::CAMERA_VIDEO_PACKAGED_ENCODED_BUFFER);
    encodedBuffer->WrapData(returnPackagedBuffer);
    return encodedBuffer;
}

std::shared_ptr<AVEncoderAVBufferInfo> MovieFileVideoEncoderEncodeNode::CopyPipelineVideoEncodedBuffer(
    std::shared_ptr<AVEncoderAVBufferInfo> bufferIn)
{
    std::shared_ptr<AVEncoderAVBufferInfo> newBuffer = std::make_shared<AVEncoderAVBufferInfo>(*bufferIn);
    newBuffer->buffer = CopyAVBuffer(bufferIn->buffer);
    return newBuffer;
}

void MovieFileVideoEncoderEncodeNode::ReleaseAVEncoderAVBuffer(AVEncoderAVBufferInfo& bufferIn)
{
    int32_t ret = encoder_->ReleaseOutputBuffer(bufferIn.index);
    CHECK_PRINT_ELOG(ret != AVCS_ERR_OK, "UnifiedPipelineVideoEncodedBuffer Release failed, ret: %{public}d", ret);
}

void MovieFileVideoEncoderEncodeNode::OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    MEDIA_DEBUG_LOG("MovieFileVideoEncoderEncodeNode OnOutputBufferAvailable memory size: %{public}d "
                   "flag:%{public}d timestamp:%{public}" PRIi64 " avEncoderOutBufferInfos_ size: %{public}zu",
        buffer->memory_->GetSize(), buffer->flag_, buffer->pts_, avEncoderOutBufferInfos_.size());
    std::unique_lock<std::mutex> lock(outputMutex_);
    avEncoderOutBufferInfos_.emplace_back(
        std::make_shared<AVEncoderAVBufferInfo>(AVEncoderAVBufferInfo { .index = index, .buffer = buffer }));
    outputCond_.notify_all();
}

std::shared_ptr<AVEncoderAVBufferInfo> MovieFileVideoEncoderEncodeNode::AddCopyIDRBufferAVBuffer(
    std::shared_ptr<AVEncoderAVBufferInfo> headBuffer, std::shared_ptr<AVEncoderAVBufferInfo> tailBuffer)
{
    auto IDRBuffer = headBuffer->buffer;
    auto buffer = tailBuffer->buffer;
    CHECK_RETURN_RET_ELOG(nullptr == IDRBuffer, headBuffer, "AddCopyAVBuffer without IDRBuffer!");
    int32_t destBufferSize = IDRBuffer->memory_->GetSize() + buffer->memory_->GetSize();
    auto allocator = Media::AVAllocatorFactory::CreateSharedAllocator(Media::MemoryFlag::MEMORY_READ_WRITE);
    CHECK_RETURN_RET_ELOG(allocator == nullptr, nullptr, "create allocator failed");
    std::shared_ptr<Media::AVBuffer> destBuffer = Media::AVBuffer::CreateAVBuffer(allocator, destBufferSize);
    CHECK_RETURN_RET_ELOG(destBuffer == nullptr, nullptr, "destBuffer is null");
    auto destAddr = destBuffer->memory_->GetAddr();
    auto sourceIDRAddr = IDRBuffer->memory_->GetAddr();
    errno_t cpyRet = memcpy_s(reinterpret_cast<void*>(destAddr), destBufferSize, reinterpret_cast<void*>(sourceIDRAddr),
        IDRBuffer->memory_->GetSize());
    CHECK_PRINT_ELOG(0 != cpyRet, "CodecBufferInfo memcpy_s IDR frame failed. %{public}d", cpyRet);
    destAddr = destAddr + IDRBuffer->memory_->GetSize();
    auto sourceAddr = buffer->memory_->GetAddr();
    cpyRet = memcpy_s(reinterpret_cast<void*>(destAddr), buffer->memory_->GetSize(),
        reinterpret_cast<void*>(sourceAddr), buffer->memory_->GetSize());
    CHECK_PRINT_ELOG(0 != cpyRet, "CodecBufferInfo memcpy_s I frame failed. %{public}d", cpyRet);
    destBuffer->memory_->SetSize(destBufferSize);
    destBuffer->flag_ = IDRBuffer->flag_ | buffer->flag_;
    destBuffer->pts_ = buffer->pts_;
    MEDIA_DEBUG_LOG("CodecBufferInfo copy with size: %{public}d, %{public}d", destBufferSize, destBuffer->flag_);

    auto returnBuffer = headBuffer;
    returnBuffer->buffer = destBuffer;
    returnBuffer->isIDRFrame = false;
    return returnBuffer;
}

std::shared_ptr<MediaAVCodec::AVBuffer> MovieFileVideoEncoderEncodeNode::CopyAVBuffer(
    std::shared_ptr<MediaAVCodec::AVBuffer> buffer)
{
    MEDIA_DEBUG_LOG("MovieFileVideoEncoderEncodeNode CopyAVBuffer memory size: %{public}d", buffer->memory_->GetSize());
    auto allocator = Media::AVAllocatorFactory::CreateSharedAllocator(Media::MemoryFlag::MEMORY_READ_WRITE);
    CHECK_RETURN_RET_ELOG(allocator == nullptr, nullptr, "create allocator failed");
    std::shared_ptr<Media::AVBuffer> destBuffer =
        Media::AVBuffer::CreateAVBuffer(allocator, buffer->memory_->GetCapacity());
    CHECK_RETURN_RET_ELOG(destBuffer == nullptr, nullptr, "destBuffer is null");
    auto sourceAddr = buffer->memory_->GetAddr();
    auto destAddr = destBuffer->memory_->GetAddr();
    errno_t cpyRet = memcpy_s(reinterpret_cast<void*>(destAddr), buffer->memory_->GetSize(),
        reinterpret_cast<void*>(sourceAddr), buffer->memory_->GetSize());
    CHECK_PRINT_ELOG(0 != cpyRet, "MovieFileVideoEncoderEncodeNode CopyAVBuffer memcpy_s failed. %{public}d", cpyRet);
    destBuffer->pts_ = buffer->pts_;
    destBuffer->flag_ = buffer->flag_;
    destBuffer->memory_->SetSize(buffer->memory_->GetSize());
    return destBuffer;
}
} // namespace CameraStandard
} // namespace OHOS