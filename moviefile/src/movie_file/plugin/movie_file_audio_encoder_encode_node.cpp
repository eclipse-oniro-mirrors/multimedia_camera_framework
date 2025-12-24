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

#include "movie_file_audio_encoder_encode_node.h"

#include <array>
#include <memory>

#include "audio_stream_info.h"
#include "avcodec_audio_encoder.h"
#include "avcodec_errors.h"
#include "avcodec_info.h"
#include "camera_log.h"
#include "media_description.h"
#include "movie_file_common_utils.h"
#include "native_avbuffer.h"

namespace OHOS {
namespace CameraStandard {
using namespace MediaAVCodec;

MovieFileAudioEncoderEncodeNode::MovieFileAudioEncoderEncodeNodeEncoderCallback::
    MovieFileAudioEncoderEncodeNodeEncoderCallback(MovieFileAudioEncoderEncodeNode* encodeNode)
    : encodeNode_(encodeNode) {};

void MovieFileAudioEncoderEncodeNode::MovieFileAudioEncoderEncodeNodeEncoderCallback::OnInputBufferAvailable(
    uint32_t index, OH_AVBuffer* buffer)
{
    std::lock_guard<std::mutex> lock(encodeNodeMutex_);
    CHECK_RETURN(encodeNode_ == nullptr);
    encodeNode_->OnInputBufferAvailable(index, buffer);
}

void MovieFileAudioEncoderEncodeNode::MovieFileAudioEncoderEncodeNodeEncoderCallback::OnOutputBufferAvailable(
    uint32_t index, OH_AVBuffer* buffer)
{
    std::lock_guard<std::mutex> lock(encodeNodeMutex_);
    CHECK_RETURN(encodeNode_ == nullptr);
    encodeNode_->OnOutputBufferAvailable(index, buffer);
}

void MovieFileAudioEncoderEncodeNode::MovieFileAudioEncoderEncodeNodeEncoderCallback::Release()
{
    std::lock_guard<std::mutex> lock(encodeNodeMutex_);
    encodeNode_ = nullptr;
}

void MovieFileAudioEncoderEncodeNode::AudioCallbackOnError(OH_AVCodec* codec, int32_t errorCode, void* userData) {}
void MovieFileAudioEncoderEncodeNode::AudioCallbackAVCodecOnStreamChanged(
    OH_AVCodec* codec, OH_AVFormat* format, void* userData)
{}

void MovieFileAudioEncoderEncodeNode::AudioCallbackAVCodecOnNeedInputBuffer(
    OH_AVCodec* codec, uint32_t index, OH_AVBuffer* buffer, void* userData)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("AudioCallbackAVCodecOnNeedInputBuffer %{public}d", index);
    CHECK_RETURN(userData == nullptr);
    (void)codec;
    auto innerCallback = static_cast<MovieFileAudioEncoderEncodeNodeEncoderCallback*>(userData);
    innerCallback->OnInputBufferAvailable(index, buffer);
}

void MovieFileAudioEncoderEncodeNode::AudioCallbackAVCodecOnNewOutputBuffer(
    OH_AVCodec* codec, uint32_t index, OH_AVBuffer* buffer, void* userData)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("AudioCallbackAVCodecOnNewOutputBuffer %{public}d", index);
    (void)codec;
    CHECK_RETURN(userData == nullptr);
    auto innerCallback = static_cast<MovieFileAudioEncoderEncodeNodeEncoderCallback*>(userData);
    innerCallback->OnOutputBufferAvailable(index, buffer);
}

uint32_t GetSampleFormatByteSize(uint32_t sampleFormat)
{
    switch (sampleFormat) {
        case SAMPLE_U8:
        case SAMPLE_U8P:
            return 1;
        case SAMPLE_S16LE:
        case SAMPLE_S16P:
            return 2;
        case SAMPLE_S24LE:
        case SAMPLE_S24P:
            return 3;
        case SAMPLE_S32LE:
        case SAMPLE_F32LE:
        case SAMPLE_S32P:
        case SAMPLE_F32P:
            return 4;
        default:
            return 2;
    }
}

MovieFileAudioEncoderEncodeNode::MovieFileAudioEncoderEncodeNode(EncodeConfig& encodeConfig)
{
    int32_t oneFrameSize = encodeConfig.sampleRate / MOVIE_FILE_AUDIO_ONE_THOUSAND * encodeConfig.channelCount *
                           static_cast<int32_t>(GetSampleFormatByteSize(encodeConfig.sampleFormat)) *
                           MOVIE_FILE_AUDIO_DURATION_EACH_AUDIO_FRAME;
    MEDIA_INFO_LOG("MovieFileAudioEncoderEncodeNode encodeConfig: channelCount:%{public}d "
                   "channelLayout:%{public}" PRId64 " sampleRate:%{public}d sampleFormat:%{public}d "
                   "bitRate:%{public}" PRId64 " oneFrameSize:%{public}d profile:%{public}d",
        encodeConfig.channelCount, encodeConfig.channelLayout, encodeConfig.sampleRate, encodeConfig.sampleFormat,
        encodeConfig.bitRate, oneFrameSize, encodeConfig.profile);
    encoder_ = OH_AudioCodec_CreateByMime(CodecMimeType::AUDIO_AAC.data(), true);
    CHECK_RETURN_ELOG(!encoder_, "MovieFileAudioEncoderEncodeNode create encoder fail");

    OH_AVFormat* format = OH_AVFormat_Create();
    CHECK_RETURN_ELOG(format == nullptr, "MovieFileAudioEncoderEncodeNode AVFormat create failed");

    // 编码器对 Layout 的处理有bug，这里不进行设置
    OH_AVFormat_SetIntValue(format, OH_MD_KEY_AUD_CHANNEL_COUNT, encodeConfig.channelCount);
    OH_AVFormat_SetIntValue(format, OH_MD_KEY_AUD_SAMPLE_RATE, encodeConfig.sampleRate);
    OH_AVFormat_SetIntValue(format, OH_MD_KEY_AUDIO_SAMPLE_FORMAT, encodeConfig.sampleFormat);
    OH_AVFormat_SetLongValue(format, OH_MD_KEY_BITRATE, encodeConfig.bitRate);
    OH_AVFormat_SetIntValue(format, OH_MD_KEY_MAX_INPUT_SIZE, oneFrameSize);
    OH_AVFormat_SetIntValue(format, OH_MD_KEY_PROFILE, encodeConfig.profile);

    int ret = OH_AudioCodec_Configure(encoder_, format);
    OH_AVFormat_Destroy(format);
    CHECK_RETURN_ELOG(ret != AV_ERR_OK, "MovieFileAudioEncoderEncodeNode config failed, ret: %{public}d", ret);

    encoderCallback_ = std::make_shared<MovieFileAudioEncoderEncodeNodeEncoderCallback>(this);

    ret = OH_AudioCodec_RegisterCallback(encoder_,
        { .onError = AudioCallbackOnError,
            .onStreamChanged = AudioCallbackAVCodecOnStreamChanged,
            .onNeedInputBuffer = AudioCallbackAVCodecOnNeedInputBuffer,
            .onNewOutputBuffer = AudioCallbackAVCodecOnNewOutputBuffer },
        static_cast<void*>(encoderCallback_.get()));
    CHECK_RETURN_ELOG(ret != AV_ERR_OK, "MovieFileAudioEncoderEncodeNode set callback failed, ret: %{public}d", ret);

    // Prepare audio encoder
    ret = OH_AudioCodec_Prepare(encoder_);
    CHECK_RETURN_ELOG(ret != AV_ERR_OK, "MovieFileAudioEncoderEncodeNode prepare failed, ret: %{public}d", ret);
}

MovieFileAudioEncoderEncodeNode::~MovieFileAudioEncoderEncodeNode()
{
    if (encoderCallback_) {
        encoderCallback_->Release();
    }
    if (encoder_) {
        OH_AudioCodec_Destroy(encoder_);
    }
}

std::unique_ptr<UnifiedPipelineAudioPackagedEncodedBuffer> MovieFileAudioEncoderEncodeNode::ProcessBuffer(
    std::unique_ptr<UnifiedPipelineAudioPackagedBuffer> bufferIn)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!bufferIn || !encoder_, nullptr,
        "MovieFileAudioEncoderEncodeNode ProcessBuffer bufferIn is null or encoder_ is null");
    auto packagedAudioBufferData = bufferIn->UnwrapData();

    AVEncoderedPackagedOH_AVBufferInfo packagedAVBufferInfo {};
    for (auto& bufferData : packagedAudioBufferData.bufferDatas) {
        MEDIA_DEBUG_LOG("MovieFileAudioEncoderEncodeNode::ProcessBuffer pts:%{public}" PRIi64, bufferData.timestamp);
        CHECK_RETURN_RET_ELOG(!EnqueueBuffer(bufferData.data.get(), bufferData.dataSize, bufferData.timestamp), nullptr,
            "MovieFileAudioEncoderEncodeNode::ProcessBuffer EnqueueBuffer fail");
        packagedAVBufferInfo.infos.splice(packagedAVBufferInfo.infos.end(), DequeueBuffer(bufferData.timestamp));
    }

    auto returnBufferType = bufferIn->GetBufferType() == BufferType::CAMERA_AUDIO_PACKAGED_RAW_BUFFER
                                ? BufferType::CAMERA_AUDIO_PACKAGED_ENCODED_RAW_BUFFER
                                : BufferType::CAMERA_AUDIO_PACKAGED_ENCODED_BUFFER;

    auto returnBuffer = std::make_unique<UnifiedPipelineAudioPackagedEncodedBuffer>(returnBufferType);
    returnBuffer->WrapData(packagedAVBufferInfo);
    returnBuffer->SetBufferMemoryReleaser([](AVEncoderedPackagedOH_AVBufferInfo* packagedInfo) {
        MEDIA_DEBUG_LOG("MovieFileAudioEncoderEncodeNode::ProcessBuffer encodedBuffer release");
        for (auto& bufferInfo : packagedInfo->infos) {
            OH_AVBuffer_Destroy(bufferInfo.buffer);
        }
    });
    return returnBuffer;
};

void MovieFileAudioEncoderEncodeNode::ProcessCommand(UnifiedPipelineCommand* command)
{
    CHECK_RETURN(command == nullptr || command->IsConsumed());
    CHECK_RETURN(encoder_ == nullptr);
    if (command->GetCommandId() == UnifiedPipelineCommandId::AUDIO_BUFFER_START) {
        std::unique_lock<std::mutex> lock(outputMutex_);
        for (auto& avEncoderOutBufferInfo : avEncoderOutBufferInfos_) {
            OH_AudioCodec_FreeOutputBuffer(encoder_, avEncoderOutBufferInfo->index);
        }
        avEncoderOutBufferInfos_.clear();
        ResetBaseTimestamp();
        OH_AudioCodec_Start(encoder_);
    } else if (command->GetCommandId() == UnifiedPipelineCommandId::AUDIO_BUFFER_END) {
        OH_AudioCodec_Flush(encoder_);
        {
            std::unique_lock<std::mutex> lock(inputMutex_);
            avEncoderInBufferInfos_.clear();
        }
    }
}

bool MovieFileAudioEncoderEncodeNode::EnqueueBuffer(uint8_t* srcBufferAddr, size_t srcBufferSize, int64_t timestamp)
{
    MEDIA_DEBUG_LOG("MovieFileAudioEncoderEncodeNode::EnqueueBuffer enter");
    int enqueueRetryCount = MOVIE_FILE_AUDIO_INPUT_RETRY_TIMES;
    while (enqueueRetryCount > 0) {
        enqueueRetryCount--;
        std::unique_lock<std::mutex> lock(inputMutex_);
        if (avEncoderInBufferInfos_.empty()) {
            inputCond_.wait_for(lock, std::chrono::milliseconds(MOVIE_FILE_AUDIO_ENCODE_EXPIRATION_TIME),
                [this]() { return !avEncoderInBufferInfos_.empty(); });
            CHECK_CONTINUE(avEncoderInBufferInfos_.empty());
        }

        std::shared_ptr<AVEncoderOH_AVBufferInfo> avEncoderInBufferInfo = avEncoderInBufferInfos_.front();
        avEncoderInBufferInfos_.pop_front();

        int32_t codecCap = OH_AVBuffer_GetCapacity(avEncoderInBufferInfo->buffer);
        if (codecCap < static_cast<int32_t>(srcBufferSize)) {
            enqueueRetryCount++; // 移除无效buffer，不消耗重试次数
            continue;
        }

        // 把原始音频数据内存复制到编码器buffer中
        auto codecAddr = OH_AVBuffer_GetAddr(avEncoderInBufferInfo->buffer);

        errno_t cpyRet = memcpy_s(codecAddr, codecCap, srcBufferAddr, srcBufferSize);
        CHECK_RETURN_RET_ELOG(cpyRet != 0, false,
            "EnqueueBuffer encoder memcpy_s failed. %{public}d  srcBufferSize:%{public}zu"
            " codecCap:%{public}d",
            cpyRet, srcBufferSize, codecCap);

        MEDIA_DEBUG_LOG("MovieFileAudioEncoderEncodeNode::EnqueueBuffer timpStamp:%{public}" PRIi64
                       " bufferSize:%{public}zu",
            timestamp, srcBufferSize);

        // 使用编码器进行编码
        OH_AVCodecBufferAttr attr {
            .pts = timestamp, .size = srcBufferSize, .offset = 0, .flags = AVCODEC_BUFFER_FLAGS_NONE
        };
        int32_t ret = OH_AVBuffer_SetBufferAttr(avEncoderInBufferInfo->buffer, &attr);
        CHECK_CONTINUE_WLOG(ret != AV_ERR_OK, "Set avbuffer attr failed, ret: %{public}d", ret);
        ret = OH_AudioCodec_PushInputBuffer(encoder_, avEncoderInBufferInfo->index);
        CHECK_CONTINUE_WLOG(ret != AV_ERR_OK, "Push input data failed, ret: %{public}d", ret);
        UpdateBaseTimestampIfNessary(timestamp);
        avEncoderInBufferInfo = nullptr;
        MEDIA_DEBUG_LOG("MovieFileAudioEncoderEncodeNode::EnqueueBuffer done");
        return true;
    }
    MEDIA_WARNING_LOG("MovieFileAudioEncoderEncodeNode::EnqueueBuffer reach max retry");
    return false;
}

std::list<AVEncoderOH_AVBufferInfo> MovieFileAudioEncoderEncodeNode::DequeueBuffer(int64_t timestamp)
{
    MEDIA_DEBUG_LOG("MovieFileAudioEncoderEncodeNode::DequeueBuffer enter");
    int retryCount = MOVIE_FILE_AUDIO_OUTPUT_RETRY_TIMES;
    while (retryCount > 0) {
        retryCount--;
        std::unique_lock<std::mutex> lock(outputMutex_);
        if (avEncoderOutBufferInfos_.empty()) {
            outputCond_.wait_for(lock, std::chrono::milliseconds(MOVIE_FILE_AUDIO_ENCODE_EXPIRATION_TIME),
                [this]() { return !avEncoderOutBufferInfos_.empty(); });
            CHECK_CONTINUE(avEncoderOutBufferInfos_.empty());
        }

        std::list<AVEncoderOH_AVBufferInfo> returnBuffers = {};
        for (auto& avEncoderOutBufferInfo : avEncoderOutBufferInfos_) {
            OH_AVBuffer* audioBuffer = avEncoderOutBufferInfo->buffer;

            // 内存进行深拷贝
            OH_AVCodecBufferAttr attr = { 0, 0, 0, AVCODEC_BUFFER_FLAGS_NONE };
            OH_AVBuffer_GetBufferAttr(audioBuffer, &attr);
            MEDIA_DEBUG_LOG("DequeueBuffer OH_AVBuffer_Create with size: %{public}d", attr.size);
            OH_AVBuffer* destBuffer = OH_AVBuffer_Create(attr.size);
            CHECK_RETURN_RET_ELOG(destBuffer == nullptr, {}, "destBuffer is null");
            auto sourceAddr = OH_AVBuffer_GetAddr(audioBuffer);
            auto destAddr = OH_AVBuffer_GetAddr(destBuffer);
            errno_t cpyRet = memcpy_s(destAddr, attr.size, sourceAddr, attr.size);
            CHECK_PRINT_ELOG(cpyRet != 0, "DequeueBuffer memcpy_s failed. %{public}d", cpyRet);

            // 归还编码器内存
            int32_t ret = OH_AudioCodec_FreeOutputBuffer(encoder_, avEncoderOutBufferInfo->index);
            CHECK_PRINT_ELOG(
                ret != AV_ERR_OK, "DequeueBuffer FreeOutputBuffer output data failed, ret: %{public}d", ret);

            auto outBufferPts = attr.pts;
            auto baseTimestamp = GetBaseTimestamp();
            attr.pts = outBufferPts + baseTimestamp;
            OH_AVErrCode errorCode = OH_AVBuffer_SetBufferAttr(destBuffer, &attr);
            CHECK_PRINT_ELOG(errorCode != 0, "DequeueBuffer OH_AVBuffer_SetBufferAttr failed. %{public}d", errorCode);
            MEDIA_DEBUG_LOG("MovieFileAudioEncoderEncodeNode::DequeueBuffer done. outbufferPtr:%{public}" PRIi64
                            " baseTimestamp:%{public}" PRIi64 " attr.ptr %{public}" PRIi64
                            " timestamp:%{public}" PRIi64,
                outBufferPts, baseTimestamp, attr.pts, timestamp);
            returnBuffers.emplace_back(
                AVEncoderOH_AVBufferInfo { .buffer = destBuffer, .timestamp = attr.pts, .size = attr.size });
        }
        avEncoderOutBufferInfos_.clear();
        return returnBuffers;
    }
    MEDIA_ERR_LOG("DequeueBuffer failed");
    return {};
};

void MovieFileAudioEncoderEncodeNode::OnInputBufferAvailable(uint32_t index, OH_AVBuffer* buffer)
{
    std::unique_lock<std::mutex> lock(inputMutex_);
    avEncoderInBufferInfos_.emplace_back(
        std::make_shared<AVEncoderOH_AVBufferInfo>(AVEncoderOH_AVBufferInfo { .index = index, .buffer = buffer }));
    inputCond_.notify_all();
}

void MovieFileAudioEncoderEncodeNode::OnOutputBufferAvailable(uint32_t index, OH_AVBuffer* buffer)
{
    std::unique_lock<std::mutex> lock(outputMutex_);
    avEncoderOutBufferInfos_.emplace_back(
        std::make_shared<AVEncoderOH_AVBufferInfo>(AVEncoderOH_AVBufferInfo { .index = index, .buffer = buffer }));
    outputCond_.notify_all();
}

} // namespace CameraStandard
} // namespace OHOS
