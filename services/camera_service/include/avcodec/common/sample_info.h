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

#ifndef AVCODEC_SAMPLE_SAMPLE_INFO_H
#define AVCODEC_SAMPLE_SAMPLE_INFO_H
#include <cstdint>
#include <string>
#include <securec.h>
#include <condition_variable>
#include <queue>
#include "camera_log.h"
#include "native_avcodec_base.h"
#include "native_avbuffer.h"
#include "native_audio_channel_layout.h"
#include <refbase.h>

namespace OHOS {
namespace CameraStandard {
constexpr std::string_view MIME_VIDEO_AVC = "video/avc";
constexpr std::string_view MIME_VIDEO_HEVC = "video/hevc";

constexpr int32_t BITRATE_10M = 10 * 1024 * 1024; // 10Mbps
constexpr int32_t BITRATE_20M = 20 * 1024 * 1024; // 20Mbps
constexpr int32_t BITRATE_30M = 30 * 1024 * 1024; // 30Mbps
constexpr uint32_t DEFAULT_SAMPLERATE = 48000;
constexpr uint64_t DEFAULT_BITRATE = 48000;
constexpr uint32_t DEFAULT_CHANNEL_COUNT = 2;
constexpr OH_AudioChannelLayout CHANNEL_LAYOUT = OH_AudioChannelLayout::CH_LAYOUT_STEREO ;
constexpr OH_BitsPerSample SAMPLE_FORMAT = OH_BitsPerSample::SAMPLE_S16LE;
constexpr int32_t COMPLIANCE_LEVEL = 0;
constexpr OH_BitsPerSample BITS_PER_CODED_SAMPLE = OH_BitsPerSample::SAMPLE_S16LE;
constexpr uint32_t DEFAULT_MAX_INPUT_SIZE = 1024 * DEFAULT_CHANNEL_COUNT * sizeof(short);
constexpr int32_t VIDEO_FRAME_INTERVAL = 33333;
constexpr int32_t AUDIO_FRAME_INTERVAL = 21333;
constexpr double VIDOE_FRAME_RATE = 30.0;
constexpr int32_t CACHE_FRAME_COUNT = 45;
constexpr int32_t BUFFER_RELEASE_EXPIREATION_TIME = 150;
constexpr int32_t BUFFER_ENCODE_EXPIREATION_TIME = 10;
constexpr OH_AVPixelFormat VIDOE_PIXEL_FORMAT = AV_PIXEL_FORMAT_NV21;

class CodecAVBufferInfo : public RefBase {
public:
    explicit CodecAVBufferInfo(uint32_t argBufferIndex, OH_AVBuffer *argBuffer)
        : bufferIndex(argBufferIndex), buffer(argBuffer)
    {
        // get output buffer attr
        OH_AVBuffer_GetBufferAttr(argBuffer, &attr);
    };
    ~CodecAVBufferInfo() = default;
    uint32_t bufferIndex = 0;
    OH_AVBuffer *buffer = nullptr;
    OH_AVCodecBufferAttr attr = {0, 0, 0, AVCODEC_BUFFER_FLAGS_NONE};

    OH_AVBuffer *GetCopyAVBuffer()
    {
        int32_t capacity = OH_AVBuffer_GetCapacity(buffer);
        MEDIA_INFO_LOG("CodecBufferInfo deep copy enter %{public}d", capacity);
        OH_AVBuffer *destBuffer = OH_AVBuffer_Create(capacity);
        auto sourceAddr = OH_AVBuffer_GetAddr(buffer);
        auto destAddr = OH_AVBuffer_GetAddr(destBuffer);
        errno_t cpyRet = memcpy_s(reinterpret_cast<void *>(destAddr), capacity,
                                  reinterpret_cast<void *>(sourceAddr), attr.size);
        if (cpyRet != 0) {
            MEDIA_ERR_LOG("CodecBufferInfo memcpy_s failed. %{public}d", cpyRet);
        }
        OH_AVErrCode errorCode = OH_AVBuffer_SetBufferAttr(destBuffer, &attr);
        if (errorCode != 0) {
            MEDIA_ERR_LOG("CodecBufferInfo OH_AVBuffer_SetBufferAttr failed. %{public}d", errorCode);
        }
        return destBuffer;
    }

    void AddCopyAVBuffer(OH_AVBuffer *IDRBuffer)
    {
        if (IDRBuffer == nullptr) {
            return;
        }
        int32_t capacity = OH_AVBuffer_GetCapacity(buffer);
        MEDIA_INFO_LOG("CodecBufferInfo deep copy enter %{public}d", capacity);
        OH_AVCodecBufferAttr destAttr = {0, 0, 0, AVCODEC_BUFFER_FLAGS_NONE};
        OH_AVBuffer_GetBufferAttr(IDRBuffer, &destAttr);
        auto sourceAddr = OH_AVBuffer_GetAddr(buffer);
        auto destAddr = OH_AVBuffer_GetAddr(IDRBuffer) + destAttr.size;
        errno_t cpyRet = memcpy_s(reinterpret_cast<void *>(destAddr), capacity,
                                  reinterpret_cast<void *>(sourceAddr), attr.size);
        if (cpyRet != 0) {
            MEDIA_ERR_LOG("CodecBufferInfo memcpy_s failed. %{public}d", cpyRet);
        }
        destAttr.size = destAttr.size + attr.size;
        destAttr.flags &= attr.flags;
        OH_AVBuffer_SetBufferAttr(IDRBuffer, &destAttr);
    }
};

class CodecUserData : public RefBase {
public:
    CodecUserData() = default;
    ~CodecUserData()
    {
        inputMutex_.lock();
        while (!inputBufferInfoQueue_.empty()) {
            inputBufferInfoQueue_.pop();
        }
        inputMutex_.unlock();
        outputMutex_.lock();
        while (!outputBufferInfoQueue_.empty()) {
            outputBufferInfoQueue_.pop();
        }
        outputMutex_.unlock();
    };
    uint32_t inputFrameCount_ = 0;
    std::mutex inputMutex_;
    std::condition_variable inputCond_;
    std::queue<sptr<CodecAVBufferInfo>> inputBufferInfoQueue_;

    uint32_t outputFrameCount_ = 0;
    std::mutex outputMutex_;
    std::condition_variable outputCond_;
    std::queue<sptr<CodecAVBufferInfo>> outputBufferInfoQueue_;
};
} // CameraStandard
} // OHOS
#endif // AVCODEC_SAMPLE_SAMPLE_INFO_H