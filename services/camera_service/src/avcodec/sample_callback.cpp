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

#include "sample_callback.h"
#include "sample_info.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
void SampleCallback::OnCodecError(OH_AVCodec *codec, int32_t errorCode, void *userData)
{
    (void)codec;
    (void)errorCode;
    (void)userData;
    MEDIA_ERR_LOG("On decoder error, error code: %{public}d", errorCode);
}

void SampleCallback::OnCodecFormatChange(OH_AVCodec *codec, OH_AVFormat *format, void *userData)
{
    if (userData == nullptr) {
        return;
    }
    (void)codec;
    MEDIA_ERR_LOG("OnCodecFormatChange");
}


void SampleCallback::OnNeedInputBuffer(OH_AVCodec *codec, uint32_t index, OH_AVBuffer *buffer, void *userData)
{
    MEDIA_WARNING_LOG("OnNeedInputBuffer");
    if (userData == nullptr) {
        return;
    }
    (void)codec;
    CodecUserData *codecUserData = static_cast<CodecUserData *>(userData);
    std::unique_lock<std::mutex> lock(codecUserData->inputMutex_);
    codecUserData->inputBufferInfoQueue_.emplace(new CodecAVBufferInfo(index, buffer));
    codecUserData->inputCond_.notify_all();
}

void SampleCallback::OnNewOutputBuffer(OH_AVCodec *codec, uint32_t index, OH_AVBuffer *buffer, void *userData)
{
    MEDIA_WARNING_LOG("OnNewOutputBuffer");
    (void)codec;
    if (userData == nullptr) {
        return;
    }
    CodecUserData *codecUserData = static_cast<CodecUserData *>(userData);
    std::unique_lock<std::mutex> lock(codecUserData->outputMutex_);
    codecUserData->outputBufferInfoQueue_.emplace(new CodecAVBufferInfo(index, buffer));
    codecUserData->outputCond_.notify_all();
}

void SampleCallback::OnOutputFormatChanged(OH_AVCodec *codec, OH_AVFormat *format, void *userData)
{
    (void)codec;
    (void)format;
    (void)userData;
    MEDIA_WARNING_LOG("OnOutputFormatChanged received");
}

void SampleCallback::OnInputBufferAvailable(OH_AVCodec *codec, uint32_t index, OH_AVBuffer *buffer, void *userData)
{
    MEDIA_WARNING_LOG("OnInputBufferAvailable %{public}d", index);
    if (userData == nullptr) {
        return;
    }
    (void)codec;
    sptr<CodecUserData> codecAudioData = static_cast<CodecUserData *>(userData);
    std::unique_lock<std::mutex> lock(codecAudioData->inputMutex_);
    codecAudioData->inputBufferInfoQueue_.emplace(new CodecAVBufferInfo(index, buffer));
    codecAudioData->inputCond_.notify_all();
}

void SampleCallback::OnOutputBufferAvailable(OH_AVCodec *codec, uint32_t index, OH_AVBuffer *buffer, void *userData)
{
    MEDIA_WARNING_LOG("OnOutputBufferAvailable");
    (void)codec;
    if (userData == nullptr) {
        return;
    }
    sptr<CodecUserData> codecAudioData = static_cast<CodecUserData *>(userData);
    std::unique_lock<std::mutex> lock(codecAudioData->outputMutex_);
    codecAudioData->outputBufferInfoQueue_.emplace(new CodecAVBufferInfo(index, buffer));
    codecAudioData->outputCond_.notify_all();
}
} // CameraStandard
} // OHOS