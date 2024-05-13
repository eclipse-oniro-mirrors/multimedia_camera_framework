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

#ifndef AVCODEC_SAMPLE_AUDIO_ENCODER_H
#define AVCODEC_SAMPLE_AUDIO_ENCODER_H

#include "native_avcodec_audiocodec.h"
#include "sample_info.h"
#include "audio_record.h"
#include <mutex>

namespace OHOS {
namespace CameraStandard {
class AudioEncoder {
public:
    AudioEncoder() = default;
    ~AudioEncoder();

    int32_t Create(const std::string &codecMime);
    int32_t Config();
    int32_t Start();
    bool EncodeAudioBuffer(vector<sptr<AudioRecord>> audioRecords);
    int32_t PushInputData(sptr<CodecAVBufferInfo> info);
    int32_t FreeOutputData(uint32_t bufferIndex);
    int32_t Stop();
    int32_t Release();

private:
    int32_t SetCallback(CodecUserData *codecAudioData);
    void RestartAudioCodec();
    int32_t Configure();
    bool EnqueueBuffer(sptr<AudioRecord> audioRecord);
    bool EncodeAudioBuffer(sptr<AudioRecord> audioRecord);
    std::atomic<bool> isStarted_ { false };
    std::mutex encoderMutex_;
    OH_AVCodec *encoder_ = nullptr;
    std::mutex contextMutex_;
    CodecUserData *context_ = nullptr;
    std::mutex serialMutex_;
};
} // CameraStandard
} // OHOS
#endif // AVCODEC_SAMPLE_AUDIO_ENCODER_H