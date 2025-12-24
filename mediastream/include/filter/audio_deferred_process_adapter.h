/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_MEDIA_STREAM_AUDIO_DEFERRED_PROCESS_ADAPTER_H
#define OHOS_CAMERA_MEDIA_STREAM_AUDIO_DEFERRED_PROCESS_ADAPTER_H

#include "refbase.h"
#include "audio_capturer.h"
#include "audio_buffer_wrapper.h"
#include "audio_session_manager.h"
#include "offline_audio_effect_manager.h"
#include <cstdint>
#include <mutex>

namespace OHOS {
namespace CameraStandard {
using namespace AudioStandard;
class AudioDeferredProcessAdapter : public RefBase {
public:
    static constexpr int32_t ONE_THOUSAND = 1000;
    static constexpr int32_t DURATION_EACH_AUDIO_FRAME = 32;
    static constexpr int32_t PROCESS_BATCH_SIZE = 5;
    static constexpr int32_t MAX_INPUT_SIZE = 12288;
    static constexpr int32_t MAX_OUTPUT_SIZE = 2048;
    static constexpr int32_t MAX_BATCH_INPUT_SIZE = MAX_INPUT_SIZE * PROCESS_BATCH_SIZE;
    static constexpr int32_t MAX_BATCH_OUTPUT_SIZE = MAX_OUTPUT_SIZE * PROCESS_BATCH_SIZE;

    using InputArray = std::array<uint8_t, MAX_BATCH_INPUT_SIZE>;
    using OutputArray = std::array<uint8_t, MAX_BATCH_OUTPUT_SIZE>;

    explicit AudioDeferredProcessAdapter();
    ~AudioDeferredProcessAdapter();

    int32_t Init(const AudioStreamInfo& inputOptions, const AudioStreamInfo& outputOptions);
    uint32_t GetSingleInputSize();

    int32_t Process(vector<sptr<AudioBufferWrapper>>& audioRecords, vector<sptr<AudioBufferWrapper>>& processedRecords);
    void Release();

    static uint32_t CalculateBufferSize(const AudioStreamInfo& info);
private:
    void StoreOptions(const AudioStreamInfo& inputOptions, const AudioStreamInfo& outputOptions);
    int32_t GetOfflineEffectChain();
    int32_t ConfigOfflineAudioEffectChain();
    int32_t PrepareOfflineAudioEffectChain();
    int32_t GetMaxBufferSize();

    void EffectChainProcess(InputArray& inputArr, OutputArray& outputArr);
    void FadeOneBatch(OutputArray& outputArr);
    void ReturnToRecords(
        OutputArray& outputArr, vector<sptr<AudioBufferWrapper>>& processedRecords, uint32_t i, uint32_t batchSize);

    std::string chainName_ = "offline_record_algo";
    std::mutex mutex_;
    std::unique_ptr<OfflineAudioEffectManager> offlineAudioEffectManager_{nullptr};
    std::unique_ptr<OfflineAudioEffectChain> offlineEffectChain_{nullptr};
    AudioStreamInfo inputOptions_;
    AudioStreamInfo outputOptions_;
    uint32_t singleInputSize_{0};
    uint32_t singleOutputSize_{0};
};
} // CameraStandard
} // OHOS
#endif // OHOS_CAMERA_MEDIA_STREAM_AUDIO_DEFERRED_PROCESS_ADAPTER_H