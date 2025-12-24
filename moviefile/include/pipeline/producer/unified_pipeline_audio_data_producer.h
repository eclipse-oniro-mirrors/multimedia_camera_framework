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

#ifndef OHOS_UNIFIED_PIPELINE_AUDIO_DATA_PRODUCER_H
#define OHOS_UNIFIED_PIPELINE_AUDIO_DATA_PRODUCER_H

#include <memory>
#include <mutex>

#include "unified_pipeline_audio_capture_wrap.h"
#include "unified_pipeline_data_producer.h"

namespace OHOS {
namespace CameraStandard {
class UnifiedPipelineAudioDataProducer : public UnifiedPipelineDataProducer {
public:
    UnifiedPipelineAudioDataProducer();
    virtual ~UnifiedPipelineAudioDataProducer() override;

    // 此接口应在 UnifiedPipelineAudioDataProducer 实例创建后立即调用
    void InitBufferListener();

    std::weak_ptr<UnifiedPipelineAudioCaptureWrap::AudioCaptureBufferListener> GetAudioCaptureBufferListener();

private:
    class AudioCaptureBufferListenerImpl : public UnifiedPipelineAudioCaptureWrap::AudioCaptureBufferListener {
    public:
        AudioCaptureBufferListenerImpl(std::weak_ptr<UnifiedPipelineAudioDataProducer> dataProducer);

        void OnBufferStart() override;

        void OnBufferEnd() override;

        void OnBufferArrival(int64_t timestamp, std::unique_ptr<uint8_t[]> buffer, size_t bufferSize) override;

    private:
        std::weak_ptr<UnifiedPipelineAudioDataProducer> dataProducer_;
    };

protected:
    virtual std::unique_ptr<UnifiedPipelineBuffer> MakePipelineBuffer(
        int64_t timestamp, std::shared_ptr<uint8_t[]> buffer, size_t bufferSize) = 0;

private:
    std::shared_ptr<AudioCaptureBufferListenerImpl> audioCaptureBufferListener_ = nullptr;
};
} // namespace CameraStandard
} // namespace OHOS

#endif