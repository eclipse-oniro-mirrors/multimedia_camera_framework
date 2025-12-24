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

#include "unified_pipeline_audio_data_producer.h"

#include <thread>

#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
UnifiedPipelineAudioDataProducer::UnifiedPipelineAudioDataProducer() : UnifiedPipelineDataProducer()
{
    MEDIA_INFO_LOG("UnifiedPipelineAudioDataProducer construct");
}

UnifiedPipelineAudioDataProducer::~UnifiedPipelineAudioDataProducer()
{
    MEDIA_INFO_LOG("UnifiedPipelineAudioDataProducer::~UnifiedPipelineAudioDataProducer");
}

void UnifiedPipelineAudioDataProducer::InitBufferListener()
{
    audioCaptureBufferListener_ = std::make_shared<AudioCaptureBufferListenerImpl>(
        std::static_pointer_cast<UnifiedPipelineAudioDataProducer>(shared_from_this()));
}

UnifiedPipelineAudioDataProducer::AudioCaptureBufferListenerImpl::AudioCaptureBufferListenerImpl(
    std::weak_ptr<UnifiedPipelineAudioDataProducer> dataProducer)
    : dataProducer_(dataProducer)
{}

void UnifiedPipelineAudioDataProducer::AudioCaptureBufferListenerImpl::OnBufferStart()
{
    auto dataProducer = dataProducer_.lock();
    CHECK_RETURN(!dataProducer);
    dataProducer->OnCommandArrival(
        std::make_unique<UnifiedPipelineCommand>(UnifiedPipelineCommandId::AUDIO_BUFFER_START, nullptr));
}

void UnifiedPipelineAudioDataProducer::AudioCaptureBufferListenerImpl::OnBufferEnd()
{
    auto dataProducer = dataProducer_.lock();
    CHECK_RETURN(!dataProducer);
    dataProducer->OnCommandArrival(
        std::make_unique<UnifiedPipelineCommand>(UnifiedPipelineCommandId::AUDIO_BUFFER_END, nullptr));
}

void UnifiedPipelineAudioDataProducer::AudioCaptureBufferListenerImpl::OnBufferArrival(
    int64_t timestamp, std::unique_ptr<uint8_t[]> buffer, size_t bufferSize)
{
    auto dataProducer = dataProducer_.lock();
    CHECK_RETURN(!dataProducer);
    dataProducer->OnBufferArrival(dataProducer->MakePipelineBuffer(timestamp, std::move(buffer), bufferSize));
}

std::weak_ptr<UnifiedPipelineAudioCaptureWrap::AudioCaptureBufferListener>
UnifiedPipelineAudioDataProducer::GetAudioCaptureBufferListener()
{
    return audioCaptureBufferListener_;
}

} // namespace CameraStandard
} // namespace OHOS
