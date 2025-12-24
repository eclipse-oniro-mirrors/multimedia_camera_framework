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

#include "movie_file_audio_buffer_producer.h"

#include <utility>

#include "camera_log.h"
#include "unified_pipeline_audio_buffer.h"

namespace OHOS {
namespace CameraStandard {

std::unique_ptr<UnifiedPipelineBuffer> MovieFileAudioBufferProducer::MakePipelineBuffer(
    int64_t timestamp, std::shared_ptr<uint8_t[]> buffer, size_t bufferSize)
{
    MEDIA_DEBUG_LOG("MovieFileAudioBufferProducer MakePipelineBuffer timestamp:%{public}" PRIi64
                   " size %{public}zu",
        timestamp, bufferSize);
    auto pipelineBuffer = std::make_unique<UnifiedPipelineAudioBuffer>(BufferType::CAMERA_AUDIO_RAW_BUFFER);
    pipelineBuffer->WrapData({ .timestamp = timestamp, .data = buffer, .dataSize = bufferSize, .isRawBuffer = true });
    return pipelineBuffer;
}
} // namespace CameraStandard
} // namespace OHOS
