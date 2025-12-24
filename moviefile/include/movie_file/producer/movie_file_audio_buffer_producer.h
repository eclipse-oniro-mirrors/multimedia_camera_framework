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

#ifndef OHOS_CAMERA_MOVIE_FILE_AUDIO_BUFFER_PRODUCER_H
#define OHOS_CAMERA_MOVIE_FILE_AUDIO_BUFFER_PRODUCER_H

#include <cstdint>

#include "unified_pipeline_audio_data_producer.h"

namespace OHOS {
namespace CameraStandard {
class MovieFileAudioBufferProducer : public UnifiedPipelineAudioDataProducer {
public:
    MovieFileAudioBufferProducer() = default;

protected:
    std::unique_ptr<UnifiedPipelineBuffer> MakePipelineBuffer(
        int64_t timestamp, std::shared_ptr<uint8_t[]> buffer, size_t bufferSize) override;
};
} // namespace CameraStandard
} // namespace OHOS
#endif