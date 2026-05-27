/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_MOVIE_FILE_AUDIO_METADATA_BUFFER_PRODUCER_H
#define OHOS_CAMERA_MOVIE_FILE_AUDIO_METADATA_BUFFER_PRODUCER_H

#include <cinttypes>
#include <cstdint>
#include <memory>
#include <vector>

#include "audio_info.h"
#include "audio_capturer.h"
#include "camera_log.h"
#include "unified_pipeline_data_producer.h"
#include "unified_pipeline_metadata_buffer.h"

namespace OHOS {
namespace CameraStandard {
class MovieFileAudioMetadataBufferProducer : public UnifiedPipelineDataProducer {
public:
    MovieFileAudioMetadataBufferProducer() = default;

    void OnMetaDataArrival(
        AudioStandard::CaptureMetaDataType type, const std::vector<uint8_t>& metaData, int64_t timestamp)
    {
        CHECK_RETURN(metaData.empty());
        MEDIA_DEBUG_LOG("MovieFileAudioMetadataBufferProducer OnMetaDataArrival type:%{public}d timestamp:%{public}"
                        PRIi64 " size:%{public}zu",
            type, timestamp, metaData.size());
        auto pipelineBuffer = std::make_unique<UnifiedPipelineMetadataBuffer>(BufferType::CAMERA_AUDIO_4_2_METADATA);
        pipelineBuffer->WrapData({ .timestamp = timestamp, .type = static_cast<int32_t>(type), .metaData = metaData });
        OnBufferArrival(std::move(pipelineBuffer));
    }
};
} // namespace CameraStandard
} // namespace OHOS

#endif