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

#include "movie_file_meta_buffer_producer.h"

#include "unified_pipeline_surface_buffer.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {

std::unique_ptr<UnifiedPipelineBuffer> MovieFileMetaBufferProducer::MakePipelineBuffer(
    sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp)
{
    int32_t bufferSize = 0;
    auto extraData = surfaceBuffer->GetExtraData();
    if (extraData) {
        extraData->ExtraGet("dataSize", bufferSize);
        extraData->ExtraGet("timeStamp", timestamp);
    }
    if (bufferSize == 0) {
        return nullptr;
    }
    MEDIA_DEBUG_LOG("MovieFileMetaBufferProducer::MakePipelineBuffer timestamp:%{public} " PRIi64, timestamp);

    auto pipelineBuffer = std::make_unique<UnifiedPipelineSurfaceBuffer>(BufferType::CAMERA_VIDEO_META);
    pipelineBuffer->WrapData({ .timestamp = timestamp, .surfaceBuffer = surfaceBuffer });
    return pipelineBuffer;
};
} // namespace CameraStandard
} // namespace OHOS