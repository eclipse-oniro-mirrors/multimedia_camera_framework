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

#include "movie_file_video_buffer_producer.h"

#include <memory>

#include "camera_log.h"
#include "unified_pipeline_surface_buffer.h"

namespace OHOS {
namespace CameraStandard {

MovieFileVideoBufferProducer::MovieFileVideoBufferProducer(int32_t width, int32_t height)
    : width_(width), height_(height)
{}

int32_t MovieFileVideoBufferProducer::GetWidth()
{
    return width_;
}

int32_t MovieFileVideoBufferProducer::GetHeight()
{
    return height_;
}

std::unique_ptr<UnifiedPipelineBuffer> MovieFileVideoBufferProducer::MakePipelineBuffer(
    sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp)
{
    auto pipelineBuffer = std::make_unique<UnifiedPipelineSurfaceBuffer>(BufferType::CAMERA_VIDEO_SURFACE_BUFFER);
    pipelineBuffer->WrapData({ .timestamp = timestamp, .surfaceBuffer = surfaceBuffer });
    return pipelineBuffer;
};

} // namespace CameraStandard
} // namespace OHOS
