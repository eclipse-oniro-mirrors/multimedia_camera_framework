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

#ifndef OHOS_UNIFIED_PIPELINE_SURFACE_BUFFER_H
#define OHOS_UNIFIED_PIPELINE_SURFACE_BUFFER_H

#include <memory>

#include "surface.h"
#include "unified_pipeline_buffer.h"
#include "unified_pipeline_buffer_wrapper.h"

namespace OHOS {
namespace CameraStandard {
struct PipelineSurfaceBufferData {
    int64_t timestamp = 0;
    sptr<SurfaceBuffer> surfaceBuffer;
};

class UnifiedPipelineSurfaceBuffer : public UnifiedPipelineBuffer,
                                     public UnifiedPipelineBufferWrapper<PipelineSurfaceBufferData> {
public:
    UnifiedPipelineSurfaceBuffer(BufferType type);
};
} // namespace CameraStandard
} // namespace OHOS

#endif