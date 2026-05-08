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

#ifndef OHOS_UNIFIED_PIPELINE_METADATA_BUFFER_H
#define OHOS_UNIFIED_PIPELINE_METADATA_BUFFER_H

#include <cstdint>
#include <vector>
#include "unified_pipeline_buffer.h"
#include "unified_pipeline_buffer_wrapper.h"

namespace OHOS {
namespace CameraStandard {
struct PipelineMetadataBufferData {
    int64_t timestamp = 0;
    int32_t type = 0;
    std::vector<uint8_t> metaData {};
};

class UnifiedPipelineMetadataBuffer : public UnifiedPipelineBuffer,
                                      public UnifiedPipelineBufferWrapper<PipelineMetadataBufferData> {
public:
    explicit UnifiedPipelineMetadataBuffer(BufferType type) : UnifiedPipelineBuffer(type) {}
};
} // namespace CameraStandard
} // namespace OHOS

#endif