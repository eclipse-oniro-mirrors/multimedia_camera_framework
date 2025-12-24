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

#ifndef OHOS_UNIFIED_PIPELINE_AUDIO_BUFFER_H
#define OHOS_UNIFIED_PIPELINE_AUDIO_BUFFER_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

#include "unified_pipeline_buffer.h"
#include "unified_pipeline_buffer_wrapper.h"

namespace OHOS {
namespace CameraStandard {
struct PipelineAudioBufferData {
    // 用于编码以及送muxer的时间戳，单位是微秒
    int64_t timestamp = 0;
    std::shared_ptr<uint8_t[]> data = nullptr;
    size_t dataSize = 0;
    bool isRawBuffer = false;
};

struct PipelinePackagedAudioBufferData {
    std::list<PipelineAudioBufferData> bufferDatas {};
    // 小包音频的时间戳会被编码器修改，这里用于记录原始时间戳
    int64_t timestamp = 0;
};

class UnifiedPipelineAudioBuffer : public UnifiedPipelineBuffer,
                                   public UnifiedPipelineBufferWrapper<PipelineAudioBufferData> {
public:
    UnifiedPipelineAudioBuffer(BufferType type);
};

class UnifiedPipelineAudioPackagedBuffer : public UnifiedPipelineBuffer,
                                           public UnifiedPipelineBufferWrapper<PipelinePackagedAudioBufferData> {
public:
    UnifiedPipelineAudioPackagedBuffer(BufferType type);
};

} // namespace CameraStandard
} // namespace OHOS

#endif