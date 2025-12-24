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

#ifndef OHOS_UNIFIED_PIPELINE_AUDIO_ENCODED_BUFFER_H
#define OHOS_UNIFIED_PIPELINE_AUDIO_ENCODED_BUFFER_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

#include "unified_pipeline_avencoder_out_buffer_info.h"
#include "unified_pipeline_buffer.h"
#include "unified_pipeline_buffer_wrapper.h"

namespace OHOS {
namespace CameraStandard {
class UnifiedPipelineAudioEncodedBuffer : public UnifiedPipelineBuffer,
                                          public UnifiedPipelineBufferWrapper<AVEncoderOH_AVBufferInfo> {
public:
    UnifiedPipelineAudioEncodedBuffer(BufferType type);
};

class UnifiedPipelineAudioPackagedEncodedBuffer
    : public UnifiedPipelineBuffer,
      public UnifiedPipelineBufferWrapper<AVEncoderedPackagedOH_AVBufferInfo> {
public:
    UnifiedPipelineAudioPackagedEncodedBuffer(BufferType type);
};
} // namespace CameraStandard
} // namespace OHOS

#endif