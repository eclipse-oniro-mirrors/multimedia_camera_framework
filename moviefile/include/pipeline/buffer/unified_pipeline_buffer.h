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

#ifndef OHOS_UNIFIED_PIPELINE_BUFFER_H
#define OHOS_UNIFIED_PIPELINE_BUFFER_H

#include <list>
#include <memory>
#include <type_traits>

#include "unified_pipeline_buffer_types.h"

namespace OHOS {
namespace CameraStandard {
class UnifiedPipelineBuffer {
public:
    template<typename OUT_TYPE, typename = std::enable_if_t<std::is_base_of_v<UnifiedPipelineBuffer, OUT_TYPE>>>
    static std::unique_ptr<OUT_TYPE> CastPtr(std::unique_ptr<UnifiedPipelineBuffer> inPtr)
    {
        return std::unique_ptr<OUT_TYPE>(static_cast<OUT_TYPE*>(inPtr.release()));
    };

    explicit UnifiedPipelineBuffer(BufferType type = BufferType::VOID);
    virtual ~UnifiedPipelineBuffer() = default;

    UnifiedPipelineBuffer(const UnifiedPipelineBuffer&) = delete;
    UnifiedPipelineBuffer& operator=(const UnifiedPipelineBuffer&) = delete;

    inline BufferType GetBufferType()
    {
        return bufferType_;
    }

private:
    BufferType bufferType_ = BufferType::VOID;
};
} // namespace CameraStandard
} // namespace OHOS

#endif