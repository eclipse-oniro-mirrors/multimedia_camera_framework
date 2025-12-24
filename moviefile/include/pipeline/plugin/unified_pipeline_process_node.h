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

#ifndef OHOS_UNIFIED_PIPELINE_PROCESS_NODE_H
#define OHOS_UNIFIED_PIPELINE_PROCESS_NODE_H

#include <list>
#include <memory>

#include "iunified_pipeline_pressure_monitor.h"
#include "unified_pipeline_buffer.h"
#include "unified_pipeline_command.h"

namespace OHOS {
namespace CameraStandard {
class UnifiedPiplineProcessNodeBase {
public:
    virtual ~UnifiedPiplineProcessNodeBase() = default;
    virtual std::unique_ptr<UnifiedPipelineBuffer> NodeBaseProcessBuffer(
        std::unique_ptr<UnifiedPipelineBuffer> bufferIn) = 0;
    virtual void ProcessCommand(UnifiedPipelineCommand* command) {};

    inline void SetPipelinePressureMonitor(std::weak_ptr<IUnifyPipelinePressureMonitor> pipelinePressureMonitor)
    {
        std::lock_guard<std::mutex> lock(pipelinePressureMonitorMtx_);
        pipelinePressureMonitor_ = pipelinePressureMonitor;
    }

    inline int64_t GetPipelinePressure()
    {
        std::lock_guard<std::mutex> lock(pipelinePressureMonitorMtx_);
        auto monitor = pipelinePressureMonitor_.lock();
        if (!monitor) {
            return 0; // default pressure is 0.
        }
        return monitor->GetPipelinePressure();
    }

private:
    std::mutex pipelinePressureMonitorMtx_;
    std::weak_ptr<IUnifyPipelinePressureMonitor> pipelinePressureMonitor_;
};

template<typename IN_TYPE, typename OUT_TYPE,
    typename = std::enable_if_t<std::is_base_of_v<UnifiedPipelineBuffer, IN_TYPE> &&
                                std::is_base_of_v<UnifiedPipelineBuffer, OUT_TYPE>>>
class UnifiedPiplineProcessNode : public UnifiedPiplineProcessNodeBase {
public:
    UnifiedPiplineProcessNode() {};
    virtual ~UnifiedPiplineProcessNode() = default;
    std::unique_ptr<UnifiedPipelineBuffer> NodeBaseProcessBuffer(
        std::unique_ptr<UnifiedPipelineBuffer> bufferIn) override
    {
        UnifiedPipelineBuffer* pipelineBuffer = bufferIn.release();
        IN_TYPE* inTypePtr = static_cast<IN_TYPE*>(pipelineBuffer);
        return ProcessBuffer(std::unique_ptr<IN_TYPE>(inTypePtr));
    }

    virtual std::unique_ptr<OUT_TYPE> ProcessBuffer(std::unique_ptr<IN_TYPE> bufferIn) = 0;
};

using UnifiedPiplineProcessNodeDefault = UnifiedPiplineProcessNode<UnifiedPipelineBuffer, UnifiedPipelineBuffer>;
} // namespace CameraStandard
} // namespace OHOS

#endif