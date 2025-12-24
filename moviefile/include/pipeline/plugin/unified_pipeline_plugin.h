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

#ifndef OHOS_UNIFIED_PIPELINE_PLUGIN_H
#define OHOS_UNIFIED_PIPELINE_PLUGIN_H

#include <list>
#include <map>
#include <memory>
#include <mutex>

#include "unified_pipeline_command.h"
#include "unified_pipeline_process_node.h"

namespace OHOS {
namespace CameraStandard {
class UnifiedPipelinePlugin {
public:
    virtual ~UnifiedPipelinePlugin() = default;

    void AddProcessNode(int32_t order, std::shared_ptr<UnifiedPiplineProcessNodeBase> processNode);
    void RemoveProcessNode(std::shared_ptr<UnifiedPiplineProcessNodeBase> processNode);
    virtual std::unique_ptr<UnifiedPipelineBuffer> ProcessBuffer(std::unique_ptr<UnifiedPipelineBuffer> bufferIn);
    virtual void ProcessCommand(UnifiedPipelineCommand* command);

    inline void SetPipelinePressureMonitor(std::weak_ptr<IUnifyPipelinePressureMonitor> pipelinePressureMonitor)
    {
        {
            std::lock_guard<std::mutex> lock(pipelinePressureMonitorMtx_);
            pipelinePressureMonitor_ = pipelinePressureMonitor;
        }
        {
            std::lock_guard<std::mutex> nodesLock(processNodesMutex_);
            for (auto it = processNodes_.begin(); it != processNodes_.end(); it++) {
                it->second->SetPipelinePressureMonitor(pipelinePressureMonitor);
            }
        }
    }

private:
    inline std::weak_ptr<IUnifyPipelinePressureMonitor> GetPipelinePressureMonitor()
    {
        std::lock_guard<std::mutex> lock(pipelinePressureMonitorMtx_);
        return pipelinePressureMonitor_;
    }

    std::mutex processNodesMutex_;
    std::map<int32_t, std::shared_ptr<UnifiedPiplineProcessNodeBase>, std::less<int32_t>> processNodes_;

    std::mutex pipelinePressureMonitorMtx_;
    std::weak_ptr<IUnifyPipelinePressureMonitor> pipelinePressureMonitor_;
};
} // namespace CameraStandard
} // namespace OHOS

#endif