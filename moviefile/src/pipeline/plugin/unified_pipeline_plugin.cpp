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

#include "unified_pipeline_plugin.h"

#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
void UnifiedPipelinePlugin::AddProcessNode(int32_t order, std::shared_ptr<UnifiedPiplineProcessNodeBase> processNode)
{
    CHECK_RETURN(processNode == nullptr);
    std::lock_guard<std::mutex> lock(processNodesMutex_);
    processNodes_[order] = processNode;
    processNode->SetPipelinePressureMonitor(GetPipelinePressureMonitor());
};

void UnifiedPipelinePlugin::RemoveProcessNode(std::shared_ptr<UnifiedPiplineProcessNodeBase> processNode)
{
    CHECK_RETURN(processNode == nullptr);
    std::lock_guard<std::mutex> lock(processNodesMutex_);
    for (auto it = processNodes_.begin(); it != processNodes_.end();) {
        if (it->second == processNode) {
            it = processNodes_.erase(it);
        } else {
            ++it;
        }
    }
}

std::unique_ptr<UnifiedPipelineBuffer> UnifiedPipelinePlugin::ProcessBuffer(
    std::unique_ptr<UnifiedPipelineBuffer> bufferIn)
{
    CHECK_RETURN_RET(bufferIn == nullptr, nullptr);
    std::unique_ptr<UnifiedPipelineBuffer> buffer = std::move(bufferIn);
    std::lock_guard<std::mutex> lock(processNodesMutex_);
    for (auto it = processNodes_.begin(); it != processNodes_.end(); it++) {
        buffer = it->second->NodeBaseProcessBuffer(std::move(buffer));
    }
    return buffer;
}

void UnifiedPipelinePlugin::ProcessCommand(UnifiedPipelineCommand* command)
{
    CHECK_RETURN(command == nullptr);
    CHECK_RETURN(command->IsConsumed());
    std::lock_guard<std::mutex> lock(processNodesMutex_);
    for (auto it = processNodes_.begin(); it != processNodes_.end(); it++) {
        it->second->ProcessCommand(command);
        CHECK_RETURN(command->IsConsumed());
    }
}
} // namespace CameraStandard
} // namespace OHOS
