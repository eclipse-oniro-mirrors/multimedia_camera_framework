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

#include "unified_pipeline_manager.h"
#include "camera_log.h"

#include <memory>
#include <mutex>

namespace OHOS {
namespace CameraStandard {

std::mutex UnifiedPipelineManager::g_managerMapMutex;
std::map<UnifiedPipelineManager::PipelineManagerId, std::shared_ptr<UnifiedPipelineManager>>
    UnifiedPipelineManager::g_managerMap = {};

std::shared_ptr<UnifiedPipelineManager> UnifiedPipelineManager::GetPipelineManager(
    UnifiedPipelineManager::PipelineManagerId managerId)
{
    std::lock_guard<std::mutex> lock(g_managerMapMutex);
    auto it = g_managerMap.find(managerId);
    if (it == g_managerMap.end()) {
        auto manager = std::make_shared<UnifiedPipelineManager>();
        g_managerMap.insert({ managerId, manager });
        return manager;
    }
    return it->second;
}

bool UnifiedPipelineManager::ReleasePipelineManager(PipelineManagerId managerId)
{
    std::lock_guard<std::mutex> lock(g_managerMapMutex);
    auto it = g_managerMap.find(managerId);
    CHECK_RETURN_RET(it == g_managerMap.end(), false);
    g_managerMap.erase(it);
    return true;
}

UnifiedPipelineManager::UnifiedPipelineManager() {}

std::shared_ptr<UnifiedPipeline> UnifiedPipelineManager::GetPipelineWithProducer(
    std::shared_ptr<UnifiedPipelineDataProducer> producer, int32_t threadMax)
{
    std::lock_guard<std::mutex> lock(pipelinesMutex_);
    auto it = pipelines_.find(producer);
    CHECK_RETURN_RET(it != pipelines_.end(), it->second);
    auto newPipeline = std::make_shared<UnifiedPipeline>(threadMax);
    producer->SetBufferListener(newPipeline);
    pipelines_[producer] = newPipeline;
    return newPipeline;
};
} // namespace CameraStandard
} // namespace OHOS