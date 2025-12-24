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

#ifndef OHOS_UNIFIED_PIPELINE_MANAGER_H
#define OHOS_UNIFIED_PIPELINE_MANAGER_H

#include <memory>
#include <mutex>
#include <vector>

#include "unified_pipeline.h"
#include "unified_pipeline_data_producer.h"

namespace OHOS {
namespace CameraStandard {
class UnifiedPipelineManager {
public:
    enum class PipelineManagerId { MOVING_PHOTO_AUDIO, MOVING_PHOTO_VIDEO, MOVING_PHOTO_META };
    static std::shared_ptr<UnifiedPipelineManager> GetPipelineManager(PipelineManagerId managerId);
    static bool ReleasePipelineManager(PipelineManagerId managerId);

public:
    explicit UnifiedPipelineManager();
    std::shared_ptr<UnifiedPipeline> GetPipelineWithProducer(
        std::shared_ptr<UnifiedPipelineDataProducer> producer, int32_t threadMax = 1);

private:
    std::mutex pipelinesMutex_;
    std::map<std::shared_ptr<UnifiedPipelineDataProducer>, std::shared_ptr<UnifiedPipeline>> pipelines_;

private:
    static std::mutex g_managerMapMutex;
    static std::map<PipelineManagerId, std::shared_ptr<UnifiedPipelineManager>> g_managerMap;
};
} // namespace CameraStandard
} // namespace OHOS
#endif