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

#ifndef OHOS_UNIFIED_PIPELINE_H
#define OHOS_UNIFIED_PIPELINE_H

#include <memory>
#include <mutex>

#include "iunified_pipeline_pressure_monitor.h"
#include "unified_pipeline_buffer.h"
#include "unified_pipeline_buffer_listener.h"
#include "unified_pipeline_data_consumer.h"
#include "unified_pipeline_plugin.h"
#include "unified_pipeline_threadpool.h"

namespace OHOS {
namespace CameraStandard {

class UnifiedPipeline : public UnifiedPipelineBufferListener,
                        public IUnifyPipelinePressureMonitor,
                        public std::enable_shared_from_this<UnifiedPipeline> {
public:
    UnifiedPipeline(int32_t maxThreadSize = 1);
    virtual ~UnifiedPipeline() = default;

    void OnBufferArrival(std::unique_ptr<UnifiedPipelineBuffer> sourceData) override;
    virtual void OnCommandArrival(std::unique_ptr<UnifiedPipelineCommand> command) override;

    void AddPlugin(int32_t order, std::shared_ptr<UnifiedPipelinePlugin> plugin);

    void RemovePlugin(std::shared_ptr<UnifiedPipelinePlugin> plugin);

    void ClearPlugin();

    void SetDataConsumer(std::weak_ptr<UnifiedPipelineDataConsumer> dataConsumer);

    int64_t GetPipelinePressure() override;

private:
    std::shared_ptr<UnifiedPipelineThreadpool> GetThreadPool();

    static std::unique_ptr<UnifiedPipelineBuffer> PluginsProcessBuffer(std::unique_ptr<UnifiedPipelineBuffer> inBuffer,
        const std::map<int32_t, std::shared_ptr<UnifiedPipelinePlugin>, std::less<int32_t>>& plugins);

    static void PluginsProcessCommand(UnifiedPipelineCommand* command,
        const std::map<int32_t, std::shared_ptr<UnifiedPipelinePlugin>, std::less<int32_t>>& plugins);

    std::mutex pluginsMutex_;
    std::map<int32_t, std::shared_ptr<UnifiedPipelinePlugin>, std::less<int32_t>> plugins_;

    int32_t maxThreadSize_ = 1;
    std::mutex threadPoolMutex_;
    std::shared_ptr<UnifiedPipelineThreadpool> threadPool_ = nullptr;

    std::mutex dataConsumerMutex_;
    std::weak_ptr<UnifiedPipelineDataConsumer> dataConsumer_;

    std::mutex pipelineThreadMtx_; // lock for pipelineThreadCv_,currentBufferId_,handledBufferId_
    std::condition_variable pipelineThreadCv_;
    uint64_t currentBufferId_ = 0;
    uint64_t handledBufferId_ = 0;
};

} // namespace CameraStandard
} // namespace OHOS
#endif