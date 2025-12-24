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

#include "unified_pipeline.h"

#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {

UnifiedPipeline::UnifiedPipeline(int32_t maxThreadSize) : maxThreadSize_(maxThreadSize) {}

std::shared_ptr<UnifiedPipelineThreadpool> UnifiedPipeline::GetThreadPool()
{
    CHECK_RETURN_RET(threadPool_ != nullptr, threadPool_);
    std::lock_guard<std::mutex> lock(threadPoolMutex_);
    if (threadPool_ == nullptr) {
        threadPool_ = std::make_shared<UnifiedPipelineThreadpool>(maxThreadSize_);
    }
    return threadPool_;
}

std::unique_ptr<UnifiedPipelineBuffer> UnifiedPipeline::PluginsProcessBuffer(
    std::unique_ptr<UnifiedPipelineBuffer> inBuffer,
    const std::map<int32_t, std::shared_ptr<UnifiedPipelinePlugin>, std::less<int32_t>>& plugins)
{
    auto bufferData = std::move(inBuffer);
    MEDIA_DEBUG_LOG("UnifiedPipeline::PluginsProcessBuffer bufferType:%{public}d", bufferData->GetBufferType());
    for (auto& pluginPair : plugins) {
        bufferData = pluginPair.second->ProcessBuffer(std::move(bufferData));
        if (bufferData == nullptr) {
            break;
        }
    }

    return bufferData;
}

void UnifiedPipeline::PluginsProcessCommand(UnifiedPipelineCommand* command,
    const std::map<int32_t, std::shared_ptr<UnifiedPipelinePlugin>, std::less<int32_t>>& plugins)
{
    CHECK_RETURN(command == nullptr);
    CHECK_RETURN(command->IsConsumed());
    for (auto& pluginPair : plugins) {
        pluginPair.second->ProcessCommand(command);
        CHECK_RETURN(command->IsConsumed());
    }
}

int64_t UnifiedPipeline::GetPipelinePressure()
{
    auto threadPool = GetThreadPool();
    return threadPool->GetTaskSize();
}

void UnifiedPipeline::OnBufferArrival(std::unique_ptr<UnifiedPipelineBuffer> sourceData)
{
    CHECK_RETURN(sourceData == nullptr);
    auto threadPool = GetThreadPool();

    // plugins_ 必须在锁范围内进行拷贝之后放到线程池中，避免多线程操作plugins_出现异常。
    std::map<int32_t, std::shared_ptr<UnifiedPipelinePlugin>, std::less<int32_t>> plugins;
    {
        std::lock_guard<std::mutex> lock(pluginsMutex_);
        plugins = plugins_;
    }

    std::weak_ptr<UnifiedPipelineDataConsumer> dataConsumer;
    {
        std::lock_guard<std::mutex> lockDataConsumer(dataConsumerMutex_);
        dataConsumer = dataConsumer_;
    }

    std::unique_lock<std::mutex> pipelineThreadLock(pipelineThreadMtx_);

    // currentBufferId_ overflow is fine, because handledBufferId_ will also overflow
    auto currentId = currentBufferId_++;
    threadPool->Submit([plugins, inBuffer = std::move(sourceData), dataConsumer, this, currentId]() mutable {
        auto bufferData = PluginsProcessBuffer(std::move(inBuffer), plugins);
        std::unique_lock<std::mutex> pipelineThreadLock(pipelineThreadMtx_);
        pipelineThreadCv_.wait(pipelineThreadLock, [this, &currentId] { return handledBufferId_ == currentId; });
        if (bufferData != nullptr) {
            auto strongDataConsumer = dataConsumer.lock();
            if (strongDataConsumer) {
                strongDataConsumer->OnBufferArrival(std::move(bufferData));
            }
        }
        handledBufferId_++;
        pipelineThreadCv_.notify_all();
    });
};

void UnifiedPipeline::OnCommandArrival(std::unique_ptr<UnifiedPipelineCommand> command)
{
    CHECK_RETURN(command == nullptr || command->IsConsumed());
    auto threadPool = GetThreadPool();

    // plugins_ 必须在锁范围内进行拷贝之后放到线程池中，避免多线程操作plugins_出现异常。
    std::map<int32_t, std::shared_ptr<UnifiedPipelinePlugin>, std::less<int32_t>> plugins;
    {
        std::lock_guard<std::mutex> lock(pluginsMutex_);
        plugins = plugins_;
    }

    std::weak_ptr<UnifiedPipelineDataConsumer> dataConsumer;
    {
        std::lock_guard<std::mutex> lockDataConsumer(dataConsumerMutex_);
        dataConsumer = dataConsumer_;
    }

    std::unique_lock<std::mutex> pipelineThreadLock(pipelineThreadMtx_);

    // currentBufferId_ overflow is fine, because handledBufferId_ will also overflow
    auto currentId = currentBufferId_++;
    threadPool->Submit([plugins, inCommand = std::move(command), dataConsumer, this, currentId]() mutable {
        PluginsProcessCommand(inCommand.get(), plugins);
        CHECK_RETURN(inCommand->IsConsumed());

        std::unique_lock<std::mutex> pipelineThreadLock(pipelineThreadMtx_);
        pipelineThreadCv_.wait(pipelineThreadLock, [this, &currentId] { return handledBufferId_ == currentId; });
        auto strongDataConsumer = dataConsumer.lock();
        if (strongDataConsumer) {
            strongDataConsumer->OnCommandArrival(std::move(inCommand));
        }
        handledBufferId_++;
        pipelineThreadCv_.notify_all();
    });
};

void UnifiedPipeline::AddPlugin(int32_t order, std::shared_ptr<UnifiedPipelinePlugin> plugin)
{
    CHECK_RETURN(plugin == nullptr);
    std::lock_guard<std::mutex> lock(pluginsMutex_);
    plugins_[order] = plugin;
    plugin->SetPipelinePressureMonitor(weak_from_this());
}

void UnifiedPipeline::RemovePlugin(std::shared_ptr<UnifiedPipelinePlugin> plugin)
{
    CHECK_RETURN(plugin == nullptr);
    std::lock_guard<std::mutex> lock(pluginsMutex_);
    for (auto it = plugins_.begin(); it != plugins_.end();) {
        if (it->second == plugin) {
            it = plugins_.erase(it);
        } else {
            ++it;
        }
    }
}

void UnifiedPipeline::ClearPlugin()
{
    std::lock_guard<std::mutex> lock(pluginsMutex_);
    plugins_.clear();
}

void UnifiedPipeline::SetDataConsumer(std::weak_ptr<UnifiedPipelineDataConsumer> dataConsumer)
{
    std::lock_guard<std::mutex> lock(dataConsumerMutex_);
    dataConsumer_ = dataConsumer;
}
} // namespace CameraStandard
} // namespace OHOS