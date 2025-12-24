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

#include "unified_pipeline_data_producer.h"

#include <memory>
#include <mutex>

#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
UnifiedPipelineDataProducer::UnifiedPipelineDataProducer() {};

void UnifiedPipelineDataProducer::OnBufferArrival(std::unique_ptr<UnifiedPipelineBuffer> pipelineBuffer)
{
    CHECK_RETURN(pipelineBuffer == nullptr);

    MEDIA_DEBUG_LOG("UnifiedPipelineDataProducer OnConsumerBufferAvailable");

    // 接入缓存机制
    // 缓存机制中，如果设定超过缓存被丢弃，这里返回nullptr。
    // 如果未开启缓存，这里返回原指针。
    auto buffer = CacheBuffer(pipelineBuffer);
    CHECK_RETURN(buffer == nullptr);

    auto listener = GetBufferListener();
    if (listener) {
        listener->OnBufferArrival(std::move(buffer));
    }
}

void UnifiedPipelineDataProducer::OnCommandArrival(std::unique_ptr<UnifiedPipelineCommand> command)
{
    CHECK_RETURN(command == nullptr);
    MEDIA_DEBUG_LOG("UnifiedPipelineDataProducer OnCommandArrival");
    auto listener = GetBufferListener();
    if (listener) {
        listener->OnCommandArrival(std::move(command));
    }
}

std::shared_ptr<UnifiedPipelineBufferListener> UnifiedPipelineDataProducer::GetBufferListener()
{
    std::lock_guard<std::mutex> lock(bufferListenerMutex_);
    return bufferListener_.lock();
}

void UnifiedPipelineDataProducer::SetBufferListener(std::weak_ptr<UnifiedPipelineBufferListener> bufferListener)
{
    std::lock_guard<std::mutex> lock(bufferListenerMutex_);
    bufferListener_ = bufferListener;
}

void UnifiedPipelineDataProducer::EnableBufferCache(int32_t bufferSize, bool dropOverFlowBufferData)
{
    std::lock_guard<std::mutex> lock(bufferCacheQueueMutex_);
    bufferCacheSize_ = bufferSize;
    dropOverFlowBufferCacheData_ = dropOverFlowBufferData;
}

void UnifiedPipelineDataProducer::DisableBufferCache()
{
    std::lock_guard<std::mutex> lock(bufferCacheQueueMutex_);
    bufferCacheSize_ = 0;
    FlushBufferCacheNoLock();
}

void UnifiedPipelineDataProducer::FlushBufferCache()
{
    std::lock_guard<std::mutex> lock(bufferCacheQueueMutex_);
    FlushBufferCacheNoLock();
}

void UnifiedPipelineDataProducer::FlushBufferCacheNoLock()
{
    while (!bufferCacheQueue_.empty()) {
        auto data = std::move(bufferCacheQueue_.front());
        bufferCacheQueue_.pop();
        auto listener = GetBufferListener();
        if (listener) {
            listener->OnBufferArrival(std::move(data));
        }
    }
}

std::unique_ptr<UnifiedPipelineBuffer> UnifiedPipelineDataProducer::CacheBuffer(
    std::unique_ptr<UnifiedPipelineBuffer>& pipelineBuffer)
{
    std::lock_guard<std::mutex> lock(bufferCacheQueueMutex_);
    // 不进行缓存操作，直接返回指针
    CHECK_RETURN_RET(bufferCacheSize_ <= 0, std::move(pipelineBuffer));

    std::unique_ptr<UnifiedPipelineBuffer> returnBuffer = nullptr;
    if (bufferCacheSize_ > 0) {
        bufferCacheQueue_.push(std::move(pipelineBuffer));
        // 弹出所有超出的缓存，如果涉及buffer容量缩减，这里需要通过循环处理而不是弹出一次
        // 将最后一个弹出的指针保存到临时变量中准备返回
        while (bufferCacheQueue_.size() > static_cast<size_t>(bufferCacheSize_)) {
            returnBuffer = std::move(bufferCacheQueue_.front());
            bufferCacheQueue_.pop();
        }
    }
    CHECK_RETURN_RET(dropOverFlowBufferCacheData_, nullptr);
    return returnBuffer;
}

} // namespace CameraStandard
} // namespace OHOS
