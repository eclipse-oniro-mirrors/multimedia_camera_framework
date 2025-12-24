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

#ifndef OHOS_UNIFIED_PIPELINE_DATA_PRODUCER_H
#define OHOS_UNIFIED_PIPELINE_DATA_PRODUCER_H

#include <memory>
#include <mutex>
#include <queue>

#include "unified_pipeline_buffer_listener.h"

namespace OHOS {
namespace CameraStandard {
class UnifiedPipelineDataProducer : public std::enable_shared_from_this<UnifiedPipelineDataProducer>,
                                    public UnifiedPipelineBufferListener {
public:
    UnifiedPipelineDataProducer();
    virtual ~UnifiedPipelineDataProducer() = default;

    std::shared_ptr<UnifiedPipelineBufferListener> GetBufferListener();

    void SetBufferListener(std::weak_ptr<UnifiedPipelineBufferListener> bufferListener);

    void OnBufferArrival(std::unique_ptr<UnifiedPipelineBuffer> pipelineBuffer) override;

    void OnCommandArrival(std::unique_ptr<UnifiedPipelineCommand> command) override;

    void EnableBufferCache(int32_t bufferSize, bool dropOverFlowBufferData = false);

    void DisableBufferCache();

    void FlushBufferCache();

private:
    void FlushBufferCacheNoLock();

    std::unique_ptr<UnifiedPipelineBuffer> CacheBuffer(std::unique_ptr<UnifiedPipelineBuffer>& pipelineBuffer);

    std::mutex bufferListenerMutex_;
    std::weak_ptr<UnifiedPipelineBufferListener> bufferListener_;

    std::mutex bufferCacheQueueMutex_;
    std::queue<std::unique_ptr<UnifiedPipelineBuffer>> bufferCacheQueue_;
    int32_t bufferCacheSize_ = 0;
    bool dropOverFlowBufferCacheData_ = false;
};
} // namespace CameraStandard
} // namespace OHOS

#endif