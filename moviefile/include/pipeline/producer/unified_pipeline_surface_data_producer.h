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

#ifndef OHOS_UNIFIED_PIPELINE_SURFACE_DATA_PRODUCER_H
#define OHOS_UNIFIED_PIPELINE_SURFACE_DATA_PRODUCER_H

#include <memory>
#include <mutex>

#include "sp_holder.h"
#include "surface.h"
#include "unified_pipeline_data_producer.h"

namespace OHOS {
namespace CameraStandard {
class UnifiedPipelineSurfaceDataProducer : public UnifiedPipelineDataProducer {
public:
    UnifiedPipelineSurfaceDataProducer() = default;

    ~UnifiedPipelineSurfaceDataProducer() override;

    sptr<IBufferProducer> GetSurfaceProducer();

    // 该接口应在 UnifiedPipelineSurfaceDataProducer 创建成功后立即调用
    void InitSurfaceWraper(const std::string& surfaceName);

protected:
    virtual std::unique_ptr<UnifiedPipelineBuffer> MakePipelineBuffer(
        sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp) = 0;

private:
    class SurfaceWrapper : public IBufferConsumerListener {
    public:
        SurfaceWrapper(
            std::weak_ptr<UnifiedPipelineSurfaceDataProducer> surfaceDataProducer, const std::string& surfaceName);

        // Init 函数应在构造函数之后立即调用，并且不要将Init函数写入构造函数内。
        // 在构造函数内将this转成智能指针时，离开了构造函数作用域将引发this析构。
        void Init();

        void OnBufferAvailable() override;

        void ReturnBuffer(sptr<SurfaceBuffer> surfaceBuffer);

        void Release();

        sptr<IBufferProducer> GetSurfaceProducer();

    private:
        sptr<Surface> surface_;
        std::weak_ptr<UnifiedPipelineSurfaceDataProducer> surfaceDataProducer_;
    };

private:
    bool OnConsumerBufferAvailable(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp);

    SpHolder<sptr<SurfaceWrapper>> surfaceWrapper_;
};
} // namespace CameraStandard
} // namespace OHOS

#endif