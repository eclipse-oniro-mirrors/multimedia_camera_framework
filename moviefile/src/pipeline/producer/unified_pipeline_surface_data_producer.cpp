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

#include "unified_pipeline_surface_data_producer.h"

#include "camera_log.h"
#include "sync_fence.h"
#include "unified_pipeline_surface_buffer.h"

namespace OHOS {
namespace CameraStandard {
UnifiedPipelineSurfaceDataProducer::SurfaceWrapper::SurfaceWrapper(
    std::weak_ptr<UnifiedPipelineSurfaceDataProducer> surfaceDataProducer, const std::string& surfaceName)
    : surfaceDataProducer_(surfaceDataProducer)
{
    surface_ = Surface::CreateSurfaceAsConsumer(surfaceName);
    CHECK_RETURN_ELOG(!surface_, "SurfaceWrapper::SurfaceWrapper create surface fail:%{public}s", surfaceName.c_str());
}

void UnifiedPipelineSurfaceDataProducer::SurfaceWrapper::Init()
{
    CHECK_RETURN(!surface_);
    sptr<IBufferConsumerListener> listener = this;
    surface_->RegisterConsumerListener(listener);
}

void UnifiedPipelineSurfaceDataProducer::SurfaceWrapper::OnBufferAvailable()
{
    CHECK_RETURN(!surface_);
    int64_t timestamp;
    OHOS::Rect damage;
    sptr<SurfaceBuffer> buffer;
    sptr<SyncFence> syncFence = SyncFence::INVALID_FENCE;
    SurfaceError surfaceRet = surface_->AcquireBuffer(buffer, syncFence, timestamp, damage);
    CHECK_RETURN(surfaceRet != SURFACE_ERROR_OK);

    surfaceRet = surface_->DetachBufferFromQueue(buffer, true);
    CHECK_RETURN(surfaceRet != SURFACE_ERROR_OK);

    auto surfaceDataProducer = surfaceDataProducer_.lock();
    if (!surfaceDataProducer || !surfaceDataProducer->OnConsumerBufferAvailable(buffer, timestamp)) {
        ReturnBuffer(buffer);
    }
}

void UnifiedPipelineSurfaceDataProducer::SurfaceWrapper::ReturnBuffer(sptr<SurfaceBuffer> surfaceBuffer)
{
    CHECK_RETURN(!surface_ || !surfaceBuffer);
    surface_->AttachBufferToQueue(surfaceBuffer);
    surface_->ReleaseBuffer(surfaceBuffer, SyncFence::INVALID_FENCE);
    MEDIA_DEBUG_LOG("UnifiedPipelineSurfaceDataProducer::SurfaceWrapper::ReturnBuffer done");
}

void UnifiedPipelineSurfaceDataProducer::SurfaceWrapper::Release()
{
    CHECK_RETURN(!surface_);
    surface_->UnregisterConsumerListener();
}

sptr<IBufferProducer> UnifiedPipelineSurfaceDataProducer::SurfaceWrapper::GetSurfaceProducer()
{
    CHECK_RETURN_RET(!surface_, nullptr);
    return surface_->GetProducer();
}

void UnifiedPipelineSurfaceDataProducer::InitSurfaceWraper(const std::string& surfaceName)
{
    sptr<SurfaceWrapper> surfaceWrapper = new SurfaceWrapper(
        std::static_pointer_cast<UnifiedPipelineSurfaceDataProducer>(shared_from_this()), surfaceName);
    surfaceWrapper->Init();
    surfaceWrapper_.Set(surfaceWrapper);
}

UnifiedPipelineSurfaceDataProducer::~UnifiedPipelineSurfaceDataProducer()
{
    MEDIA_INFO_LOG("UnifiedPipelineSurfaceDataProducer::~UnifiedPipelineSurfaceDataProducer");
    auto surfaceWrapper = surfaceWrapper_.Get();
    if (surfaceWrapper) {
        surfaceWrapper->Release();
    }
    MEDIA_INFO_LOG("UnifiedPipelineSurfaceDataProducer::~UnifiedPipelineSurfaceDataProducer done");
}

sptr<IBufferProducer> UnifiedPipelineSurfaceDataProducer::GetSurfaceProducer()
{
    auto surfaceWrapper = surfaceWrapper_.Get();
    CHECK_RETURN_RET(!surfaceWrapper, nullptr);
    return surfaceWrapper->GetSurfaceProducer();
}

bool UnifiedPipelineSurfaceDataProducer::OnConsumerBufferAvailable(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp)
{
    MEDIA_DEBUG_LOG("UnifiedPipelineSurfaceDataProducer OnConsumerBufferAvailable enter");
    auto surfaceWrapper = surfaceWrapper_.Get();
    CHECK_RETURN_RET_DLOG(surfaceWrapper == nullptr, false,
        "UnifiedPipelineSurfaceDataProducer::OnConsumerBufferAvailable surfaceWrapper is null");

    auto pipelineBuffer = MakePipelineBuffer(surfaceBuffer, timestamp);
    CHECK_RETURN_RET_DLOG(pipelineBuffer == nullptr, false,
        "UnifiedPipelineSurfaceDataProducer::OnConsumerBufferAvailable pipelineBuffer is null");
    auto pipelineSurfaceBuffer =
        UnifiedPipelineBuffer::CastPtr<UnifiedPipelineSurfaceBuffer>(std::move(pipelineBuffer));

    pipelineSurfaceBuffer->SetBufferMemoryReleaser([surfaceWrapper](PipelineSurfaceBufferData* bufferData) {
        MEDIA_DEBUG_LOG("UnifiedPipelineSurfaceDataProducer memoryRelease enter");
        surfaceWrapper->ReturnBuffer(bufferData->surfaceBuffer);
    });

    MEDIA_DEBUG_LOG("UnifiedPipelineSurfaceDataProducer OnConsumerBufferAvailable end %{public}" PRIi64, timestamp);
    OnBufferArrival(std::move(pipelineSurfaceBuffer));
    return true;
}
} // namespace CameraStandard
} // namespace OHOS
