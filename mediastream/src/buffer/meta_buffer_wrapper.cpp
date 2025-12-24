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

#include "meta_buffer_wrapper.h"
#include "camera_log.h"
#include "sync_fence.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {

MetaBufferWrapper::MetaBufferWrapper(sptr<SurfaceBuffer> metaBuffer, int64_t timestamp, sptr<Surface> inputSurface)
    : BufferWrapperBase(Type::META, timestamp), metaBuffer_(metaBuffer),
    inputSurface_(wptr<Surface>(inputSurface))
{
    MEDIA_DEBUG_LOG("MetaBufferWrapper %{public}" PRId64, timestamp);
}

MetaBufferWrapper::~MetaBufferWrapper()
{
    MEDIA_DEBUG_LOG("~MetaBufferWrapper %{public}" PRId64, GetTimestamp());
    metaBuffer_ = nullptr;
}

sptr<SurfaceBuffer> MetaBufferWrapper::GetMetaBuffer()
{ 
    std::unique_lock<std::mutex> lock(metaBufferMutex_);
    return metaBuffer_;
}

void MetaBufferWrapper::SetMetaBuffer(sptr<SurfaceBuffer> buffer)
{
    std::unique_lock<std::mutex> lock(metaBufferMutex_);
    metaBuffer_ = buffer;
}

bool MetaBufferWrapper::Release()
{
    std::unique_lock<std::mutex> lock(metaBufferMutex_);
    sptr<SurfaceBuffer> buffer = nullptr;
    if (metaBuffer_) {
        buffer = SurfaceBuffer::Create();
        CHECK_RETURN_RET_ELOG(buffer == nullptr, MEDIA_ERR, "buffer is null");
        DeepCopyBuffer(buffer, metaBuffer_);
    }
    if (metaBuffer_) {
        auto surface = inputSurface_.promote();
        CHECK_RETURN_RET_ELOG(surface == nullptr, MEDIA_ERR, "MetaBufferWrapper::Release surface is null");
        SurfaceError surfaceRet = surface->AttachBufferToQueue(metaBuffer_);
        CHECK_RETURN_RET_ELOG(
            surfaceRet != SURFACE_ERROR_OK, MEDIA_OK, "Failed to attach meta buffer %{public}d", surfaceRet);
        surfaceRet = surface->ReleaseBuffer(metaBuffer_, -1);
        CHECK_RETURN_RET_ELOG(
            surfaceRet != SURFACE_ERROR_OK, MEDIA_ERR, "Failed to Release meta Buffer %{public}d", surfaceRet);
        metaBuffer_ = buffer;
    }
    return MEDIA_OK;
}

void MetaBufferWrapper::DeepCopyBuffer(sptr<SurfaceBuffer> newSurfaceBuffer, sptr<SurfaceBuffer> surfaceBuffer)
{
    CHECK_RETURN_ELOG(newSurfaceBuffer == nullptr, "newSurfaceBuffer is null");
    BufferRequestConfig requestConfig = {
        .width = surfaceBuffer->GetWidth(),
        .height = surfaceBuffer->GetHeight(),
        .strideAlignment = 0x8, // default stride is 8 Bytes.
        .format = surfaceBuffer->GetFormat(),
        .usage = surfaceBuffer->GetUsage(),
        .timeout = 0,
        .colorGamut = surfaceBuffer->GetSurfaceBufferColorGamut(),
        .transform = surfaceBuffer->GetSurfaceBufferTransform(),
    };
    auto allocErrorCode = newSurfaceBuffer->Alloc(requestConfig);
    CHECK_RETURN_ELOG(allocErrorCode != GSERROR_OK, "SurfaceBuffer alloc ret: %d", allocErrorCode);
    if (memcpy_s(newSurfaceBuffer->GetVirAddr(), newSurfaceBuffer->GetSize(),
        surfaceBuffer->GetVirAddr(), surfaceBuffer->GetSize()) != EOK) {
        MEDIA_ERR_LOG("SurfaceBuffer memcpy_s failed");
    }
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP