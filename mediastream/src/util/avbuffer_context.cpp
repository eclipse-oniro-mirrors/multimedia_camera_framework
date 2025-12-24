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

#include "avbuffer_context.h"
#include "camera_log.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {

AVBufferInfo::AVBufferInfo(uint32_t bufferIndex, std::shared_ptr<OHOS::Media::AVBuffer> avbuffer)
    : bufferIndex_(bufferIndex), avBuffer_(avbuffer)
{
}

std::shared_ptr<OHOS::Media::AVBuffer> AVBufferInfo::GetCopyAVBuffer()
{
    MEDIA_DEBUG_LOG("CodecBufferInfo OH_AVBuffer_Create with size: %{public}d", avBuffer_->memory_->GetSize());
    auto allocator = Media::AVAllocatorFactory::CreateSharedAllocator(Media::MemoryFlag::MEMORY_READ_WRITE);
    CHECK_RETURN_RET_ELOG(allocator == nullptr, nullptr, "create allocator failed");
    std::shared_ptr<Media::AVBuffer> destBuffer = Media::AVBuffer::CreateAVBuffer(allocator,
        avBuffer_->memory_->GetCapacity());
    CHECK_RETURN_RET_ELOG(destBuffer == nullptr, nullptr, "destBuffer is null");
    auto sourceAddr = avBuffer_->memory_->GetAddr();
    auto destAddr = destBuffer->memory_->GetAddr();
    errno_t cpyRet = memcpy_s(reinterpret_cast<void *>(destAddr), avBuffer_->memory_->GetSize(),
        reinterpret_cast<void *>(sourceAddr), avBuffer_->memory_->GetSize());
    CHECK_PRINT_ELOG(0 != cpyRet, "CodecBufferInfo memcpy_s failed. %{public}d", cpyRet);
    destBuffer->pts_ = avBuffer_->pts_;
    destBuffer->flag_ = avBuffer_->flag_;
    destBuffer->memory_->SetSize(avBuffer_->memory_->GetSize());
    return destBuffer;
}

std::shared_ptr<OHOS::Media::AVBuffer> AVBufferInfo::AddCopyAVBuffer(
    std::shared_ptr<OHOS::Media::AVBuffer> IDRBuffer)
{
    CHECK_RETURN_RET_ELOG(IDRBuffer == nullptr, nullptr, "AddCopyAVBuffer without IDRBuffer!");
    CHECK_RETURN_RET_ELOG(IDRBuffer->memory_ == nullptr, nullptr, "AddCopyAVBuffer without IDRBuffer->memory_!");
    CHECK_RETURN_RET_ELOG(avBuffer_ == nullptr, nullptr, "AddCopyAVBuffer without avBuffer_!");
    CHECK_RETURN_RET_ELOG(avBuffer_->memory_ == nullptr, nullptr, "AddCopyAVBuffer without avBuffer_->memory_!");
    int32_t iSize = IDRBuffer->memory_->GetSize();
    int32_t aSize = avBuffer_->memory_->GetSize();
    CHECK_RETURN_RET_ELOG(iSize > INT32_MAX - aSize, nullptr, "buffer size overflow");
    int32_t destBufferSize = iSize + aSize; 
    auto allocator = Media::AVAllocatorFactory::CreateSharedAllocator(Media::MemoryFlag::MEMORY_READ_WRITE);
    CHECK_RETURN_RET_ELOG(allocator == nullptr, nullptr, "create allocator failed");
    std::shared_ptr<Media::AVBuffer> destBuffer = Media::AVBuffer::CreateAVBuffer(allocator, destBufferSize);
    CHECK_RETURN_RET_ELOG(destBuffer == nullptr, nullptr, "destBuffer is null");
    auto destAddr = destBuffer->memory_->GetAddr();
    auto sourceIDRAddr = IDRBuffer->memory_->GetAddr();
    errno_t cpyRet = memcpy_s(reinterpret_cast<void *>(destAddr), destBufferSize,
        reinterpret_cast<void *>(sourceIDRAddr), IDRBuffer->memory_->GetSize());
    CHECK_PRINT_ELOG(0 != cpyRet, "CodecBufferInfo memcpy_s IDR frame failed. %{public}d", cpyRet);
    destAddr = destAddr + IDRBuffer->memory_->GetSize();
    auto sourceAddr = avBuffer_->memory_->GetAddr();
    cpyRet = memcpy_s(reinterpret_cast<void *>(destAddr), avBuffer_->memory_->GetSize(),
        reinterpret_cast<void *>(sourceAddr), avBuffer_->memory_->GetSize());
    CHECK_PRINT_ELOG(0 != cpyRet, "CodecBufferInfo memcpy_s I frame failed. %{public}d", cpyRet);
    destBuffer->memory_->SetSize(destBufferSize);
    destBuffer->flag_ = IDRBuffer->flag_ | avBuffer_->flag_;
    MEDIA_INFO_LOG("CodecBufferInfo copy with size: %{public}d, %{public}d", destBufferSize, destBuffer->flag_);
    return destBuffer;
}

void AVBufferContext::Release()
{
    {
        std::lock_guard<std::mutex> lock(inputMutex_);
        while (!inputBufferInfoQueue_.empty()) {
            inputBufferInfoQueue_.pop();
        }
    }
    {
        std::lock_guard<std::mutex> lock(outputMutex_);
        while (!outputBufferInfoQueue_.empty()) {
            outputBufferInfoQueue_.pop();
        }
    }
}

AVBufferContext::~AVBufferContext()
{
    Release();
}

} // CameraStandard
} // OHOS
// LCOV_EXCL_STOP