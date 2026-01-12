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

#include "sample_info.h"
#include "utils/camera_log.h"

namespace OHOS {
namespace CameraStandard {

CodecAVBufferInfo::CodecAVBufferInfo(uint32_t argBufferIndex, OH_AVBuffer* argBuffer)
    : bufferIndex(argBufferIndex), buffer(argBuffer)
{
    // get output buffer attr
    OH_AVBuffer_GetBufferAttr(argBuffer, &attr);
}

OH_AVBuffer* CodecAVBufferInfo::GetCopyAVBuffer()
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("CodecBufferInfo OH_AVBuffer_Create with size: %{public}d", attr.size);
    OH_AVBuffer* destBuffer = OH_AVBuffer_Create(attr.size);
    CHECK_RETURN_RET_ELOG(destBuffer == nullptr, nullptr, "destBuffer is null");
    auto sourceAddr = OH_AVBuffer_GetAddr(buffer);
    auto destAddr = OH_AVBuffer_GetAddr(destBuffer);
    errno_t cpyRet = memcpy_s(reinterpret_cast<void *>(destAddr), attr.size,
        reinterpret_cast<void *>(sourceAddr), attr.size);
    CHECK_PRINT_ELOG(cpyRet != 0, "CodecBufferInfo memcpy_s failed. %{public}d", cpyRet);

    OH_AVErrCode errorCode = OH_AVBuffer_SetBufferAttr(destBuffer, &attr);
    CHECK_PRINT_ELOG(errorCode != 0, "CodecBufferInfo OH_AVBuffer_SetBufferAttr failed. %{public}d", errorCode);
    return destBuffer;
    // LCOV_EXCL_STOP
}

OH_AVBuffer* CodecAVBufferInfo::AddCopyAVBuffer(OH_AVBuffer* IDRBuffer)
{
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(nullptr == IDRBuffer, IDRBuffer, "AddCopyAVBuffer without IDRBuffer!");
    OH_AVCodecBufferAttr IDRAttr = {0, 0, 0, AVCODEC_BUFFER_FLAGS_NONE};
    OH_AVCodecBufferAttr destAttr = {0, 0, 0, AVCODEC_BUFFER_FLAGS_NONE};
    OH_AVBuffer_GetBufferAttr(IDRBuffer, &IDRAttr);
    int32_t destBufferSize = IDRAttr.size + attr.size;
    OH_AVBuffer* destBuffer = OH_AVBuffer_Create(destBufferSize);
    CHECK_RETURN_RET_ELOG(destBuffer == nullptr, nullptr, "destBuffer is null");
    auto destAddr = OH_AVBuffer_GetAddr(destBuffer);
    auto sourceIDRAddr = OH_AVBuffer_GetAddr(IDRBuffer);

    errno_t cpyRet = memcpy_s(reinterpret_cast<void *>(destAddr), destBufferSize,
        reinterpret_cast<void *>(sourceIDRAddr), IDRAttr.size);
    CHECK_PRINT_ELOG(0 != cpyRet, "CodecBufferInfo memcpy_s IDR frame failed. %{public}d", cpyRet);
    destAddr = destAddr + IDRAttr.size;
    auto sourceAddr = OH_AVBuffer_GetAddr(buffer);
    cpyRet = memcpy_s(reinterpret_cast<void *>(destAddr), attr.size, reinterpret_cast<void *>(sourceAddr), attr.size);
    CHECK_PRINT_ELOG(0 != cpyRet, "CodecBufferInfo memcpy_s I frame failed. %{public}d", cpyRet);
    OH_AVBuffer_Destroy(IDRBuffer);
    destAttr.size = destBufferSize;
    destAttr.flags = IDRAttr.flags | attr.flags;
    MEDIA_INFO_LOG("CodecBufferInfo deep copy with size: %{public}d, %{public}d", destBufferSize, destAttr.flags);
    OH_AVBuffer_SetBufferAttr(destBuffer, &destAttr);
    return destBuffer;
    // LCOV_EXCL_STOP
}

void CodecUserData::Release()
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

CodecUserData::~CodecUserData()
{
    Release();
}

VideoCodecAVBufferInfo::VideoCodecAVBufferInfo(uint32_t argBufferIndex,
    std::shared_ptr<OHOS::Media::AVBuffer> argBuffer)
    : bufferIndex(argBufferIndex), buffer(argBuffer)
{
}

std::shared_ptr<OHOS::Media::AVBuffer> VideoCodecAVBufferInfo::GetCopyAVBuffer()
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("CodecBufferInfo OH_AVBuffer_Create with size: %{public}d", buffer->memory_->GetSize());
    auto allocator = Media::AVAllocatorFactory::CreateSharedAllocator(Media::MemoryFlag::MEMORY_READ_WRITE);
    CHECK_RETURN_RET_ELOG(allocator == nullptr, nullptr, "create allocator failed");
    std::shared_ptr<Media::AVBuffer> destBuffer = Media::AVBuffer::CreateAVBuffer(allocator,
        buffer->memory_->GetCapacity());
    CHECK_RETURN_RET_ELOG(destBuffer == nullptr, nullptr, "destBuffer is null");
    auto sourceAddr = buffer->memory_->GetAddr();
    auto destAddr = destBuffer->memory_->GetAddr();
    errno_t cpyRet = memcpy_s(reinterpret_cast<void *>(destAddr), buffer->memory_->GetSize(),
        reinterpret_cast<void *>(sourceAddr), buffer->memory_->GetSize());
    CHECK_PRINT_ELOG(0 != cpyRet, "CodecBufferInfo memcpy_s failed. %{public}d", cpyRet);
    destBuffer->pts_ = buffer->pts_;
    destBuffer->flag_ = buffer->flag_;
    destBuffer->memory_->SetSize(buffer->memory_->GetSize());
    return destBuffer;
    // LCOV_EXCL_STOP
}

std::shared_ptr<OHOS::Media::AVBuffer> VideoCodecAVBufferInfo::AddCopyAVBuffer(
    std::shared_ptr<OHOS::Media::AVBuffer> IDRBuffer)
{
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(nullptr == IDRBuffer, IDRBuffer, "AddCopyAVBuffer without IDRBuffer!");
    int32_t destBufferSize = IDRBuffer->memory_->GetSize() + buffer->memory_->GetSize();
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
    auto sourceAddr = buffer->memory_->GetAddr();
    cpyRet = memcpy_s(reinterpret_cast<void *>(destAddr), buffer->memory_->GetSize(),
        reinterpret_cast<void *>(sourceAddr), buffer->memory_->GetSize());
    CHECK_PRINT_ELOG(0 != cpyRet, "CodecBufferInfo memcpy_s I frame failed. %{public}d", cpyRet);
    destBuffer->memory_->SetSize(destBufferSize);
    destBuffer->flag_ = IDRBuffer->flag_ | buffer->flag_;
    MEDIA_INFO_LOG("CodecBufferInfo copy with size: %{public}d, %{public}d", destBufferSize, destBuffer->flag_);
    return destBuffer;
    // LCOV_EXCL_STOP
}

void VideoCodecUserData::Release()
{
    // LCOV_EXCL_START
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
    // LCOV_EXCL_STOP
}

VideoCodecUserData::~VideoCodecUserData()
{
    Release();
}

} // CameraStandard
} // OHOS
