/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "shared_buffer.h"

#include <cerrno>
#include <unistd.h>

#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
SharedBuffer::SharedBuffer(int64_t capacity)
    : capacity_(capacity)
{
    DP_DEBUG_LOG("entered, capacity = %{public}" PRId64, capacity_);
}

SharedBuffer::~SharedBuffer()
{
    DP_DEBUG_LOG("entered.");
    DeallocAshmem();
}

int32_t SharedBuffer::Initialize()
{
    return AllocateAshmemUnlocked();
}

int64_t SharedBuffer::GetSize()
{
    if (ashmem_ != nullptr) {
        return ashmem_->GetAshmemSize();
    }
    return INVALID_FD;
}

int32_t SharedBuffer::CopyFrom(uint8_t* address, int64_t bytes)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(bytes > capacity_, DP_INVALID_PARAM,
        "buffer failed due to invalid size: %{public}" PRId64 ", capacity: %{public}" PRId64, bytes, capacity_);
    DP_CHECK_ERROR_RETURN_RET_LOG(ashmem_ == nullptr, DP_INIT_FAIL, "ashmem is nullptr.");
    DP_DEBUG_LOG("capacity: %{public}" PRId64 ", bytes: %{public}" PRId64, capacity_, bytes);
    auto ret = ashmem_->WriteToAshmem(address, bytes, 0);
    DP_CHECK_ERROR_RETURN_RET_LOG(!ret, DP_ERR, "copy failed.");
    return DP_OK;
}

void SharedBuffer::Reset()
{
    auto offset = lseek(GetFd(), 0, SEEK_SET);
    DP_CHECK_ERROR_PRINT_LOG(offset != DP_OK, "failed to reset, error = %{public}s.", std::strerror(errno));
    DP_INFO_LOG("reset success.");
}

int32_t SharedBuffer::AllocateAshmemUnlocked()
{
    std::string_view name = "DPS ShareMemory";
    ashmem_ = Ashmem::CreateAshmem(name.data(), capacity_);
    DP_CHECK_ERROR_RETURN_RET_LOG(ashmem_ == nullptr, DP_INIT_FAIL,
        "buffer create ashmem failed. capacity: %{public}" PRId64, capacity_);
    int fd = ashmem_->GetAshmemFd();
    DP_DEBUG_LOG("size: %{public}" PRId64 ", fd: %{public}d", capacity_, fd);
    auto ret = ashmem_->MapReadAndWriteAshmem();
    DP_CHECK_ERROR_RETURN_RET_LOG(!ret, DP_MEM_MAP_FAILED, "mmap failed.");
    return DP_OK;
}

void SharedBuffer::DeallocAshmem()
{
    if (ashmem_ != nullptr) {
        ashmem_->UnmapAshmem();
        ashmem_->CloseAshmem();
        ashmem_ = nullptr;
        DP_DEBUG_LOG("dealloc ashmem capacity(%{public}" PRId64 ") success.", capacity_);
    }
}

int SharedBuffer::GetFd() const
{
    if (ashmem_ != nullptr) {
        return ashmem_->GetAshmemFd();
    }
    return INVALID_FD;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
