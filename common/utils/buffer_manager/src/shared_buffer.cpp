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

#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
// LCOV_EXCL_START
SharedBuffer::SharedBuffer(int64_t capacity)
    : capacity_(capacity), name_("DPS ShareMemory")
{
    MEDIA_DEBUG_LOG("entered, capacity = %{public}" PRId64, capacity_);
}

SharedBuffer::SharedBuffer(int64_t capacity, const std::string& name)
    : capacity_(capacity), name_(name)
{
    MEDIA_DEBUG_LOG("entered, capacity = %{public}" PRId64, capacity_);
}

SharedBuffer::~SharedBuffer()
{
    MEDIA_DEBUG_LOG("entered.");
    DeallocAshmem();
}

int32_t SharedBuffer::Initialize()
{
    return AllocateAshmemUnlocked();
}

int64_t SharedBuffer::GetSize()
{
    return ashmem_ != nullptr ? ashmem_->GetAshmemSize() : INVALID_FD;
}

int32_t SharedBuffer::CopyFrom(uint8_t* address, int64_t bytes)
{
    CHECK_RETURN_RET_ELOG(bytes > capacity_, MEDIA_INVALID_PARAM,
        "buffer failed due to invalid size: %{public}" PRId64 ", capacity: %{public}" PRId64, bytes, capacity_);
    CHECK_RETURN_RET_ELOG(ashmem_ == nullptr, MEDIA_INIT_FAIL, "ashmem is nullptr.");
    MEDIA_DEBUG_LOG("capacity: %{public}" PRId64 ", bytes: %{public}" PRId64, capacity_, bytes);
    auto ret = ashmem_->WriteToAshmem(address, bytes, 0);
    CHECK_RETURN_RET_ELOG(!ret, MEDIA_ERR, "copy failed.");
    return MEDIA_OK;
}

void SharedBuffer::Reset()
{
    auto offset = lseek(GetFd(), 0, SEEK_SET);
    CHECK_RETURN_ELOG(offset != MEDIA_OK, "failed to reset, error = %{public}s.", std::strerror(errno));
    MEDIA_INFO_LOG("reset success.");
}

int32_t SharedBuffer::AllocateAshmemUnlocked()
{
    ashmem_ = Ashmem::CreateAshmem(name_.data(), capacity_);
    CHECK_RETURN_RET_ELOG(ashmem_ == nullptr, MEDIA_INIT_FAIL,
        "buffer create ashmem failed. capacity: %{public}" PRId64, capacity_);
    int fd = ashmem_->GetAshmemFd();
    MEDIA_DEBUG_LOG("size: %{public}" PRId64 ", fd: %{public}d", capacity_, fd);
    auto ret = ashmem_->MapReadAndWriteAshmem();
    CHECK_RETURN_RET_ELOG(!ret, MEDIA_ERR, "mmap failed.");
    return MEDIA_OK;
}

void SharedBuffer::DeallocAshmem()
{
    CHECK_RETURN(ashmem_ == nullptr);
    ashmem_->UnmapAshmem();
    ashmem_->CloseAshmem();
    ashmem_ = nullptr;
    MEDIA_DEBUG_LOG("dealloc ashmem capacity(%{public}" PRId64 ") success.", capacity_);
}

int SharedBuffer::GetFd() const
{
    return ashmem_ != nullptr ? ashmem_->GetAshmemFd() : INVALID_FD;
}
// LCOV_EXCL_STOP
} // namespace CameraStandard
} // namespace OHOS
