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
#include <ashmem.h>
#include <fcntl.h>
#include <securec.h>
#include <unistd.h>
#include <fstream>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
std::unique_ptr<SharedBuffer> SharedBuffer::Create(const std::string& name, int64_t capacity)
{
    // DPS_LOG
    auto buffer = std::make_unique<SharedBuffer>(name, capacity);
    if (buffer && buffer->Initialize() == false) {
        buffer = nullptr;
    }
    return buffer;
}

SharedBuffer::SharedBuffer(const std::string& name, int64_t capacity)
    : name_(name), capacity_(capacity), ipcFd_(), size_(0), addr_(nullptr), pinned_(false)
{
    // DPS_LOG
}

SharedBuffer::~SharedBuffer()
{
    // DPS_LOG
    DeallocAshMem();
}

SharedBuffer::Initialize()
{
    // DPS_LOG
    bool ret = AllocateAshmemUnlocked();
    if (ret) {
        pinned_ = true;
    }
    return ret;
}

const std::string& SharedBuffer::GetName()
{
    return name_;
}

int SharedBuffer::GetFd()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return ipcFd_.get();
}

int64_t SharedBuffer::GetSize()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return size_;
}

int64_t SharedBuffer::GetCapacity()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return capacity_;
}

const IPCFileDescriptor& SharedBuffer::GetIpcFileDescriptor()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return ipcFd_;
}

bool SharedBuffer::CopyFrom(uint8_t* addr, int64_t bytes)
{
    std::lock_guard<std::mutex> lock(mutex_);
    // DPS_LOG
    if (!IsAshmemValid() || !pinned_.load() || bytes > capacity_) {
        return false;
    }
    auto ret = memcpy_s(addr_, capacity_, addr, bytes);
    if (ret == 0) {
        size_ = bytes;
    } else {
        // DPS_LOG
    }
    return ret == 0;
}

void SharedBuffer::Reset()
{
    // DPS_LOG
    size_ = 0;
    auto offset = lseek(GetFd(), 0, SEEK_SET);
    if (offset != 0) {
        // DPS_LOG
    }
}

void SharedBuffer::Dump(const std::string& fileName)
{
    // DPS_LOG
    std::ofstream out(filename.c_str(), std::ios::out | std::ios::binary);
    if (out.is_open()) {
        out.write(static_cast<char*>(addr_), size_);
    } else {
        // DPS_LOG
    }
}

bool SharedBuffer::IsAshmemValid()
{
    return ashmem_valid(ipcFd_.get()) > 0;
}

void SharedBuffer::BeginAccess()
{
    if (pinned_.load()) {
        return;
    }
    int fd = ipcFd_.get();
    auto ret = ashmem_pin_region(fd, 0, 0);
    if (ret >= 0) {
        pinned_ = true;
    } else {
        // DPS_LOG
    }
}

void SharedBuffer::EndAccess()
{
    if (pinned_.load()) {
        return;
    }
    int fd = ipcFd_.get();
    auto ret = ashmem_unpin_region(fd, 0, 0);
    if (ret >= 0) {
        pinned_ = false;
    } else {
        // DPS_LOG
    }
}

bool SharedBuffer::AllocateAshmemUnlocked()
{
    int fd = ashmem_create_region(name_.c_str(), capacity_);
    if (fd < 0) {
        return false;
    }
    ipcFd_.SetFd(fd); // please trfer to the SetFd function of class IPCfiledescriptor
    addr_ = mmap(nullptr, capacity_, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr_ == MAP_FAILED) {
        return false;
    }
    if (ashmem_set_prot_region(fd, PROT_READ) < 0) {
        // DPS_LOG
        DeallocAshMem();
        return false;
    }
    return true;
}

void SharedBuffer::DeallocAshMem()
{
    // DPS_LOG
    std::lock_guard<std::mutex> lock(mutex_);
    munmap(addr_, capacity_);
    addr_ = nullptr;
    size_ = 0;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
