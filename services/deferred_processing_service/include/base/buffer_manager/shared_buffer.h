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

#ifndef OHOS_DEFERRED_PROCESSING_SERVICE_SHARED_BUFFER_H
#define OHOS_DEFERRED_PROCESSING_SERVICE_SHARED_BUFFER_H

#include <memory>
#include <string>
#include <mutex>
#include "ipc_file_descriptor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class SharedBuffer {
public:
    static std::unique_ptr<SharedBuffer> Create(const std::string& name, int64_t capacity);
    ~SharedBuffer();
    const std::string& GetName();
    int GetFd();
    int64_t GetSize();
    int64_t GetCapacity();
    const IPCFileDescriptor& GetIpcFileDescriptor();
    bool CopyFrom(uint8_t* addr, int64_t bytes);
    void Reset();
    void Dump(const std::string& fileName);

private:
    friend std::unique_ptr<SharedBuffer> std::make_unique<SharedBuffer>(const std::string&, int64_t&);
    friend class BufferPool;
    SharedBuffer(const std::string& name, int64_t capacity);
    bool Initialize();
    bool IsAshmemValid();
    void BeginAccess();
    void EndAccess();
    bool AllocateAshmemUnlocked();
    void DeallocAshMem();

    const std::string name_;
    const int64_t capacity_;
    std::mutex mutex_;
    IPCFileDescriptor ipcFd_;
    int64_t size_;
    void* addr_;
    std::atomic<bool> pinned_;
};
using SharedBufferPtr = std::shared_ptr<SharedBuffer>;
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PROCESSING_SERVICE_SHARED_BUFFER_H
