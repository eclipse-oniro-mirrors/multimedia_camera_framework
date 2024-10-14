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

#ifndef OHOS_DEFERRED_PROCESSING_SERVICE_BUFFER_INFO_H
#define OHOS_DEFERRED_PROCESSING_SERVICE_BUFFER_INFO_H

#include "ipc_file_descriptor.h"
#include "shared_buffer.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class BufferInfo {
public:
    BufferInfo(const std::shared_ptr<SharedBuffer>& sharedBuffer, int32_t dataSize, bool isHighQuality);
    ~BufferInfo();
    sptr<IPCFileDescriptor> GetIPCFileDescriptor();
    int32_t GetDataSize();
    bool IsHighQuality();

private:
    std::shared_ptr<SharedBuffer> sharedBuffer_;
    const int32_t dataSize_;
    const bool isHighQuality_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PROCESSING_SERVICE_BUFFER_INFO_H