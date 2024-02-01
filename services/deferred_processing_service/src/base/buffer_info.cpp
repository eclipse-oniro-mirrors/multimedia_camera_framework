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

#include <unistd.h>

#include "buffer_info.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
BufferInfo::BufferInfo(sptr<IPCFileDescriptor> ipcFileDescriptor, long dataSize, bool isHighQuality)
    : ipcFileDescriptor_(ipcFileDescriptor),
      dataSize_(dataSize),
      isHighQuality_(isHighQuality)
{
}

BufferInfo::~BufferInfo()
{
    ipcFileDescriptor_ = nullptr;
}

sptr<IPCFileDescriptor> BufferInfo::GetIPCFileDescriptor()
{
    return ipcFileDescriptor_;
}

long BufferInfo::GetDataSize()
{
    return dataSize_;
}

bool BufferInfo::IsHighQuality()
{
    return isHighQuality_;
}

void BufferInfo::ReleaseBuffer()
{
    if (ipcFileDescriptor_) {
        close(ipcFileDescriptor_->GetFd());
    }
    return;
}
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
