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

#include "buffer_info.h"

#include <unistd.h>

#include "dp_log.h"
#include "picture_interface.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
BufferInfo::BufferInfo(const std::shared_ptr<SharedBuffer>& sharedBuffer, int32_t dataSize, bool isHighQuality,
    uint32_t cloudImageEnhanceFlag)
    : sharedBuffer_(sharedBuffer),
      dataSize_(dataSize),
      isHighQuality_(isHighQuality),
      cloudImageEnhanceFlag_(cloudImageEnhanceFlag)
{
    DP_DEBUG_LOG("entered.");
}

BufferInfo::~BufferInfo()
{
    DP_DEBUG_LOG("entered.");
    sharedBuffer_ = nullptr;
}

sptr<IPCFileDescriptor> BufferInfo::GetIPCFileDescriptor()
{
    int fd = dup(sharedBuffer_->GetFd());
    DP_DEBUG_LOG("GetIPCFileDescriptor fd: %{public}d", fd);
    return sptr<IPCFileDescriptor>::MakeSptr(fd);
}

BufferInfoExt::BufferInfoExt(std::shared_ptr<PictureIntf> picture, long dataSize, bool isHighQuality,
    uint32_t cloudImageEnhanceFlag)
    : picture_(picture),
      dataSize_(dataSize),
      isHighQuality_(isHighQuality),
      cloudImageEnhanceFlag_(cloudImageEnhanceFlag)
{
}

BufferInfoExt::~BufferInfoExt()
{
    picture_ = nullptr;
}

std::shared_ptr<PictureIntf> BufferInfoExt::GetPicture()
{
    return picture_;
}

long BufferInfoExt::GetDataSize()
{
    return dataSize_;
}

bool BufferInfoExt::IsHighQuality()
{
    return isHighQuality_;
}

uint32_t BufferInfoExt::GetCloudImageEnhanceFlag()
{
    return cloudImageEnhanceFlag_;
}
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
