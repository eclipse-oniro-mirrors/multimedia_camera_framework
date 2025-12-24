/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "image_info.h"

#include "dp_log.h"
#include "picture_interface.h"
#include "dps_metadata_info.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
ImageInfo::ImageInfo()
{
    DP_DEBUG_LOG("entered.");
}

ImageInfo::ImageInfo(int32_t dataSize, bool isHighQuality, uint32_t cloudFlag, uint32_t captureFlag,
    DpsMetadata dpsMetadata) : dataSize_(dataSize), isHighQuality_(isHighQuality), cloudFlag_(cloudFlag),
    captureFlag_(captureFlag), dpsMetaData_(dpsMetadata)
{
    DP_DEBUG_LOG("entered.");
}

ImageInfo::~ImageInfo()
{
    DP_DEBUG_LOG("entered.");
}

void ImageInfo::SetBuffer(std::unique_ptr<SharedBuffer> sharedBuffer)
{
    sharedBuffer_ = std::move(sharedBuffer);
    SetType(CallbackType::IMAGE_PROCESS_DONE);
}

void ImageInfo::SetPicture(const std::shared_ptr<PictureIntf>& picture)
{
    picture_ = picture;
    SetType(CallbackType::IMAGE_PROCESS_YUV_DONE);
}

void ImageInfo::SetError(DpsError error)
{
    error_ = error;
    SetType(CallbackType::IMAGE_ERROR);
}

void ImageInfo::SetType(CallbackType type)
{
    type_ = type;
}

sptr<IPCFileDescriptor> ImageInfo::GetIPCFileDescriptor()
{
    DP_CHECK_RETURN_RET(sharedBuffer_ == nullptr, nullptr);
    DP_CHECK_RETURN_RET(sharedBuffer_->GetFd() == -1, nullptr);
    int fd = dup(sharedBuffer_->GetFd());
    DP_DEBUG_LOG("GetIPCFileDescriptor fd: %{public}d", fd);
    return sptr<IPCFileDescriptor>::MakeSptr(fd);
}

std::shared_ptr<PictureIntf> ImageInfo::GetPicture()
{
    return picture_;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
