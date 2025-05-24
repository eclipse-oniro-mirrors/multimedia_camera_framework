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

#ifndef OHOS_CAMERA_DPS_IMAGE_INFO_H
#define OHOS_CAMERA_DPS_IMAGE_INFO_H

#include "basic_definitions.h"
#include "ipc_file_descriptor.h"
#include "shared_buffer.h"

namespace OHOS {
namespace CameraStandard {
class PictureIntf;
namespace DeferredProcessing {
class ImageInfo {
public:
    ImageInfo();
    ImageInfo(int32_t dataSize, bool isHighQuality, uint32_t cloudFlag);
    ~ImageInfo();
    ImageInfo(const ImageInfo&) = delete;
    ImageInfo& operator=(const ImageInfo&) = delete;
    ImageInfo(ImageInfo&&) = delete;
    ImageInfo& operator=(ImageInfo&&) = delete;

    void SetBuffer(std::unique_ptr<SharedBuffer> sharedBuffer);
    void SetPicture(const std::shared_ptr<PictureIntf>& picture);
    sptr<IPCFileDescriptor> GetIPCFileDescriptor();
    std::shared_ptr<PictureIntf> GetPicture();
    void SetError(DpsError error);
    
    inline int32_t GetDataSize() const
    {
        return dataSize_;
    }

    inline bool IsHighQuality() const
    {
        return isHighQuality_;
    }

    inline uint32_t GetCloudFlag() const
    {
        return cloudFlag_;
    }

    inline CallbackType GetType()
    {
        return type_;
    }

    inline DpsError GetErrorCode()
    {
        return error_;
    }

private:
    void SetType(CallbackType type);

    int32_t dataSize_ {0};
    bool isHighQuality_ {false};
    uint32_t cloudFlag_ {0};
    DpsError error_ {DpsError::DPS_NO_ERROR};
    CallbackType type_ {CallbackType::NONE};
    std::unique_ptr<SharedBuffer> sharedBuffer_ {nullptr};
    std::shared_ptr<PictureIntf> picture_ {nullptr};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_IMAGE_INFO_H