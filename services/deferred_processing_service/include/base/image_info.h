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
#include "dps_metadata_info.h"
#include "ipc_file_descriptor.h"
#include "shared_buffer.h"

namespace OHOS {
namespace CameraStandard {
class PictureIntf;
namespace DeferredProcessing {
class ImageInfoSingle {
public:
    ImageInfoSingle();
    ImageInfoSingle(
        int32_t dataSize, bool isHighQuality, uint32_t cloudFlag, uint32_t captureFlag, DpsMetadata metadata);

    virtual ~ImageInfoSingle();
    ImageInfoSingle& operator=(const ImageInfoSingle&) = delete;
    ImageInfoSingle(const ImageInfoSingle&);
    ImageInfoSingle(ImageInfoSingle&& rhs);
    ImageInfoSingle& operator=(ImageInfoSingle&&) = delete;

    void SetBuffer(std::unique_ptr<SharedBuffer> sharedBuffer);
    void SetPicture(const std::shared_ptr<PictureIntf>& picture);
    void SetPicture(const std::shared_ptr<PictureIntf>& picture, CallbackType type);
    sptr<IPCFileDescriptor> GetIPCFileDescriptor();
    std::shared_ptr<PictureIntf> GetPicture();
    void SetError(DpsError error);

    inline int32_t GetDataSize() const
    {
        return dataSize_;
    }

    inline void SetDataSize(int32_t size)
    {
        dataSize_ = size;
    }

    inline bool IsHighQuality() const
    {
        return isHighQuality_;
    }

    inline uint32_t GetCloudFlag() const
    {
        return cloudFlag_;
    }

    inline uint32_t GetCaptureFlag() const
    {
        return captureFlag_;
    }

    inline CallbackType GetType()
    {
        return type_;
    }

    inline DpsError GetErrorCode()
    {
        return error_;
    }

    inline DpsMetadata GetMetaData()
    {
        return dpsMetaData_;
    }

    void SetType(CallbackType type);

protected:
    int32_t dataSize_ { 0 };
    bool isHighQuality_ { false };

    uint32_t cloudFlag_ { 0 };
    uint32_t captureFlag_ { 0 };
    DpsMetadata dpsMetaData_;
    DpsError error_ { DpsError::DPS_NO_ERROR };
    CallbackType type_ { CallbackType::NONE };
    std::unique_ptr<SharedBuffer> sharedBuffer_ { nullptr };
    std::shared_ptr<PictureIntf> picture_ { nullptr };
};

class ImageInfo : public ImageInfoSingle {
public:
    enum BuffersType {
        ONE_EFFECT_NEED_ORIGIN, // deepCopy then encode and wm
        ONE_EFFECT,             // v1_4
        ONE_EFFECT_ONE_ORIGIN,  // encode and wm
        INVALID_BUFFERS_TYPE,
    };

    ImageInfo() : ImageInfoSingle() {}
    ImageInfo(int32_t dataSize, bool isHighQuality, uint32_t cloudFlag, uint32_t captureFlag, DpsMetadata metadata)
        : ImageInfoSingle(dataSize, isHighQuality, cloudFlag, captureFlag, metadata)
    {}
    ImageInfo(ImageInfoSingle&& rhs) : ImageInfoSingle(std::move(rhs)) {}
    ~ImageInfo() {}
    ImageInfo(const ImageInfo&) = delete;
    ImageInfo& operator=(const ImageInfo&) = delete;
    ImageInfo(ImageInfo&&) = delete;
    ImageInfo& operator=(ImageInfo&&) = delete;
    std::vector<std::unique_ptr<ImageInfoSingle>> imageInfoSingles_;
    BuffersType buffersType_ = INVALID_BUFFERS_TYPE;
    bool isSupportedOriginImg_ = false;
    bool isEnableOriginImg_ = false;

    std::shared_ptr<CameraStandard::PictureIntf> GetLcdImage() const
    {
        return lcdImage_;
    };
    void SetLcdImage(std::shared_ptr<CameraStandard::PictureIntf> lcdImage)
    {
        lcdImage_ = lcdImage;
    }

private:
    std::shared_ptr<CameraStandard::PictureIntf> lcdImage_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_IMAGE_INFO_H