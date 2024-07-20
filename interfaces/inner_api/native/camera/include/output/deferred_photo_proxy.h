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

#ifndef OHOS_CAMERA_DEFERRED_PHOTO_PROXY_H
#define OHOS_CAMERA_DEFERRED_PHOTO_PROXY_H

#include <buffer_handle_parcel.h>
#include <mutex>
#include <refbase.h>

#include "buffer_handle.h"
#include "message_parcel.h"
#include "photo_proxy.h"

namespace OHOS {
namespace CameraStandard {

class DeferredPhotoProxy : public Media::PhotoProxy {
public:
    DeferredPhotoProxy();
    DeferredPhotoProxy(const BufferHandle* bufferHandle, std::string imageId, int32_t deferredProcType);
    DeferredPhotoProxy(const BufferHandle* bufferHandle, std::string imageId, int32_t deferredProcType,
        int32_t photoWidth, int32_t photoHeight);
    DeferredPhotoProxy(const BufferHandle* bufferHandle, std::string imageId, int32_t deferredProcType,
        uint8_t* buffer, size_t fileSize);
    virtual ~DeferredPhotoProxy();
    void ReadFromParcel(MessageParcel &parcel);
    void WriteToParcel(MessageParcel &parcel);
    std::string GetTitle() override;
    std::string GetExtension() override;
    std::string GetPhotoId() override;
    Media::DeferredProcType GetDeferredProcType() override;
    void* GetFileDataAddr() override;
    size_t GetFileSize() override;
    int32_t GetWidth() override;
    int32_t GetHeight() override;
    Media::PhotoFormat GetFormat() override;
    Media::PhotoQuality GetPhotoQuality() override;
    double GetLatitude() override;
    double GetLongitude() override;
    int32_t GetShootingMode() override;
    void Release() override;
    std::string GetBurstKey() override;
    bool IsCoverPhoto() override;

private:
    uint8_t* buffer_;
    const BufferHandle* bufferHandle_;
    std::string photoId_;
    int32_t deferredProcType_;
    int32_t photoWidth_;
    int32_t photoHeight_;
    void* fileDataAddr_;
    size_t fileSize_;
    bool isMmaped_;
    std::mutex mutex_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DEFERRED_PHOTO_PROXY_H