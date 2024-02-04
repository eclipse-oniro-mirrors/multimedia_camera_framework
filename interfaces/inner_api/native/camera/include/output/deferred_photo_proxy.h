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

#include <refbase.h>
#include "message_parcel.h"

namespace OHOS {
namespace CameraStandard {
enum DeferredProcType {
    BACKGROUND = 0,
    OFFLINE,
};

class DeferredPhotoProxy : public RefBase {
public:
    DeferredPhotoProxy();
    DeferredPhotoProxy(const BufferHandle* bufferHandle, std::string imageId, int32_t deferredProcType);
    DeferredPhotoProxy(const BufferHandle* bufferHandle, std::string imageId, int32_t deferredProcType,
        int32_t thumbnailWidth, int32_t thumbnailHeight);
    DeferredPhotoProxy(const BufferHandle* bufferHandle, std::string imageId, int32_t deferredProcType,
        uint8_t* buffer, size_t fileSize);
    virtual ~DeferredPhotoProxy();
    void ReadFromParcel(MessageParcel &parcel);
    void WriteToParcel(MessageParcel &parcel);
    std::string GetPhotoId();
    DeferredProcType GetDeferredProcType();
    void* GetFileDataAddr();
    size_t GetFileSize();
    int32_t GetWidth();
    int32_t GetHeight();

private:
    uint8_t* buffer_;
    const BufferHandle* bufferHandle_;
    std::string photoId_;
    int32_t deferredProcType_;
    int32_t thumbnailWidth_;
    int32_t thumbnailHeight_;
    void* fileDataAddr_;
    size_t fileSize_;
    bool isMmaped_;
    std::mutex mutex_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DEFERRED_PHOTO_PROXY_H