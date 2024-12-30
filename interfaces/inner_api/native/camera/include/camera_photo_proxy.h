/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_PHOTO_PROXY_H
#define OHOS_CAMERA_PHOTO_PROXY_H

#include "message_parcel.h"
#include "surface.h"

namespace OHOS {
namespace CameraStandard {

class CameraPhotoProxy : public RefBase {
public:
    CameraPhotoProxy();
    CameraPhotoProxy(BufferHandle* bufferHandle, int32_t format, int32_t photoWidth,
        int32_t photoHeight, bool isHighQuality, int32_t captureId);
    CameraPhotoProxy(BufferHandle* bufferHandle, int32_t format, int32_t photoWidth,
        int32_t photoHeight, bool isHighQuality, int32_t captureId, int32_t burstSeqId);
    virtual ~CameraPhotoProxy();
    void ReadFromParcel(MessageParcel &parcel);
    void WriteToParcel(MessageParcel &parcel);
    void SetDeferredAttrs(std::string photoId, int32_t deferredProcType, uint64_t fileSize, int32_t imageFormat);
    void SetLocation(double latitude, double longitude);
    int32_t CameraFreeBufferHandle();

    BufferHandle* bufferHandle_;
    int32_t format_;
    int32_t photoWidth_;
    int32_t photoHeight_;
    size_t fileSize_;
    bool isHighQuality_;
    std::mutex mutex_;
    std::string photoId_;
    int32_t deferredProcType_;
    int32_t isDeferredPhoto_;
    double latitude_;
    double longitude_;
    int32_t captureId_;
    int32_t burstSeqId_;
    sptr<Surface> photoSurface_;
    int32_t imageFormat_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DEFERRED_PHOTO_PROXY_H