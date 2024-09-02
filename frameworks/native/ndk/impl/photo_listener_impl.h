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

#ifndef OHOS_PHOTO_LISTENER_IMPL_H
#define OHOS_PHOTO_LISTENER_IMPL_H

#include "kits/native/include/camera/photo_output.h"
#include "surface.h"
#include "native_image.h"
#include "inner_api/native/camera/include/utils/camera_buffer_handle_utils.h"

namespace OHOS {
namespace CameraStandard {

class PhotoBufferProcessor : public Media::IBufferProcessor {
public:
    explicit PhotoBufferProcessor(sptr<Surface> photoSurface) : photoSurface_(photoSurface) {}
    ~PhotoBufferProcessor()
    {
        photoSurface_ = nullptr;
    }
    void BufferRelease(sptr<SurfaceBuffer>& buffer) override
    {
        if (photoSurface_ != nullptr) {
            photoSurface_->ReleaseBuffer(buffer, -1);
        }
    }

private:
    sptr<Surface> photoSurface_ = nullptr;
};

class PhotoListener : public IBufferConsumerListener {
public:
    explicit PhotoListener(Camera_PhotoOutput* photoOutput, sptr<Surface> surface);
    ~PhotoListener();
    void OnBufferAvailable() override;
    void SetCallbackFlag(uint8_t callbackFlag);
    void SetPhotoAvailableCallback(OH_PhotoOutput_PhotoAvailable callback);
    void SetPhotoAssetAvailableCallback(OH_PhotoOutput_PhotoAssetAvailable callback);
    void UnregisterPhotoAvailableCallback(OH_PhotoOutput_PhotoAvailable callback);
    void UnregisterPhotoAssetAvailableCallback(OH_PhotoOutput_PhotoAssetAvailable callback);

private:
    void ExecutePhoto(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp);
    void ExecutePhotoAsset(sptr<SurfaceBuffer> surfaceBuffer, CameraBufferExtraData extraData,
        bool isHighQuality, int64_t timestamp);
    void DeepCopyBuffer(sptr<SurfaceBuffer> newSurfaceBuffer, sptr<SurfaceBuffer> surfaceBuffer);
    void CreateMediaLibrary(sptr<SurfaceBuffer> surfaceBuffer, BufferHandle *bufferHandle,
        CameraBufferExtraData extraData, bool isHighQuality, std::string &uri,
        int32_t &cameraShotType, std::string &burstKey, int64_t timestamp);
    CameraBufferExtraData GetCameraBufferExtraData(const sptr<SurfaceBuffer> &surfaceBuffer);

    Camera_PhotoOutput* photoOutput_;
    sptr<Surface> photoSurface_;
    OH_PhotoOutput_PhotoAvailable photoCallback_ = nullptr;
    OH_PhotoOutput_PhotoAssetAvailable photoAssetCallback_ = nullptr;
    uint8_t callbackFlag_ = 0;
    std::shared_ptr<PhotoBufferProcessor> bufferProcessor_;
};

class RawPhotoListener : public IBufferConsumerListener {
public:
    explicit RawPhotoListener(Camera_PhotoOutput* photoOutput, const sptr<Surface> rawPhotoSurface);
    ~RawPhotoListener();
    void OnBufferAvailable() override;
    void SetCallback(OH_PhotoOutput_PhotoAvailable callback);
    void UnregisterCallback(OH_PhotoOutput_PhotoAvailable callback);

private:
    void ExecuteRawPhoto(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp);

    Camera_PhotoOutput* photoOutput_;
    sptr<Surface> rawPhotoSurface_;
    OH_PhotoOutput_PhotoAvailable callback_ = nullptr;
    std::shared_ptr<PhotoBufferProcessor> bufferProcessor_;
};

} // namespace CameraStandard
} // namespace OHOS

#endif // OHOS_PHOTO_LISTENER_IMPL_H