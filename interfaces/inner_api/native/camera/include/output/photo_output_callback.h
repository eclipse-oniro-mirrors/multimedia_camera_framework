/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_PHOTO_OUTPUT_CALLBACK_H
#define OHOS_CAMERA_PHOTO_OUTPUT_CALLBACK_H

#include "hstream_capture_photo_callback_stub.h"
#include "hstream_capture_thumbnail_callback_stub.h"
#include "stream_capture_photo_asset_callback_stub.h"
#include <native_image.h>
#include <pixel_map.h>


namespace OHOS {
namespace CameraStandard {
class PhotoOutput;
namespace DeferredProcessing {
class TaskManager;
}
class PhotoAvailableCallback {
public:
    PhotoAvailableCallback() = default;
    virtual ~PhotoAvailableCallback() = default;

    virtual void OnPhotoAvailable(const std::shared_ptr<Media::NativeImage> nativeImage, bool isRaw) const = 0;
};

class PhotoAssetAvailableCallback {
public:
    PhotoAssetAvailableCallback() = default;
    virtual ~PhotoAssetAvailableCallback() = default;

    virtual void OnPhotoAssetAvailable(const int32_t captureId, const std::string &uri,
        int32_t cameraShotType, const std::string &burstKey) const = 0;
};

class ThumbnailCallback {
public:
    ThumbnailCallback() = default;
    virtual ~ThumbnailCallback() = default;

    virtual void OnThumbnailAvailable(int32_t captureId, int64_t timestamp,
        std::unique_ptr<Media::PixelMap> pixelMap) const = 0;
};

class CameraBufferProcessor : public Media::IBufferProcessor {
public:
    explicit CameraBufferProcessor(sptr<Surface> surface) : surface_(surface) {}
    ~CameraBufferProcessor()
    {
        surface_ = nullptr;
    }
    void BufferRelease(sptr<SurfaceBuffer>& buffer) override
    {
        if (surface_ != nullptr) {
            surface_->ReleaseBuffer(buffer, -1);
        }
    }

private:
    wptr<Surface> surface_ = nullptr;
};

class HStreamCapturePhotoCallbackImpl : public HStreamCapturePhotoCallbackStub {
public:
    explicit HStreamCapturePhotoCallbackImpl(PhotoOutput* photoOutput) : innerPhotoOutput_(photoOutput) {}

    ~HStreamCapturePhotoCallbackImpl() = default;

    int32_t OnPhotoAvailable(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp, bool isRaw) override;

    inline sptr<PhotoOutput> GetPhotoOutput()
    {
        return innerPhotoOutput_.promote();
    }

private:
    wptr<PhotoOutput> innerPhotoOutput_ = nullptr;
};

class HStreamCapturePhotoAssetCallbackImpl : public StreamCapturePhotoAssetCallbackStub {
public:
    explicit HStreamCapturePhotoAssetCallbackImpl(PhotoOutput *photoOutput) : innerPhotoOutput_(photoOutput)
    {}

    ~HStreamCapturePhotoAssetCallbackImpl() = default;

    int32_t OnPhotoAssetAvailable(
        int32_t captureId, const std::string &uri, int32_t cameraShotType, const std::string &burstKey) override;

    inline sptr<PhotoOutput> GetPhotoOutput()
    {
        return innerPhotoOutput_.promote();
    }

private:
    wptr<PhotoOutput> innerPhotoOutput_ = nullptr;
};

class HStreamCaptureThumbnailCallbackImpl : public HStreamCaptureThumbnailCallbackStub {
public:
    explicit HStreamCaptureThumbnailCallbackImpl(PhotoOutput* photoOutput) : innerPhotoOutput_(photoOutput) {}

    ~HStreamCaptureThumbnailCallbackImpl() = default;

    int32_t OnThumbnailAvailable(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp) override;

    inline sptr<PhotoOutput> GetPhotoOutput()
    {
        return innerPhotoOutput_.promote();
    }

private:
    std::unique_ptr<Media::PixelMap> CreatePixelMapFromSurfaceBuffer(sptr<SurfaceBuffer> &surfaceBuffer,
        int32_t width, int32_t height, bool isHdr);
    std::unique_ptr<Media::PixelMap> SetPixelMapYuvInfo(sptr<SurfaceBuffer> &surfaceBuffer,
        std::unique_ptr<Media::PixelMap> pixelMap, bool isHdr);

    wptr<PhotoOutput> innerPhotoOutput_ = nullptr;
};

class PhotoNativeConsumer : public IBufferConsumerListener {
public:
    explicit PhotoNativeConsumer(wptr<PhotoOutput> photoOutput);
    ~PhotoNativeConsumer() override;
    void OnBufferAvailable() override;
    void ClearTaskManager();
    std::shared_ptr<DeferredProcessing::TaskManager> GetDefaultTaskManager();

private:
    void ExecuteOnBufferAvailable();
    void ExecutePhotoAvailable(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp);
    void ExecutePhotoAssetAvailable(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp);

    std::mutex taskManagerMutex_;
    std::shared_ptr<DeferredProcessing::TaskManager> taskManager_ = nullptr;

    wptr<PhotoOutput> innerPhotoOutput_ = nullptr;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_PHOTO_OUTPUT_CALLBACK_H
