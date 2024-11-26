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

#include "photo_listener_impl.h"

#include "securec.h"
#include "camera_log.h"
#include "video_key_info.h"
#include "output/photo_output.h"
#include "photo_native_impl.h"
#include "photo_output_impl.h"
#include "inner_api/native/camera/include/camera_photo_proxy.h"
#include "inner_api/native/camera/include/session/capture_session.h"
#include "media_photo_asset_proxy.h"
#include "userfile_manager_types.h"
#include "media_asset_helper.h"

namespace OHOS {
namespace CameraStandard {
static std::mutex g_photoImageMutex;

PhotoListener::PhotoListener(Camera_PhotoOutput* photoOutput, sptr<Surface> surface)
    : photoOutput_(photoOutput), photoSurface_(surface)
{
    if (bufferProcessor_ == nullptr && surface != nullptr) {
        bufferProcessor_ = std::make_shared<PhotoBufferProcessor>(surface);
    }
}

PhotoListener::~PhotoListener()
{
    photoSurface_ = nullptr;
}

void PhotoListener::OnBufferAvailable()
{
    MEDIA_INFO_LOG("PhotoListener::OnBufferAvailable");
    std::lock_guard<std::mutex> lock(g_photoImageMutex);
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("PhotoListener::OnBufferAvailable is called");
    CHECK_AND_RETURN_LOG(photoSurface_ != nullptr, "photoSurface_ is null");

    int64_t timestamp;
    OHOS::Rect damage;
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    SurfaceError surfaceRet = photoSurface_->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    CHECK_AND_RETURN_LOG(surfaceRet == SURFACE_ERROR_OK, "Failed to acquire surface buffer");

    CameraBufferExtraData extraData = GetCameraBufferExtraData(surfaceBuffer);

    if ((callbackFlag_ & CAPTURE_PHOTO_ASSET) != 0) {
        MEDIA_DEBUG_LOG("PhotoListener on capture photo asset callback");
        sptr<SurfaceBuffer> newSurfaceBuffer = SurfaceBuffer::Create();
        DeepCopyBuffer(newSurfaceBuffer, surfaceBuffer);
        photoSurface_->ReleaseBuffer(surfaceBuffer, -1);
        CHECK_AND_RETURN_LOG(newSurfaceBuffer != nullptr, "deep copy buffer failed");

        ExecutePhotoAsset(newSurfaceBuffer, extraData, extraData.isDegradedImage == 0, timestamp);
        MEDIA_DEBUG_LOG("PhotoListener on capture photo asset callback end");
    } else if (extraData.isDegradedImage == 0 && (callbackFlag_ & CAPTURE_PHOTO) != 0) {
        MEDIA_DEBUG_LOG("PhotoListener on capture photo callback");
        ExecutePhoto(surfaceBuffer, timestamp);
        photoSurface_->ReleaseBuffer(surfaceBuffer, -1);
        MEDIA_DEBUG_LOG("PhotoListener on capture photo callback end");
    } else {
        MEDIA_INFO_LOG("PhotoListener on error callback");
        photoSurface_->ReleaseBuffer(surfaceBuffer, -1);
    }
}

CameraBufferExtraData PhotoListener::GetCameraBufferExtraData(const sptr<SurfaceBuffer> &surfaceBuffer)
{
    CameraBufferExtraData extraData;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::captureId, extraData.captureId);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::imageId, extraData.imageId);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::deferredProcessingType, extraData.deferredProcessingType);
    MEDIA_INFO_LOG("imageId:%{public}" PRId64
                   ", deferredProcessingType:%{public}d",
        extraData.imageId,
        extraData.deferredProcessingType);

    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::dataWidth, extraData.photoWidth);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::dataHeight, extraData.photoHeight);
    uint64_t size = static_cast<uint64_t>(surfaceBuffer->GetSize());

    auto res = surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::dataSize, extraData.extraDataSize);
    if (res != 0) {
        MEDIA_INFO_LOG("ExtraGet dataSize error %{public}d", res);
    } else if (extraData.extraDataSize <= 0) {
        MEDIA_INFO_LOG("ExtraGet dataSize OK, but size <= 0");
    } else if (static_cast<uint64_t>(extraData.extraDataSize) > size) {
        MEDIA_INFO_LOG("ExtraGet dataSize OK, but dataSize %{public}d is bigger "
                       "than bufferSize %{public}" PRIu64,
            extraData.extraDataSize,
            size);
    } else {
        MEDIA_INFO_LOG("ExtraGet dataSize %{public}d", extraData.extraDataSize);
        size = static_cast<uint64_t>(extraData.extraDataSize);
    }
    extraData.size = size;

    res = surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::deferredImageFormat, extraData.deferredImageFormat);
    MEDIA_INFO_LOG("deferredImageFormat:%{public}d, width:%{public}d, "
                   "height:%{public}d, size:%{public}" PRId64,
        extraData.deferredImageFormat,
        extraData.photoWidth,
        extraData.photoHeight,
        size);

    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::isDegradedImage, extraData.isDegradedImage);
    MEDIA_INFO_LOG("isDegradedImage:%{public}d", extraData.isDegradedImage);

    return extraData;
}

void PhotoListener::SetCallbackFlag(uint8_t callbackFlag)
{
    callbackFlag_ = callbackFlag;
}

void PhotoListener::SetPhotoAvailableCallback(OH_PhotoOutput_PhotoAvailable callback)
{
    MEDIA_DEBUG_LOG("PhotoListener::SetPhotoAvailableCallback");
    std::lock_guard<std::mutex> lock(g_photoImageMutex);
    MEDIA_INFO_LOG("PhotoListener::SetPhotoAvailableCallback is called");
    if (callback != nullptr) {
        photoCallback_ = callback;
    }
    return;
}

void PhotoListener::UnregisterPhotoAvailableCallback(OH_PhotoOutput_PhotoAvailable callback)
{
    MEDIA_DEBUG_LOG("PhotoListener::UnregisterPhotoAvailableCallback");
    std::lock_guard<std::mutex> lock(g_photoImageMutex);
    MEDIA_INFO_LOG("PhotoListener::UnregisterPhotoAvailableCallback is called");
    if (photoCallback_ != nullptr && callback != nullptr) {
        photoCallback_ = nullptr;
    }
    return;
}

void PhotoListener::SetPhotoAssetAvailableCallback(OH_PhotoOutput_PhotoAssetAvailable callback)
{
    MEDIA_DEBUG_LOG("PhotoListener::SetPhotoAssetAvailableCallback");
    std::lock_guard<std::mutex> lock(g_photoImageMutex);
    MEDIA_INFO_LOG("PhotoListener::SetPhotoAssetAvailableCallback is called");
    if (callback != nullptr) {
        photoAssetCallback_ = callback;
    }
    return;
}

void PhotoListener::UnregisterPhotoAssetAvailableCallback(OH_PhotoOutput_PhotoAssetAvailable callback)
{
    MEDIA_DEBUG_LOG("PhotoListener::UnregisterPhotoAssetAvailableCallback");
    std::lock_guard<std::mutex> lock(g_photoImageMutex);
    MEDIA_INFO_LOG("PhotoListener::UnregisterPhotoAssetAvailableCallback is called");
    if (photoAssetCallback_ != nullptr && callback != nullptr) {
        photoAssetCallback_ = nullptr;
    }
    return;
}

void PhotoListener::ExecutePhoto(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp)
{
    std::shared_ptr<Media::NativeImage> nativeImage = std::make_shared<Media::NativeImage>(surfaceBuffer,
        bufferProcessor_, timestamp);
    CHECK_AND_RETURN_LOG(nativeImage != nullptr, "Create native image failed");

    if (photoCallback_ != nullptr && photoOutput_ != nullptr) {
        OH_PhotoNative *photoNative = photoOutput_->CreateCameraPhotoNative(nativeImage, true);
        CHECK_AND_RETURN_LOG(photoNative != nullptr, "Create photo native failed");

        photoCallback_(photoOutput_, photoNative);
    }
    return;
}

void PhotoListener::ExecutePhotoAsset(sptr<SurfaceBuffer> surfaceBuffer, CameraBufferExtraData extraData,
    bool isHighQuality, int64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    BufferHandle* bufferHandle = surfaceBuffer->GetBufferHandle();
    CHECK_AND_RETURN_LOG(bufferHandle != nullptr, "invalid bufferHandle");

    surfaceBuffer->Map();
    std::string uri = "";
    int32_t cameraShotType = 0;
    std::string burstKey = "";
    CreateMediaLibrary(surfaceBuffer, bufferHandle, extraData, isHighQuality,
        uri, cameraShotType, burstKey, timestamp);
    CHECK_AND_RETURN_LOG(!uri.empty(), "uri is empty");

    auto mediaAssetHelper = Media::MediaAssetHelperFactory::CreateMediaAssetHelper();
    CHECK_AND_RETURN_LOG(mediaAssetHelper != nullptr, "create media asset helper failed");

    auto mediaAsset = mediaAssetHelper->GetMediaAsset(uri, cameraShotType, burstKey);
    CHECK_AND_RETURN_LOG(mediaAsset != nullptr, "Create photo asset failed");

    if (photoAssetCallback_ != nullptr && photoOutput_ != nullptr) {
        photoAssetCallback_(photoOutput_, mediaAsset);
    }
    return;
}

void PhotoListener::DeepCopyBuffer(sptr<SurfaceBuffer> newSurfaceBuffer, sptr<SurfaceBuffer> surfaceBuffer)
{
    CAMERA_SYNC_TRACE;
    BufferRequestConfig requestConfig = {
        .width = surfaceBuffer->GetWidth(),
        .height = surfaceBuffer->GetHeight(),
        .strideAlignment = 0x8, // default stride is 8 Bytes.
        .format = surfaceBuffer->GetFormat(),
        .usage = surfaceBuffer->GetUsage(),
        .timeout = 0,
        .colorGamut = surfaceBuffer->GetSurfaceBufferColorGamut(),
        .transform = surfaceBuffer->GetSurfaceBufferTransform(),
    };
    auto allocErrorCode = newSurfaceBuffer->Alloc(requestConfig);
    MEDIA_INFO_LOG("SurfaceBuffer alloc ret: %d", allocErrorCode);
    if (memcpy_s(newSurfaceBuffer->GetVirAddr(), newSurfaceBuffer->GetSize(),
        surfaceBuffer->GetVirAddr(), surfaceBuffer->GetSize()) != EOK) {
        MEDIA_ERR_LOG("PhotoListener memcpy_s failed");
    }
}

void PhotoListener::CreateMediaLibrary(sptr<SurfaceBuffer> surfaceBuffer, BufferHandle *bufferHandle,
    CameraBufferExtraData extraData, bool isHighQuality, std::string &uri,
    int32_t &cameraShotType, std::string &burstKey, int64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    CHECK_AND_RETURN_LOG(bufferHandle != nullptr, "bufferHandle is nullptr");

    MEDIA_DEBUG_LOG("PhotoListener ExecutePhotoAsset captureId:%{public}d imageId:%{public}" PRId64
        ", deferredProcessingType:%{public}d",
        extraData.captureId, extraData.imageId, extraData.deferredProcessingType);
    MEDIA_DEBUG_LOG("deferredImageFormat:%{public}d, width:%{public}d, height:%{public}d, size:%{public}" PRId64,
        extraData.deferredImageFormat, extraData.photoWidth, extraData.photoHeight, extraData.size);

    int32_t format = bufferHandle->format;
    sptr<CameraPhotoProxy> photoProxy;
    std::string imageIdStr = std::to_string(extraData.imageId);
    photoProxy = new(std::nothrow) CameraPhotoProxy(bufferHandle, format, extraData.photoWidth, extraData.photoHeight,
        isHighQuality, extraData.captureId);
    CHECK_AND_RETURN_LOG(photoProxy != nullptr, "Failed to new photoProxy");

    photoProxy->SetDeferredAttrs(imageIdStr, extraData.deferredProcessingType, extraData.size,
        extraData.deferredImageFormat);
    auto photoOutput = photoOutput_->GetInnerPhotoOutput();
    if (photoOutput && photoOutput->GetSession()) {
        auto settings = photoOutput->GetDefaultCaptureSetting();
        if (settings) {
            auto location = std::make_shared<Location>();
            settings->GetLocation(location);
            photoProxy->SetLocation(location->latitude, location->longitude);
        }
        photoOutput->GetSession()->CreateMediaLibrary(photoProxy, uri, cameraShotType, burstKey, timestamp,
            extraData.captureId);
    }
}

RawPhotoListener::RawPhotoListener(Camera_PhotoOutput* photoOutput, const sptr<Surface> rawPhotoSurface)
    : photoOutput_(photoOutput), rawPhotoSurface_(rawPhotoSurface)
{
    if (bufferProcessor_ == nullptr && rawPhotoSurface != nullptr) {
        bufferProcessor_ = std::make_shared<PhotoBufferProcessor>(rawPhotoSurface);
    }
}

RawPhotoListener::~RawPhotoListener()
{
    rawPhotoSurface_ = nullptr;
}

void RawPhotoListener::OnBufferAvailable()
{
    MEDIA_DEBUG_LOG("RawPhotoListener::OnBufferAvailable");
    std::lock_guard<std::mutex> lock(g_photoImageMutex);
    MEDIA_INFO_LOG("RawPhotoListener::OnBufferAvailable is called");
    CHECK_AND_RETURN_LOG(rawPhotoSurface_ != nullptr, "rawPhotoSurface_ is null");

    int64_t timestamp;
    OHOS::Rect damage;
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    SurfaceError surfaceRet = rawPhotoSurface_->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    CHECK_AND_RETURN_LOG(surfaceRet == SURFACE_ERROR_OK, "RawPhotoListener failed to acquire surface buffer");

    int32_t isDegradedImage;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::isDegradedImage, isDegradedImage);
    if (isDegradedImage == 0) {
        ExecuteRawPhoto(surfaceBuffer, timestamp);
        rawPhotoSurface_->ReleaseBuffer(surfaceBuffer, -1);
    }
}

void RawPhotoListener::ExecuteRawPhoto(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp)
{
    std::shared_ptr<Media::NativeImage> nativeImage = std::make_shared<Media::NativeImage>(surfaceBuffer,
        bufferProcessor_, timestamp);
    CHECK_AND_RETURN_LOG(nativeImage != nullptr, "Create native image failed");

    if (callback_ != nullptr && photoOutput_ != nullptr) {
        OH_PhotoNative *photoNative = photoOutput_->CreateCameraPhotoNative(nativeImage, false);
        CHECK_AND_RETURN_LOG(photoNative != nullptr, "Create photo native failed");

        callback_(photoOutput_, photoNative);
    }
    return;
}

void RawPhotoListener::SetCallback(OH_PhotoOutput_PhotoAvailable callback)
{
    MEDIA_DEBUG_LOG("RawPhotoListener::SetCallback");
    std::lock_guard<std::mutex> lock(g_photoImageMutex);
    MEDIA_INFO_LOG("RawPhotoListener::SetCallback is called");
    if (callback != nullptr) {
        callback_ = callback;
    }
}

void RawPhotoListener::UnregisterCallback(OH_PhotoOutput_PhotoAvailable callback)
{
    MEDIA_DEBUG_LOG("RawPhotoListener::UnregisterCallback");
    std::lock_guard<std::mutex> lock(g_photoImageMutex);
    MEDIA_INFO_LOG("RawPhotoListener::UnregisterCallback is called");
    if (callback != nullptr && callback_ != nullptr) {
        callback_ = nullptr;
    }
}

}
}