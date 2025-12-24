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

#include "output/photo_output_callback.h"

#include <mutex>
#include <securec.h>

#include "photo_output.h"
#include "camera_log.h"
#include "camera_util.h"
#include "image_type.h"
#include "video_key_info.h"
#include <drivers/interface/display/graphic/common/v1_0/cm_color_space.h>
#include <drivers/interface/display/graphic/common/v2_1/cm_color_space.h>
#include "metadata_helper.h"
#include <pixel_map.h>
#include "hdr_type.h"
#include "camera_surface_buffer_util.h"
#include "task_manager.h"
#include "hstream_common.h"
using namespace std;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Display::Graphic::Common::V2_1;
using CM_ColorSpaceType_V2_1 = OHOS::HDI::Display::Graphic::Common::V2_1::CM_ColorSpaceType;
static const std::unordered_map<CM_ColorSpaceType_V2_1, OHOS::ColorManager::ColorSpaceName> COLORSPACE_MAP = {
    {CM_ColorSpaceType_V2_1::CM_COLORSPACE_NONE, OHOS::ColorManager::ColorSpaceName::NONE},
    {CM_ColorSpaceType_V2_1::CM_BT601_EBU_FULL, OHOS::ColorManager::ColorSpaceName::BT601_EBU},
    {CM_ColorSpaceType_V2_1::CM_BT601_SMPTE_C_FULL, OHOS::ColorManager::ColorSpaceName::BT601_SMPTE_C},
    {CM_ColorSpaceType_V2_1::CM_BT709_FULL, OHOS::ColorManager::ColorSpaceName::BT709},
    {CM_ColorSpaceType_V2_1::CM_BT2020_HLG_FULL, OHOS::ColorManager::ColorSpaceName::BT2020_HLG},
    {CM_ColorSpaceType_V2_1::CM_BT2020_PQ_FULL, OHOS::ColorManager::ColorSpaceName::BT2020_PQ},
    {CM_ColorSpaceType_V2_1::CM_BT601_EBU_LIMIT, OHOS::ColorManager::ColorSpaceName::BT601_EBU_LIMIT},
    {CM_ColorSpaceType_V2_1::CM_BT601_SMPTE_C_LIMIT, OHOS::ColorManager::ColorSpaceName::BT601_SMPTE_C_LIMIT},
    {CM_ColorSpaceType_V2_1::CM_BT709_LIMIT, OHOS::ColorManager::ColorSpaceName::BT709_LIMIT},
    {CM_ColorSpaceType_V2_1::CM_BT2020_HLG_LIMIT, OHOS::ColorManager::ColorSpaceName::BT2020_HLG_LIMIT},
    {CM_ColorSpaceType_V2_1::CM_BT2020_PQ_LIMIT, OHOS::ColorManager::ColorSpaceName::BT2020_PQ_LIMIT},
    {CM_ColorSpaceType_V2_1::CM_SRGB_FULL, OHOS::ColorManager::ColorSpaceName::SRGB},
    {CM_ColorSpaceType_V2_1::CM_P3_FULL, OHOS::ColorManager::ColorSpaceName::DISPLAY_P3},
    {CM_ColorSpaceType_V2_1::CM_P3_HLG_FULL, OHOS::ColorManager::ColorSpaceName::P3_HLG},
    {CM_ColorSpaceType_V2_1::CM_P3_PQ_FULL, OHOS::ColorManager::ColorSpaceName::P3_PQ},
    {CM_ColorSpaceType_V2_1::CM_ADOBERGB_FULL, OHOS::ColorManager::ColorSpaceName::ADOBE_RGB},
    {CM_ColorSpaceType_V2_1::CM_SRGB_LIMIT, OHOS::ColorManager::ColorSpaceName::SRGB_LIMIT},
    {CM_ColorSpaceType_V2_1::CM_P3_LIMIT, OHOS::ColorManager::ColorSpaceName::DISPLAY_P3_LIMIT},
    {CM_ColorSpaceType_V2_1::CM_P3_HLG_LIMIT, OHOS::ColorManager::ColorSpaceName::P3_HLG_LIMIT},
    {CM_ColorSpaceType_V2_1::CM_P3_PQ_LIMIT, OHOS::ColorManager::ColorSpaceName::P3_PQ_LIMIT},
    {CM_ColorSpaceType_V2_1::CM_ADOBERGB_LIMIT, OHOS::ColorManager::ColorSpaceName::ADOBE_RGB_LIMIT},
    {CM_ColorSpaceType_V2_1::CM_LINEAR_SRGB, OHOS::ColorManager::ColorSpaceName::LINEAR_SRGB},
    {CM_ColorSpaceType_V2_1::CM_LINEAR_BT709, OHOS::ColorManager::ColorSpaceName::LINEAR_BT709},
    {CM_ColorSpaceType_V2_1::CM_LINEAR_P3, OHOS::ColorManager::ColorSpaceName::LINEAR_P3},
    {CM_ColorSpaceType_V2_1::CM_LINEAR_BT2020, OHOS::ColorManager::ColorSpaceName::LINEAR_BT2020},
    {CM_ColorSpaceType_V2_1::CM_DISPLAY_SRGB, OHOS::ColorManager::ColorSpaceName::DISPLAY_SRGB},
    {CM_ColorSpaceType_V2_1::CM_DISPLAY_P3_SRGB, OHOS::ColorManager::ColorSpaceName::DISPLAY_P3_SRGB},
    {CM_ColorSpaceType_V2_1::CM_DISPLAY_P3_HLG, OHOS::ColorManager::ColorSpaceName::DISPLAY_P3_HLG},
    {CM_ColorSpaceType_V2_1::CM_DISPLAY_P3_PQ, OHOS::ColorManager::ColorSpaceName::DISPLAY_P3_PQ},
    {CM_ColorSpaceType_V2_1::CM_DISPLAY_BT2020_SRGB, OHOS::ColorManager::ColorSpaceName::DISPLAY_BT2020_SRGB},
    {CM_ColorSpaceType_V2_1::CM_DISPLAY_BT2020_HLG, OHOS::ColorManager::ColorSpaceName::DISPLAY_BT2020_HLG},
    {CM_ColorSpaceType_V2_1::CM_BT2020_LOG_FULL, OHOS::ColorManager::ColorSpaceName::H_LOG},
};
static constexpr int32_t PLANE_Y = 0;
static constexpr int32_t PLANE_U = 1;
static constexpr uint8_t PIXEL_SIZE_HDR_YUV = 3;
static constexpr uint8_t HDR_PIXEL_SIZE = 2;
static constexpr uint8_t SDR_PIXEL_SIZE = 1;

int32_t HStreamCapturePhotoCallbackImpl::OnPhotoAvailable(
    sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp, bool isRaw)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HStreamCapturePhotoCallbackImpl OnPhotoAvailable E");
    auto photoOutput = GetPhotoOutput();
    CHECK_RETURN_RET_ELOG(
        photoOutput == nullptr, CAMERA_OK, "HStreamCapturePhotoCallbackImpl::OnPhotoAvailable photoOutput is nullptr");
    auto callback = photoOutput->GetAppPhotoCallback();
    CHECK_RETURN_RET_ELOG(
        callback == nullptr, CAMERA_OK, "HStreamCapturePhotoCallbackImpl::OnPhotoAvailable callback is nullptr");
    CHECK_RETURN_RET_ELOG(surfaceBuffer == nullptr, CAMERA_OK,
        "HStreamCapturePhotoCallbackImpl::OnPhotoAvailable surfaceBuffer is nullptr");
    std::shared_ptr<CameraBufferProcessor> bufferProcessor;
    std::shared_ptr<Media::NativeImage> image =
        std::make_shared<Media::NativeImage>(surfaceBuffer, bufferProcessor, timestamp);
    callback->OnPhotoAvailable(image, isRaw);
    MEDIA_INFO_LOG("HStreamCapturePhotoCallbackImpl OnPhotoAvailable X");
    return CAMERA_OK;
}

int32_t HStreamCapturePhotoCallbackImpl::OnPhotoAvailable(std::shared_ptr<PictureIntf> pictureProxy)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HStreamCapturePhotoCallbackImpl OnPhotoAvailable E");
    auto photoOutput = GetPhotoOutput();
    CHECK_RETURN_RET_ELOG(
        photoOutput == nullptr, CAMERA_OK, "HStreamCapturePhotoCallbackImpl::OnPhotoAvailable photoOutput is nullptr");
    auto callback = photoOutput->GetAppPhotoCallback();
    CHECK_RETURN_RET_ELOG(
        callback == nullptr, CAMERA_OK, "HStreamCapturePhotoCallbackImpl::OnPhotoAvailable callback is nullptr");
    CHECK_RETURN_RET_ELOG(pictureProxy == nullptr, CAMERA_OK,
        "HStreamCapturePhotoCallbackImpl::OnPhotoAvailable pictureProxy is nullptr");
    std::shared_ptr<Media::Picture> picture = pictureProxy->GetPicture();
    callback->OnPhotoAvailable(picture);
    MEDIA_INFO_LOG("HStreamCapturePhotoCallbackImpl OnPhotoAvailable X");
    return CAMERA_OK;
}

int32_t HStreamCapturePhotoAssetCallbackImpl::OnPhotoAssetAvailable(
    const int32_t captureId, const std::string &uri, int32_t cameraShotType, const std::string &burstKey)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HStreamCapturePhotoAssetCallbackImpl OnPhotoAssetAvailable");
    auto photoOutput = GetPhotoOutput();
    CHECK_RETURN_RET_ELOG(photoOutput == nullptr, CAMERA_OK,
        "HStreamCapturePhotoAssetCallbackImpl::OnPhotoAssetAvailable photoOutput is nullptr");
    auto callback = photoOutput->GetAppPhotoAssetCallback();
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_OK,
        "HStreamCapturePhotoAssetCallbackImpl::OnPhotoAssetAvailable callback is nullptr");
    callback->OnPhotoAssetAvailable(captureId, uri, cameraShotType, burstKey);
    photoOutput->NotifyOfflinePhotoOutput(captureId);
    return CAMERA_OK;
}

OHOS::ColorManager::ColorSpaceName GetColorSpace(sptr<SurfaceBuffer> surfaceBuffer)
{
    OHOS::ColorManager::ColorSpaceName colorSpace = OHOS::ColorManager::ColorSpaceName::NONE;
    HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType colorSpaceType;
    GSError gsErr = MetadataHelper::GetColorSpaceType(surfaceBuffer, colorSpaceType);
    if (gsErr != GSERROR_OK) {
        MEDIA_ERR_LOG("Failed to get colorSpaceType from surfaceBuffer!");
        return colorSpace;
    } else {
        MEDIA_INFO_LOG("Get current colorSpaceType is : %{public}d", colorSpaceType);
    }
    CM_ColorSpaceType_V2_1 type2_1 = static_cast<CM_ColorSpaceType_V2_1>(colorSpaceType);
    auto it = COLORSPACE_MAP.find(type2_1);
    if (it != COLORSPACE_MAP.end()) {
        colorSpace = it->second;
        MEDIA_INFO_LOG("Current get colorSpaceName: %{public}d", colorSpace);
    } else {
        MEDIA_ERR_LOG("Current colorSpace is not supported!");
        return colorSpace;
    }
    return colorSpace;
}

void ThumbnailSetColorSpaceAndRotate(std::unique_ptr<Media::PixelMap> &pixelMap, sptr<SurfaceBuffer> surfaceBuffer,
    OHOS::ColorManager::ColorSpaceName colorSpaceName)
{
    int32_t thumbnailrotation = 0;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::dataRotation, thumbnailrotation);
    MEDIA_ERR_LOG("CamThumbnail current rotation is : %{public}d", thumbnailrotation);
    if (!pixelMap) {
        MEDIA_ERR_LOG("CamThumbnail Failed to create PixelMap.");
    } else {
        pixelMap->InnerSetColorSpace(OHOS::ColorManager::ColorSpace(colorSpaceName));
        pixelMap->rotate(thumbnailrotation);
    }
}

int32_t HStreamCaptureThumbnailCallbackImpl::OnThumbnailAvailable(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("CamThumbnail::OnThumbnailAvailable");
    auto photoOutput = GetPhotoOutput();
    CHECK_RETURN_RET_ELOG(
        photoOutput == nullptr, CAMERA_OK, "CamThumbnail::OnThumbnailAvailable photoOutput is nullptr");
    auto callback = photoOutput->GetAppThumbnailCallback();
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_OK, "CamThumbnail::OnThumbnailAvailable callback is nullptr");

    // produce thumbnail
    int32_t thumbnailWidth = 0;
    int32_t thumbnailHeight = 0;
    int32_t burstSeqId = -1;
    int32_t captureId = 0;
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::dataWidth, thumbnailWidth);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::dataHeight, thumbnailHeight);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::burstSequenceId, burstSeqId);
    surfaceBuffer->GetExtraData()->ExtraGet(OHOS::Camera::captureId, captureId);
    MEDIA_INFO_LOG("OnThumbnailAvailable width:%{public}d, height: %{public}d, captureId: %{public}d,"
        "burstSeqId: %{public}d", thumbnailWidth, thumbnailHeight, captureId, burstSeqId);
    OHOS::ColorManager::ColorSpaceName colorSpace = GetColorSpace(surfaceBuffer);
    CHECK_RETURN_RET_ELOG(
        colorSpace == OHOS::ColorManager::ColorSpaceName::NONE, CAMERA_OK, "Thumbnail GetcolorSpace failed!");
    bool isHdr = colorSpace == OHOS::ColorManager::ColorSpaceName::BT2020_HLG;
    // create pixelMap
    std::unique_ptr<Media::PixelMap> pixelMap = CreatePixelMapFromSurfaceBuffer(surfaceBuffer,
        thumbnailWidth, thumbnailHeight, isHdr);
    CHECK_PRINT_ELOG(pixelMap == nullptr, "ThumbnailListener create pixelMap is nullptr");
    ThumbnailSetColorSpaceAndRotate(pixelMap, surfaceBuffer, colorSpace);

    callback->OnThumbnailAvailable(captureId, timestamp, std::move(pixelMap));
    return CAMERA_OK;
}

std::unique_ptr<Media::PixelMap> HStreamCaptureThumbnailCallbackImpl::CreatePixelMapFromSurfaceBuffer(
    sptr<SurfaceBuffer> &surfaceBuffer, int32_t width, int32_t height, bool isHdr)
{
    CHECK_RETURN_RET_ELOG(
        surfaceBuffer == nullptr, nullptr, "CamThumbnail::CreatePixelMapFromSurfaceBuffer surfaceBuffer is nullptr");
    MEDIA_INFO_LOG("CamThumbnail Width:%{public}d, height:%{public}d, isHdr:%{public}d, format:%{public}d",
        width, height, isHdr, surfaceBuffer->GetFormat());
    Media::InitializationOptions options {
        .size = { .width = width, .height = height } };
    options.srcPixelFormat = isHdr ? Media::PixelFormat::YCRCB_P010 : Media::PixelFormat::NV12;
    options.pixelFormat = isHdr ? Media::PixelFormat::YCRCB_P010 : Media::PixelFormat::NV12;
    options.useDMA = true;
    options.editable = isHdr;
    int32_t colorLength = width * height * PIXEL_SIZE_HDR_YUV;
    colorLength = isHdr ? colorLength : colorLength / HDR_PIXEL_SIZE;
    std::unique_ptr<Media::PixelMap> pixelMap = Media::PixelMap::Create(options);
    CHECK_RETURN_RET_ELOG(
        pixelMap == nullptr, nullptr, "CamThumbnail::CreatePixelMapFromSurfaceBuffer pixelMap is nullptr");
    void* nativeBuffer = surfaceBuffer.GetRefPtr();
    RefBase *ref = reinterpret_cast<RefBase *>(nativeBuffer);
    ref->IncStrongRef(ref);
    if (isHdr) {
        pixelMap->SetHdrType(OHOS::Media::ImageHdrType::HDR_VIVID_SINGLE);
    }
    pixelMap->SetPixelsAddr(surfaceBuffer->GetVirAddr(), surfaceBuffer.GetRefPtr(), colorLength,
        Media::AllocatorType::DMA_ALLOC, nullptr);

    MEDIA_DEBUG_LOG("CamThumbnail::CreatePixelMapFromSurfaceBuffer end");
    return SetPixelMapYuvInfo(surfaceBuffer, std::move(pixelMap), isHdr);
}

std::unique_ptr<Media::PixelMap> HStreamCaptureThumbnailCallbackImpl::SetPixelMapYuvInfo(
    sptr<SurfaceBuffer> &surfaceBuffer, std::unique_ptr<Media::PixelMap> pixelMap, bool isHdr)
{
    MEDIA_INFO_LOG("CamThumbnail::SetPixelMapYuvInf enter");
    uint8_t ratio = isHdr ? HDR_PIXEL_SIZE : SDR_PIXEL_SIZE;
    int32_t srcWidth = pixelMap->GetWidth();
    int32_t srcHeight = pixelMap->GetHeight();
    Media::YUVDataInfo yuvDataInfo = { .yWidth = srcWidth,
                                       .yHeight = srcHeight,
                                       .uvWidth = srcWidth / 2,
                                       .uvHeight = srcHeight / 2,
                                       .yStride = srcWidth,
                                       .uvStride = srcWidth,
                                       .uvOffset = srcWidth * srcHeight};
    if (surfaceBuffer == nullptr) {
        pixelMap->SetImageYUVInfo(yuvDataInfo);
        return pixelMap;
    }
    OH_NativeBuffer_Planes *planes = nullptr;
    GSError retVal = surfaceBuffer->GetPlanesInfo(reinterpret_cast<void**>(&planes));
    if (retVal != OHOS::GSERROR_OK || planes == nullptr) {
        pixelMap->SetImageYUVInfo(yuvDataInfo);
        return pixelMap;
    }

    yuvDataInfo.yStride = planes->planes[PLANE_Y].columnStride / ratio;
    yuvDataInfo.uvStride = planes->planes[PLANE_U].columnStride / ratio;
    yuvDataInfo.yOffset = planes->planes[PLANE_Y].offset / ratio;
    yuvDataInfo.uvOffset = planes->planes[PLANE_U].offset / ratio;

    pixelMap->SetImageYUVInfo(yuvDataInfo);
    MEDIA_INFO_LOG("CamThumbnail::SetPixelMapYuvInf end");
    return pixelMap;
}

PhotoNativeConsumer::PhotoNativeConsumer(wptr<PhotoOutput> photoOutput) : innerPhotoOutput_(photoOutput)
{
    MEDIA_INFO_LOG("PhotoNativeConsumer new E");
}

PhotoNativeConsumer::~PhotoNativeConsumer()
{
    MEDIA_INFO_LOG("PhotoNativeConsumer ~ E");
    ClearTaskManager();
}

void PhotoNativeConsumer::OnBufferAvailable()
{
    MEDIA_INFO_LOG("PhotoNativeConsumer OnBufferAvailable E");
    auto photoOutput = innerPhotoOutput_.promote();
    CHECK_RETURN_ELOG(!photoOutput, "OnBufferAvailable photoOutput is null");
    CHECK_RETURN_ELOG(!photoOutput->photoSurface_, "OnBufferAvailable photoNative surface is null");
    auto taskManager = GetDefaultTaskManager();
    CHECK_RETURN_ELOG(!taskManager, "PhotoNativeConsumer OnBufferAvailable task is null");
    wptr<PhotoNativeConsumer> thisPtr(this);
    taskManager->SubmitTask([thisPtr]() {
        auto listener = thisPtr.promote();
        CHECK_EXECUTE(listener, listener->ExecuteOnBufferAvailable());
    });
    MEDIA_INFO_LOG("PhotoNativeConsumer OnBufferAvailable X");
}

void PhotoNativeConsumer::ExecuteOnBufferAvailable()
{
    MEDIA_INFO_LOG("PN_ExecuteOnBufferAvailable E");
    CAMERA_SYNC_TRACE;
    auto photoOutput = innerPhotoOutput_.promote();
    CHECK_RETURN_ELOG(!photoOutput, "ExecuteOnBufferAvailable photoOutput is null");
    CHECK_RETURN_ELOG(!photoOutput->photoSurface_, "ExecuteOnBufferAvailable photoNative surface is null");
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    SurfaceError surfaceRet = photoOutput->photoSurface_->AcquireBuffer(surfaceBuffer, fence, timestamp, damage);
    CHECK_RETURN_ELOG(surfaceRet != SURFACE_ERROR_OK, "PhotoNativeConsumer Failed to acquire surface buffer");
    int32_t isDegradedImage = CameraSurfaceBufferUtil::GetIsDegradedImage(surfaceBuffer);
    MEDIA_INFO_LOG("PhotoNativeConsumer ts isDegradedImage:%{public}d", isDegradedImage);
    MEDIA_INFO_LOG("PhotoNativeConsumer ts is:%{public}" PRId64, timestamp);
    // deep copy surfaceBuffer
    sptr<SurfaceBuffer> newSurfaceBuffer = CameraSurfaceBufferUtil::DeepCopyBuffer(surfaceBuffer);
    // release surfaceBuffer to bufferQueue
    photoOutput->photoSurface_->ReleaseBuffer(surfaceBuffer, -1);
    CHECK_RETURN_ELOG(newSurfaceBuffer == nullptr, "newSurfaceBuffer is null");
    if ((photoOutput->callbackFlag_ & CAPTURE_PHOTO_ASSET) != 0) {
        ExecutePhotoAssetAvailable(newSurfaceBuffer, timestamp);
    } else if (isDegradedImage == 0 && (photoOutput->callbackFlag_ & CAPTURE_PHOTO) != 0) {
        ExecutePhotoAvailable(newSurfaceBuffer, timestamp);
    } else if (isDegradedImage != 0 && (photoOutput->callbackFlag_ & CAPTURE_DEFERRED_PHOTO) != 0) {
        MEDIA_INFO_LOG("PN_ExecuteOnBufferAvailable on abandon callback");
    } else {
        MEDIA_INFO_LOG("PN_ExecuteOnBufferAvailable on error callback");
    }
    MEDIA_INFO_LOG("PN_ExecuteOnBufferAvailable X");
}

void PhotoNativeConsumer::ExecutePhotoAvailable(sptr<SurfaceBuffer> surfaceBuffer, int64_t timestamp)
{
    MEDIA_INFO_LOG("PN_ExecutePhotoAvailable E");
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_ELOG(surfaceBuffer == nullptr, "ExecutePhotoAvailable surfaceBuffer is null");
    auto photoOutput = innerPhotoOutput_.promote();
    CHECK_RETURN_ELOG(!photoOutput, "ExecutePhotoAvailable photoOutput is null");
    auto callback = photoOutput->GetAppPhotoCallback();
    CHECK_RETURN_ELOG(callback == nullptr, "ExecutePhotoAvailable callback is nullptr");
    if (surfaceBuffer->GetFormat() == GRAPHIC_PIXEL_FMT_YCRCB_420_SP) {
        std::unique_ptr<Media::Picture> picture = Media::Picture::Create(surfaceBuffer);
        callback->OnPhotoAvailable(std::move(picture));
    } else {
        std::shared_ptr<CameraBufferProcessor> bufferProcessor;
        std::shared_ptr<Media::NativeImage> image =
            std::make_shared<Media::NativeImage>(surfaceBuffer, bufferProcessor, timestamp);
        callback->OnPhotoAvailable(image, false);
    }
    MEDIA_INFO_LOG("PN_ExecutePhotoAvailable X");
}

void PhotoNativeConsumer::ExecutePhotoAssetAvailable(sptr<SurfaceBuffer> newSurfaceBuffer, int64_t timestamp)
{
    MEDIA_INFO_LOG("PN_ExecutePhotoAssetAvailable E");
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_ELOG(newSurfaceBuffer == nullptr, "ExecutePhotoAssetAvailable surfaceBuffer is null");
    auto photoOutput = innerPhotoOutput_.promote();
    CHECK_RETURN_ELOG(!photoOutput, "ExecutePhotoAssetAvailable photoOutput is null");
    auto callback = photoOutput->GetAppPhotoAssetCallback();
    CHECK_RETURN_ELOG(callback == nullptr, "ExecutePhotoAssetAvailable callback is nullptr");
    // prepare CameraPhotoProxy
    BufferHandle* bufferHandle = newSurfaceBuffer->GetBufferHandle();
    newSurfaceBuffer->Map();
    int32_t format = bufferHandle->format;
    int32_t photoWidth = CameraSurfaceBufferUtil::GetDataWidth(newSurfaceBuffer);
    int32_t photoHeight = CameraSurfaceBufferUtil::GetDataWidth(newSurfaceBuffer);
    bool isHighQuality = (CameraSurfaceBufferUtil::GetIsDegradedImage(newSurfaceBuffer) == 0);
    int32_t captureId = CameraSurfaceBufferUtil::GetCaptureId(newSurfaceBuffer);
    int32_t burstSeqId = -1;
    sptr<CameraPhotoProxy> photoProxy = new (std::nothrow)
        CameraPhotoProxy(bufferHandle, format, photoWidth, photoHeight, isHighQuality, captureId, burstSeqId);
    // ipc CreateMediaLibrary
    string uri = "";
    int32_t cameraShotType = 0;
    std::string burstKey = "";
    photoOutput->CreateMediaLibrary(photoProxy, uri, cameraShotType, burstKey, timestamp);
    MEDIA_INFO_LOG("PN_ExecutePhotoAssetAvailable CreateMediaLibrary get uri:%{public}s", uri.c_str());
    callback->OnPhotoAssetAvailable(captureId, uri, cameraShotType, burstKey);
    MEDIA_INFO_LOG("PN_ExecutePhotoAssetAvailable X");
}

void PhotoNativeConsumer::ClearTaskManager()
{
    std::lock_guard<std::mutex> lock(taskManagerMutex_);
    if (taskManager_ != nullptr) {
        taskManager_->CancelAllTasks();
        taskManager_ = nullptr;
    }
}

std::shared_ptr<DeferredProcessing::TaskManager> PhotoNativeConsumer::GetDefaultTaskManager()
{
    constexpr int32_t numThreads = 1;
    std::lock_guard<std::mutex> lock(taskManagerMutex_);
    if (taskManager_ == nullptr) {
        taskManager_ = std::make_shared<DeferredProcessing::TaskManager>("PhotoListener", numThreads, false);
    }
    return taskManager_;
}
} // namespace CameraStandard
} // namespace OHOS
