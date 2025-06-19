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

#include "picture_adapter.h"
#include "camera_log.h"
#include "image_format.h"
#include "image_mime_type.h"
#include "image_type.h"
#include "ipc_skeleton.h"
#include "picture.h"
#include "pixel_map.h"
#include "surface_buffer.h"
#include "securec.h"
namespace OHOS {
namespace CameraStandard {
std::unordered_map<std::string, float> exifOrientationDegree = {
    {"Top-left", 0},
    {"Top-right", 90},
    {"Bottom-right", 180},
    {"Right-top", 90},
    {"Left-bottom", 270},
};

float TransExifOrientationToDegree(const std::string& orientation)
{
    float degree = .0;
    if (exifOrientationDegree.count(orientation)) {
        degree = exifOrientationDegree[orientation];
    }
    return degree;
}

inline void RotatePixelMap(std::shared_ptr<Media::PixelMap> pixelMap, const std::string& exifOrientation)
{
    float degree = TransExifOrientationToDegree(exifOrientation);
    if (pixelMap) {
        DECORATOR_HILOG(HILOG_INFO, "RotatePicture degree is %{public}f", degree);
        pixelMap->rotate(degree);
    } else {
        DECORATOR_HILOG(HILOG_ERROR, "RotatePicture degree is %{public}f", degree);
    }
}

std::string GetAndSetExifOrientation(OHOS::Media::ImageMetadata* exifData)
{
    std::string orientation = "";
    if (exifData != nullptr) {
        exifData->GetValue("Orientation", orientation);
        std::string defalutExifOrientation = "1";
        exifData->SetValue("Orientation", defalutExifOrientation);
        DECORATOR_HILOG(HILOG_INFO, "GetExifOrientation orientation:%{public}s", orientation.c_str());
        exifData->RemoveExifThumbnail();
        MEDIA_INFO_LOG("RemoveExifThumbnail");
    } else {
        DECORATOR_HILOG(HILOG_ERROR, "GetExifOrientation exifData is nullptr");
    }
    return orientation;
}

PictureAdapter::PictureAdapter() : picture_(nullptr)
{
    MEDIA_INFO_LOG("PictureAdapter ctor");
}

PictureAdapter::~PictureAdapter()
{
    MEDIA_INFO_LOG("PictureAdapter dctor");
}

void PictureAdapter::Create(sptr<SurfaceBuffer> &surfaceBuffer)
{
    MEDIA_INFO_LOG("PictureAdapter ctor");
    picture_ = Media::Picture::Create(surfaceBuffer);
}

void PictureAdapter::SetAuxiliaryPicture(sptr<SurfaceBuffer> &surfaceBuffer, CameraAuxiliaryPictureType type)
{
    MEDIA_INFO_LOG("PictureAdapter::SetAuxiliaryPicture enter");
    std::shared_ptr<Media::Picture> picture = GetPicture();
    CHECK_ERROR_RETURN_LOG(!picture, "PictureAdapter::SetAuxiliaryPicture picture is nullptr");
    std::unique_ptr<Media::AuxiliaryPicture> uniptr = Media::AuxiliaryPicture::Create(
        surfaceBuffer, static_cast<Media::AuxiliaryPictureType>(type));
    std::shared_ptr<Media::AuxiliaryPicture> picturePtr = std::move(uniptr);
    picture->SetAuxiliaryPicture(picturePtr);
}

void CopyMetaData(sptr<SurfaceBuffer> &inBuffer, sptr<SurfaceBuffer> &outBuffer)
{
    std::vector<uint32_t> keys = {};
    CHECK_ERROR_RETURN_LOG(inBuffer == nullptr, "CopyMetaData: inBuffer is nullptr");
    auto ret = inBuffer->ListMetadataKeys(keys);
    CHECK_ERROR_RETURN_LOG(ret != GSError::GSERROR_OK,
        "CopyMetaData: ListMetadataKeys fail! res=%{public}d", ret);
    for (uint32_t key : keys) {
        std::vector<uint8_t> values;
        ret = inBuffer->GetMetadata(key, values);
        if (ret != 0) {
            MEDIA_INFO_LOG("GetMetadata fail! key = %{public}d res = %{public}d", key, ret);
            continue;
        }
        ret = outBuffer->SetMetadata(key, values);
        if (ret != 0) {
            MEDIA_INFO_LOG("SetMetadata fail! key = %{public}d res = %{public}d", key, ret);
            continue;
        }
    }
}

void PictureAdapter::CreateWithDeepCopySurfaceBuffer(sptr<SurfaceBuffer> &surfaceBuffer)
{
    MEDIA_INFO_LOG("PictureAdapter CreateWithDeepCopySurfaceBuffer");
    auto pixelMap = Media::Picture::SurfaceBuffer2PixelMap(surfaceBuffer);
    CHECK_ERROR_RETURN_LOG(!pixelMap, "PictureAdapter::CreateWithDeepCopySurfaceBuffer pixelMap is nullptr");
    sptr<SurfaceBuffer> oldSurfaceBuffer = reinterpret_cast<SurfaceBuffer*>(pixelMap->GetFd());
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
    sptr<SurfaceBuffer> newSurfaceBuffer = SurfaceBuffer::Create();
    CHECK_ERROR_RETURN_LOG(!newSurfaceBuffer,
        "PictureAdapter::CreateWithDeepCopySurfaceBuffer newSurfaceBuffer is nullptr");
    auto allocErrorCode = newSurfaceBuffer->Alloc(requestConfig);
    MEDIA_DEBUG_LOG("PictureAdapter::CreateWithDeepCopySurfaceBuffer SurfaceBuffer alloc ret: %{public}d",
        allocErrorCode);
    errno_t errNo = memcpy_s(newSurfaceBuffer->GetVirAddr(), newSurfaceBuffer->GetSize(),
        oldSurfaceBuffer->GetVirAddr(), oldSurfaceBuffer->GetSize());
    if (errNo != EOK) {
        MEDIA_ERR_LOG("PictureAdapter memcpy_s failed, errNo = %{public}d", static_cast<int32_t>(errNo));
        return;
    }
    CopyMetaData(oldSurfaceBuffer, newSurfaceBuffer);
    picture_ = Media::Picture::Create(newSurfaceBuffer);
}

bool PictureAdapter::Marshalling(Parcel &data) const
{
    MEDIA_INFO_LOG("PictureAdapter::Marshalling enter");
    std::shared_ptr<Media::Picture> picture = GetPicture();
    CHECK_ERROR_RETURN_RET_LOG(!picture, false, "PictureAdapter::Marshalling picture is nullptr");
    return picture->Marshalling(data);
}

void PictureAdapter::UnmarshallingPicture(Parcel &data)
{
    MEDIA_INFO_LOG("PictureAdapter::Unmarshalling enter");
    picture_.reset(Media::Picture::Unmarshalling(data));
}

int32_t PictureAdapter::SetExifMetadata(sptr<SurfaceBuffer> &surfaceBuffer)
{
    MEDIA_INFO_LOG("PictureAdapter::SetExifMetadata enter");
    int32_t retCode = -1;
    std::shared_ptr<Media::Picture> picture = GetPicture();
    CHECK_ERROR_RETURN_RET_LOG(!picture, retCode, "PictureAdapter::SetExifMetadata picture is nullptr");
    retCode = static_cast<int32_t>(picture->SetExifMetadata(surfaceBuffer));
    return retCode;
}

bool PictureAdapter::SetMaintenanceData(sptr<SurfaceBuffer> &surfaceBuffer)
{
    bool retCode = false;
    std::shared_ptr<Media::Picture> picture = GetPicture();
    CHECK_ERROR_RETURN_RET_LOG(!picture, retCode, "PictureAdapter::SetMaintenanceData picture is nullptr");
    retCode = picture->SetMaintenanceData(surfaceBuffer);
    return retCode;
}

void PictureAdapter::RotatePicture()
{
    MEDIA_DEBUG_LOG("PictureAdapter::RotatePicture E");
    std::shared_ptr<Media::Picture> picture = GetPicture();
    CHECK_ERROR_RETURN_LOG(!picture, "PictureAdapter::RotatePicture picture is nullptr");
    std::string orientation = GetAndSetExifOrientation(
        reinterpret_cast<OHOS::Media::ImageMetadata*>(picture->GetExifMetadata().get()));
    RotatePixelMap(picture->GetMainPixel(), orientation);
    MEDIA_INFO_LOG("PictureAdapter::RotatePicture orientation:%{public}s", orientation.c_str());
    auto gainMap = picture->GetAuxiliaryPicture(Media::AuxiliaryPictureType::GAINMAP);
    if (gainMap) {
        RotatePixelMap(gainMap->GetContentPixel(), orientation);
    }
    auto depthMap = picture->GetAuxiliaryPicture(Media::AuxiliaryPictureType::DEPTH_MAP);
    if (depthMap) {
        RotatePixelMap(depthMap->GetContentPixel(), orientation);
    }
    auto unrefocusMap = picture->GetAuxiliaryPicture(Media::AuxiliaryPictureType::UNREFOCUS_MAP);
    if (unrefocusMap) {
        RotatePixelMap(unrefocusMap->GetContentPixel(), orientation);
    }
    auto linearMap = picture->GetAuxiliaryPicture(Media::AuxiliaryPictureType::LINEAR_MAP);
    if (linearMap) {
        RotatePixelMap(linearMap->GetContentPixel(), orientation);
    }
    MEDIA_INFO_LOG("PictureAdapter::RotatePicture X");
}

std::shared_ptr<Media::Picture> PictureAdapter::GetPicture() const
{
    return picture_;
}

extern "C" PictureIntf *createPictureAdapterIntf()
{
    return new PictureAdapter();
}

}  // namespace AVSession
}  // namespace OHOS