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

#include "photo_native_impl.h"
#include "camera_log.h"
#include "image_kits.h"
#include "auxiliary_picture.h"
#include "picture_native_impl.h"

using namespace OHOS;

OH_PhotoNative::OH_PhotoNative()
{
    MEDIA_DEBUG_LOG("OH_PhotoNative Constructor is called");
}

OH_PhotoNative::~OH_PhotoNative()
{
    MEDIA_DEBUG_LOG("~OH_PhotoNative is called");
    if (mainImage_) {
        mainImage_->release();
        mainImage_ = nullptr;
    }
    CHECK_EXECUTE(picture_, picture_ = nullptr);

    CHECK_RETURN(!rawImage_);
    rawImage_->release();
    rawImage_ = nullptr;
}

Camera_ErrorCode OH_PhotoNative::GetMainImage(OH_ImageNative** mainImage)
{
    OH_ImageNative *imageNative = new OH_ImageNative;
    imageNative->imgNative = mainImage_.get();
    *mainImage = imageNative;
    return CAMERA_OK;
}

Camera_ErrorCode OH_PhotoNative::GetPicture(OH_PictureNative** picture)
{
    OH_PictureNative *pictureNative = new OH_PictureNative(picture_);
    *picture = pictureNative;
    return CAMERA_OK;
}

Camera_ErrorCode OH_PhotoNative::GetAuxiliaryImage(OH_Camera_AuxiliaryPhotoType type, OH_ImageNative** outImage)
    const
{
    MEDIA_INFO_LOG("OH_PhotoNative::GetAuxiliaryImage type:%{public}d", static_cast<int32_t>(type));
    std::shared_ptr<OHOS::Media::NativeImage> auxiliaryImage = nullptr;
    if (type == OH_CAMERA_AUXILIARY_PHOTO_TYPE_OXYGEN) {
        auxiliaryImage = oxygenImage_;
    } else if (type == OH_CAMERA_AUXILIARY_PHOTO_TYPE_PIGMENTATION) {
        auxiliaryImage = pigmentationImage_;
    } else {
        return CAMERA_ERROR_PARAM_OUT_OF_RANGE;
    }
    CHECK_RETURN_RET_ELOG(auxiliaryImage == nullptr, CAMERA_ERROR_PARAM_OUT_OF_RANGE,
        "OH_PhotoNative::GetAuxiliaryImage auxiliaryImage is null");
    OH_ImageNative *imageNative = new OH_ImageNative;
    imageNative->imgNative = auxiliaryImage.get();
    *outImage = imageNative;
    return CAMERA_OK;
}

Camera_ErrorCode OH_PhotoNative::GetUncompressedAuxiliaryImage(OH_Camera_AuxiliaryPhotoType type,
    OH_PictureNative** outImage) const
{
    MEDIA_INFO_LOG("OH_PhotoNative::GetUncompressedAuxiliaryImage type:%{public}d", static_cast<int32_t>(type));
    CHECK_RETURN_RET_ELOG(picture_ == nullptr, CAMERA_ERROR_PARAM_OUT_OF_RANGE,
        "OH_PhotoNative::GetUncompressedAuxiliaryImage picture_ is null");
    OHOS::Media::AuxiliaryPictureType auxiliaryType = OHOS::Media::AuxiliaryPictureType::NONE;
    if (type == OH_CAMERA_AUXILIARY_PHOTO_TYPE_OXYGEN) {
        auxiliaryType = OHOS::Media::AuxiliaryPictureType::OXY_MAP;
    } else if (type == OH_CAMERA_AUXILIARY_PHOTO_TYPE_PIGMENTATION) {
        auxiliaryType = OHOS::Media::AuxiliaryPictureType::MEL_MAP;
    } else {
        return CAMERA_ERROR_PARAM_OUT_OF_RANGE;
    }
    std::shared_ptr<OHOS::Media::AuxiliaryPicture> auxiliaryPicture = picture_->GetAuxiliaryPicture(auxiliaryType);
    CHECK_RETURN_RET_ELOG(auxiliaryPicture == nullptr, CAMERA_ERROR_PARAM_OUT_OF_RANGE,
        "OH_PhotoNative::GetUncompressedAuxiliaryImage auxiliaryPicture is null");
    std::shared_ptr<OHOS::Media::PixelMap> contentPixel = auxiliaryPicture->GetContentPixel();
    CHECK_RETURN_RET_ELOG(contentPixel == nullptr, CAMERA_ERROR_PARAM_OUT_OF_RANGE,
        "OH_PhotoNative::GetUncompressedAuxiliaryImage contentPixel is null");
    std::unique_ptr<OHOS::Media::Picture> auxiliaryPicturePtr = OHOS::Media::Picture::Create(contentPixel);
    CHECK_RETURN_RET_ELOG(auxiliaryPicturePtr == nullptr, CAMERA_ERROR_PARAM_OUT_OF_RANGE,
        "OH_PhotoNative::GetUncompressedAuxiliaryImage create picture failed");
    OH_PictureNative *pictureNative = new OH_PictureNative(std::move(auxiliaryPicturePtr));
    *outImage = pictureNative;
    return CAMERA_OK;
}

void OH_PhotoNative::SetMainImage(const std::shared_ptr<OHOS::Media::NativeImage> &mainImage)
{
    mainImage_ = mainImage;
}

void OH_PhotoNative::SetRawImage(const std::shared_ptr<OHOS::Media::NativeImage> &rawImage)
{
    rawImage_ = rawImage;
}

void OH_PhotoNative::SetPicture(const std::shared_ptr<OHOS::Media::Picture> &picture)
{
    picture_ = picture;
}

void OH_PhotoNative::SetOxygenImage(const std::shared_ptr<OHOS::Media::NativeImage> &oxygenImage)
{
    oxygenImage_ = oxygenImage;
}

void OH_PhotoNative::SetPigmentationImage(const std::shared_ptr<OHOS::Media::NativeImage> &pigmentationImage)
{
    pigmentationImage_ = pigmentationImage;
}
