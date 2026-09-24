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

#ifndef OHOS_PHOTO_NATIVE_IMPL_H
#define OHOS_PHOTO_NATIVE_IMPL_H

#include "kits/native/include/camera/camera.h"
#include "kits/native/include/camera/photo_native.h"
#include "native_image.h"
#include "picture.h"

struct OH_PhotoNative {
public:
    explicit OH_PhotoNative();
    ~OH_PhotoNative();

    Camera_ErrorCode GetMainImage(OH_ImageNative** mainImage);
    Camera_ErrorCode GetPicture(OH_PictureNative** picture);
    Camera_ErrorCode GetAuxiliaryImage(OH_Camera_AuxiliaryPhotoType type, OH_ImageNative** outImage) const;
    Camera_ErrorCode GetUncompressedAuxiliaryImage(OH_Camera_AuxiliaryPhotoType type,
        OH_PictureNative** outImage) const;

    void SetMainImage(const std::shared_ptr<OHOS::Media::NativeImage> &mainImage);
    void SetRawImage(const std::shared_ptr<OHOS::Media::NativeImage> &rawImage);
    void SetPicture(const std::shared_ptr<OHOS::Media::Picture> &picture);
    void SetOxygenImage(const std::shared_ptr<OHOS::Media::NativeImage> &oxygenImage);
    void SetPigmentationImage(const std::shared_ptr<OHOS::Media::NativeImage> &pigmentationImage);

private:
    std::shared_ptr<OHOS::Media::NativeImage> mainImage_ = nullptr;
    std::shared_ptr<OHOS::Media::NativeImage> rawImage_ = nullptr;
    std::shared_ptr<OHOS::Media::Picture> picture_ = nullptr;
    std::shared_ptr<OHOS::Media::NativeImage> oxygenImage_ = nullptr;
    std::shared_ptr<OHOS::Media::NativeImage> pigmentationImage_ = nullptr;
};
#endif // OHOS_PHOTO_NATIVE_IMPL_H