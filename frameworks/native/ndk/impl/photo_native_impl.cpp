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

    if (rawImage_) {
        rawImage_->release();
        rawImage_ = nullptr;
    }
}

Camera_ErrorCode OH_PhotoNative::GetMainImage(OH_ImageNative** mainImage)
{
    OH_ImageNative *imageNative = new OH_ImageNative;
    imageNative->imgNative = mainImage_.get();
    *mainImage = imageNative;
    return CAMERA_OK;
}

void OH_PhotoNative::SetMainImage(std::shared_ptr<OHOS::Media::NativeImage> &mainImage)
{
    mainImage_ = mainImage;
}

void OH_PhotoNative::SetRawImage(std::shared_ptr<OHOS::Media::NativeImage> &rawImage)
{
    rawImage_ = rawImage;
}
