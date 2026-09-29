/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "capture_photo_taihe.h"
#include "camera_log.h"

using namespace taihe;
using namespace OHOS;

namespace Ani {
namespace Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;
using namespace ohos::multimedia::image;
namespace ImageTaihe = ohos::multimedia::image::image;
CapturePhotoImpl::CapturePhotoImpl()
    : imageTypeValue_(ImageType::make_image(ANI::Image::ImageImpl::Create(nullptr)))
{
    MEDIA_DEBUG_LOG("CapturePhotoImpl ctor");
}

int64_t CapturePhotoImpl::GetSpecificImplPtr()
{
    return reinterpret_cast<uintptr_t>(this);
}

void CapturePhotoImpl::SetMain(ImageType const& main)
{
    MEDIA_DEBUG_LOG("CapturePhotoImpl::SetMain is uncompressed image: %{public}d", main.holds_picture());
    imageTypeValue_ = main;
}

ImageType CapturePhotoImpl::GetMain()
{
    MEDIA_DEBUG_LOG("CapturePhotoImpl::GetMain is uncompressed image: %{public}d", imageTypeValue_.holds_picture());
    return imageTypeValue_;
}

void CapturePhotoImpl::SetOxygenPhoto(optional_view<ImageType> oxygenPhoto)
{
    MEDIA_DEBUG_LOG("CapturePhotoImpl::SetOxygenPhoto is called");
    if (oxygenPhoto.has_value()) {
        oxygenImageValue_ = optional<ImageType>(std::in_place, oxygenPhoto.value());
    } else {
        oxygenImageValue_ = optional<ImageType>();
    }
}

optional<ImageType> CapturePhotoImpl::GetOxygenPhoto()
{
    MEDIA_DEBUG_LOG("CapturePhotoImpl::GetOxygenPhoto is called");
    return oxygenImageValue_;
}

void CapturePhotoImpl::SetPigmentationPhoto(optional_view<ImageType> pigmentationPhoto)
{
    MEDIA_DEBUG_LOG("CapturePhotoImpl::SetPigmentationPhoto is called");
    if (pigmentationPhoto.has_value()) {
        pigmentationImageValue_ = optional<ImageType>(std::in_place, pigmentationPhoto.value());
    } else {
        pigmentationImageValue_ = optional<ImageType>();
    }
}

optional<ImageType> CapturePhotoImpl::GetPigmentationPhoto()
{
    MEDIA_DEBUG_LOG("CapturePhotoImpl::GetPigmentationPhoto is called");
    return pigmentationImageValue_;
}

void CapturePhotoImpl::ReleaseSync()
{
    MEDIA_DEBUG_LOG("CapturePhotoImpl::ReleaseSync is called");
}
} // namespace Camera
} // namespace Ani