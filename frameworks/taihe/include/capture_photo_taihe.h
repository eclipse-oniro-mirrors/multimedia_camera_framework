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
#ifndef FRAMEWORKS_TAIHE_INCLUDE_CAPTURE_PHOTO_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_CAPTURE_PHOTO_TAIHE_H

#include "taihe/runtime.hpp"
#include "image_taihe.h"
#include "picture_taihe.h"
#include "pixel_map_taihe.h"
#include "depth_data_taihe.h"

namespace Ani::Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;
namespace ImageTaihe = ohos::multimedia::image::image;

class CapturePhotoImpl {
public:
    CapturePhotoImpl() = default;
    ~CapturePhotoImpl() = default;
    int64_t GetSpecificImplPtr();
    void SetMain(ImageTaihe::weak::Image mainImage);
    ImageTaihe::Image GetMain();
    void SetPicture(ImageTaihe::weak::Picture picture);
    ImageTaihe::Picture GetPicture();
    void ReleaseSync();

private:
    ImageTaihe::Image mainImage_ = make_holder<ANI::Image::ImageImpl, ImageTaihe::Image>();
    ImageTaihe::Picture picture_ = make_holder<ANI::Image::PictureImpl, ImageTaihe::Picture>();
};
} // namespace Ani::Camera
#endif //FRAMEWORKS_TAIHE_INCLUDE_CAPTURE_PHOTO_TAIHE_H