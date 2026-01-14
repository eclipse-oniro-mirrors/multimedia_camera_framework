/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef FRAMEWORKS_TAIHE_INCLUDE_QUICKTHUMBNAIL_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_QUICKTHUMBNAIL_TAIHE_H

#include "image_taihe.h"
#include "depth_data_taihe.h"

namespace Ani::Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;
namespace ImageTaihe = ohos::multimedia::image::image;

class QuickThumbnailImpl {
public:
    QuickThumbnailImpl();
    ~QuickThumbnailImpl() = default;
    int32_t GetCaptureId();
    void SetThumbnailImage(ImageTaihe::PixelMap thumbnailImage);
    ImageTaihe::PixelMap GetThumbnailImage();
    void ReleaseSync();
private:
    ImageTaihe::PixelMap pixelMap_ = make_holder<ANI::Image::PixelMapImpl, ImageTaihe::PixelMap>();
};
} // namespace Ani::Camera
#endif //FRAMEWORKS_TAIHE_INCLUDE_QUICKTHUMBNAIL_TAIHE_H