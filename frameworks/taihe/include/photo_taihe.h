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
#ifndef FRAMEWORKS_TAIHE_INCLUDE_PHOTO_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_PHOTO_TAIHE_H

#include "taihe/runtime.hpp"
#include "camera_log.h"
#include "image_taihe.h"
#include "pixel_map_taihe.h"
#include "depth_data_taihe.h"

namespace Ani::Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;
namespace ImageTaihe = ohos::multimedia::image::image;
class PhotoImpl {
public:
    PhotoImpl(ImageTaihe::Image mainImage, bool isRaw);
    ~PhotoImpl() = default;
    void SetMain(ImageTaihe::weak::Image main);
    ImageTaihe::Image GetMain();
    void SetRaw(optional_view<ImageTaihe::Image> raw);
    optional<ImageTaihe::Image> GetRaw();
    void SetDepthData(optional_view<DepthData> depthData);
    optional<DepthData> GetDepthData();
    void SetCaptureId(int32_t captureId);
    int32_t GetCaptureId();
    void ReleaseSync();
private:
    ImageTaihe::Image mainImage_ = make_holder<ANI::Image::ImageImpl, ImageTaihe::Image>();
    ImageTaihe::Image rawImage_ = make_holder<ANI::Image::ImageImpl, ImageTaihe::Image>();
    int32_t captureId_ = 0;
    DepthData depthData_ = taihe::make_holder<DepthDataImpl, DepthData>(
        OHOS::CameraStandard::CameraFormat::CAMERA_FORMAT_YCBCR_420_888,
            OHOS::CameraStandard::DepthDataAccuracy::DEPTH_DATA_ACCURACY_RELATIVE, 0,
                make_holder<ANI::Image::PixelMapImpl, ImageTaihe::PixelMap>());
};
} // namespace Ani::Camera
#endif //FRAMEWORKS_TAIHE_INCLUDE_PHOTO_TAIHE_H