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
#include "photo_taihe.h"

using namespace taihe;
using namespace OHOS;

namespace Ani {
namespace Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;
using namespace ohos::multimedia::image;
namespace ImageTaihe = ohos::multimedia::image::image;
PhotoImpl::PhotoImpl(ImageTaihe::Image mainImage, bool isRaw)
{
    if (isRaw) {
        rawImage_ = mainImage;
        MEDIA_DEBUG_LOG("raw image");
    } else {
        mainImage_ = mainImage;
    }
}

void PhotoImpl::SetMain(ImageTaihe::weak::Image main)
{
    mainImage_ = main;
}

ImageTaihe::Image PhotoImpl::GetMain()
{
    return mainImage_;
}

void PhotoImpl::SetRaw(optional_view<ImageTaihe::Image> raw)
{
    if (raw.has_value()) {
        rawImage_ = raw.value();
    }
}

optional<ImageTaihe::Image> PhotoImpl::GetRaw()
{
    return optional<ImageTaihe::Image>(std::in_place_t{}, rawImage_);
}

void PhotoImpl::SetDepthData(optional_view<DepthData> depthData)
{
    if (depthData.has_value()) {
        depthData_ = depthData.value();
    }
}

optional<DepthData> PhotoImpl::GetDepthData()
{
    return optional<DepthData>(std::in_place_t{}, depthData_);
}

void PhotoImpl::SetCaptureId(int32_t captureId)
{
    captureId_ = captureId;
}
int32_t PhotoImpl::GetCaptureId()
{
    return captureId_;
}
void PhotoImpl::ReleaseSync()
{
    mainImage_->ReleaseSync();
}
} // namespace Camera
} // namespace Ani