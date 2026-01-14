/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include "quickthumbnail_taihe.h"

using namespace taihe;
using namespace OHOS;

namespace Ani {
namespace Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;
using namespace ohos::multimedia::image;
namespace ImageTaihe = ohos::multimedia::image::image;
constexpr int32_t DEFAULT_VALUE = 0;
QuickThumbnailImpl::QuickThumbnailImpl()
{
}

void QuickThumbnailImpl::SetThumbnailImage(ImageTaihe::PixelMap thumbnailImage)
{
}

ImageTaihe::PixelMap QuickThumbnailImpl::GetThumbnailImage()
{
    return pixelMap_;
}

int32_t QuickThumbnailImpl::GetCaptureId()
{
    return DEFAULT_VALUE;
}
void QuickThumbnailImpl::ReleaseSync()
{
}
} // namespace Camera
} // namespace Ani