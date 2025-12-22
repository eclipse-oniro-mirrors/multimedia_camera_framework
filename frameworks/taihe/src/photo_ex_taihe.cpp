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
#include "photo_ex_taihe.h"
#include "camera_log.h"

using namespace taihe;
using namespace OHOS;

namespace Ani {
namespace Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;
using namespace ohos::multimedia::image;
namespace ImageTaihe = ohos::multimedia::image::image;
int64_t PhotoExImpl::GetSpecificImplPtr()
{
    return reinterpret_cast<uintptr_t>(this);
}

void PhotoExImpl::SetMain(ImageTaihe::weak::Image mainImage)
{
    mainImage_ = mainImage;
}

ImageTaihe::Image PhotoExImpl::GetMain()
{
    return mainImage_;
}

void PhotoExImpl::SetPicture(ImageTaihe::weak::Picture picture)
{
    picture_ = picture;
}

ImageTaihe::Picture PhotoExImpl::GetPicture()
{
    return picture_;
}

void PhotoExImpl::ReleaseSync()
{
    mainImage_->ReleaseSync();
    picture_->Release();
}
} // namespace Camera
} // namespace Ani