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
#include "deferred_photo_proxy_taihe.h"
#include "camera_security_utils_taihe.h"

using namespace taihe;
using namespace OHOS;

namespace Ani {
namespace Camera {
namespace ImageTaihe = ohos::multimedia::image::image;
DeferredPhotoProxyImpl::DeferredPhotoProxyImpl(sptr<OHOS::CameraStandard::DeferredPhotoProxy> deferredPhotoProxy)
{
    deferredPhotoProxy_ = deferredPhotoProxy;
}

ImageTaihe::PixelMap DeferredPhotoProxyImpl::GetThumbnailSync()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        ANI::Image::PixelMapImpl::CreatePixelMap(nullptr), "SystemApi GetThumbnailSync is called!");
    void* fdAddr = deferredPhotoProxy_->GetFileDataAddr();
    int32_t thumbnailWidth = deferredPhotoProxy_->GetWidth();
    int32_t thumbnailHeight = deferredPhotoProxy_->GetHeight();
    Media::InitializationOptions opts;
    opts.srcPixelFormat = Media::PixelFormat::RGBA_8888;
    opts.pixelFormat = Media::PixelFormat::RGBA_8888;
    opts.size = { .width = thumbnailWidth, .height = thumbnailHeight };
    MEDIA_INFO_LOG("thumbnailWidth:%{public}d, thumbnailHeight: %{public}d",
        thumbnailWidth, thumbnailHeight);
    auto pixelMap = Media::PixelMap::Create(static_cast<const uint32_t*>(fdAddr),
        thumbnailWidth * thumbnailHeight * 4, 0, thumbnailWidth, opts, true);
    return ANI::Image::PixelMapImpl::CreatePixelMap(std::move(pixelMap));
}

void DeferredPhotoProxyImpl::ReleaseSync()
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi ReleaseSync is called!");
    if (deferredPhotoProxy_ != nullptr) {
        deferredPhotoProxy_ = nullptr;
    }
}
} // namespace Camera
} // namespace Ani
