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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_DEFERRED_PHOTO_PROXY_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_DEFERRED_PHOTO_PROXY_TAIHE_H


#include "taihe/runtime.hpp"
#include "camera_log.h"
#include "deferred_photo_proxy.h"
#include "image_taihe.h"
#include "pixel_map_taihe.h"

namespace Ani::Camera {
using namespace OHOS;
namespace ImageTaihe = ohos::multimedia::image::image;
class DeferredPhotoProxyImpl {
public:
    DeferredPhotoProxyImpl(sptr<OHOS::CameraStandard::DeferredPhotoProxy> deferredPhotoProxy);
    ~DeferredPhotoProxyImpl() = default;
    ImageTaihe::PixelMap GetThumbnailSync();
    void ReleaseSync();
private:
    sptr<OHOS::CameraStandard::DeferredPhotoProxy> deferredPhotoProxy_ = nullptr;
};
} // namespace Ani::Camera
#endif //FRAMEWORKS_TAIHE_INCLUDE_DEFERRED_PHOTO_PROXY_TAIHE_H