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

#include "image_source_proxy.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
ImageSourceProxy::ImageSourceProxy(std::shared_ptr<Dynamiclib> imageLib,
    std::shared_ptr<ImageSourceIntf> imageSourceIntf) : imageLib_(imageLib),
    imageSourceIntf_(imageSourceIntf)
{
    MEDIA_DEBUG_LOG("ImageSourceProxy constructor");
    CHECK_RETURN_ELOG(imageLib_ == nullptr, "imageLib_ is nullptr");
    CHECK_RETURN_ELOG(imageSourceIntf_ == nullptr, "imageSourceIntf_ is nullptr");
}

ImageSourceProxy::~ImageSourceProxy()
{
    MEDIA_DEBUG_LOG("ImageSourceProxy destructor");
}

void ImageSourceProxy::Release()
{
    CameraDynamicLoader::FreeDynamicLibDelayed(PICTURE_SO, LIB_DELAYED_UNLOAD_TIME);
}

typedef ImageSourceIntf* (*CreateImageSourceIntf)();
std::shared_ptr<ImageSourceProxy> ImageSourceProxy::CreateImageSourceProxy()
{
    MEDIA_DEBUG_LOG("CreateImageSourceProxy start");
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(PICTURE_SO);
    CHECK_RETURN_RET_ELOG(
        dynamiclib == nullptr, nullptr, "get dynamiclib fail");
    CreateImageSourceIntf createImageSourceIntf =
        (CreateImageSourceIntf)dynamiclib->GetFunction("createImageSourceIntf");
    CHECK_RETURN_RET_ELOG(
        createImageSourceIntf == nullptr, nullptr, "get createImageSourceIntf fail");
    ImageSourceIntf* imageSourceIntf = createImageSourceIntf();
    CHECK_RETURN_RET_ELOG(
        imageSourceIntf == nullptr, nullptr, "get imageSourceIntf fail");
    std::shared_ptr<ImageSourceProxy> imageSourceProxy =
        std::make_shared<ImageSourceProxy>(dynamiclib, std::shared_ptr<ImageSourceIntf>(imageSourceIntf));
    return imageSourceProxy;
}

int32_t ImageSourceProxy::CreateImageSource(const uint8_t *data, uint32_t size, const Media::SourceOptions& opts,
    uint32_t& errorCode)
{
    MEDIA_DEBUG_LOG("CreateImageSource start");
    CHECK_RETURN_RET_ELOG(imageSourceIntf_ == nullptr, -1, "imageSourceIntf_ is nullptr");
    int32_t ret = imageSourceIntf_->CreateImageSource(data, size, opts, errorCode);
    CHECK_RETURN_RET_ELOG(ret == -1, ret, "CreateImageSource failed, ret: %{public}d", ret);
    return 0;
}

std::unique_ptr<Media::PixelMap> ImageSourceProxy::CreatePixelMap(const Media::DecodeOptions& opts, uint32_t& errorCode)
{
    MEDIA_DEBUG_LOG("CreatePixelMap start");
    CHECK_RETURN_RET_ELOG(imageSourceIntf_ == nullptr, nullptr, "imageSourceIntf_ is nullptr");
    return imageSourceIntf_->CreatePixelMap(opts, errorCode);
}
}  // namespace CameraStandard
}  // namespace OHOS