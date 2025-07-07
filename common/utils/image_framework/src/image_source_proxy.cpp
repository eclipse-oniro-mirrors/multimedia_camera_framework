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
    CHECK_ERROR_RETURN_LOG(imageLib_ == nullptr, "imageLib_ is nullptr");
    CHECK_ERROR_RETURN_LOG(imageSourceIntf_ == nullptr, "imageSourceIntf_ is nullptr");
}

ImageSourceProxy::~ImageSourceProxy()
{
    MEDIA_DEBUG_LOG("ImageSourceProxy destructor start");
    CHECK_EXECUTE(imageSourceIntf_ != nullptr, imageSourceIntf_ = nullptr);
    CHECK_EXECUTE(imageLib_ != nullptr, imageLib_ = nullptr);
    MEDIA_DEBUG_LOG("ImageSourceProxy destructor end");
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
    CHECK_ERROR_RETURN_RET_LOG(
        dynamiclib == nullptr, nullptr, "get dynamiclib fail");
    CreateImageSourceIntf createImageSourceIntf =
        (CreateImageSourceIntf)dynamiclib->GetFunction("createImageSourceIntf");
    CHECK_ERROR_RETURN_RET_LOG(
        createImageSourceIntf == nullptr, nullptr, "get createImageSourceIntf fail");
    ImageSourceIntf* imageSourceIntf = createImageSourceIntf();
    CHECK_ERROR_RETURN_RET_LOG(
        imageSourceIntf == nullptr, nullptr, "get imageSourceIntf fail");
    std::shared_ptr<ImageSourceProxy> imageSourceProxy =
        std::make_shared<ImageSourceProxy>(dynamiclib, std::shared_ptr<ImageSourceIntf>(imageSourceIntf));
    return imageSourceProxy;
}

int32_t ImageSourceProxy::CreateImageSource(const uint8_t *data, uint32_t size, const Media::SourceOptions& opts,
    uint32_t& errorCode)
{
    MEDIA_DEBUG_LOG("CreateImageSource start");
    CHECK_ERROR_RETURN_RET_LOG(imageSourceIntf_ == nullptr, -1, "imageSourceIntf_ is nullptr");
    int32_t ret = imageSourceIntf_->CreateImageSource(data, size, opts, errorCode);
    CHECK_ERROR_RETURN_RET_LOG(ret == -1, ret, "CreateImageSource failed, ret: %{public}d", ret);
    return 0;
}

std::unique_ptr<Media::PixelMap> ImageSourceProxy::CreatePixelMap(const Media::DecodeOptions& opts, uint32_t& errorCode)
{
    MEDIA_DEBUG_LOG("CreatePixelMap start");
    CHECK_ERROR_RETURN_RET_LOG(imageSourceIntf_ == nullptr, nullptr, "imageSourceIntf_ is nullptr");
    return imageSourceIntf_->CreatePixelMap(opts, errorCode);
}
}  // namespace CameraStandard
}  // namespace OHOS