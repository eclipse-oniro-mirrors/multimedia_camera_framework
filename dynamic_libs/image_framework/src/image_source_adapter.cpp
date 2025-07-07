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

#include "image_source_adapter.h"
#include "camera_log.h"

#include "pixel_map.h"

namespace OHOS {
namespace CameraStandard {
ImageSourceAdapter::ImageSourceAdapter()
{
    MEDIA_DEBUG_LOG("ImageSourceAdapter constructor");
}

ImageSourceAdapter::~ImageSourceAdapter()
{
    MEDIA_DEBUG_LOG("ImageSourceAdapter destructor");
    CHECK_EXECUTE(imageSource_ != nullptr, imageSource_ = nullptr);
}

int32_t ImageSourceAdapter::CreateImageSource(const uint8_t *data, uint32_t size, const Media::SourceOptions& opts,
    uint32_t& errorCode)
{
    MEDIA_DEBUG_LOG("CreateImageSource start");
    imageSource_ =
        OHOS::Media::ImageSource::CreateImageSource(data, size, opts, errorCode);
    CHECK_ERROR_RETURN_RET_LOG(imageSource_ == nullptr, -1, "CreateImageSource failed");
    return 0;
}

std::unique_ptr<Media::PixelMap> ImageSourceAdapter::CreatePixelMap(const Media::DecodeOptions& opts,
    uint32_t& errorCode)
{
    MEDIA_DEBUG_LOG("CreatePixelMap start");
    CHECK_ERROR_RETURN_RET_LOG(imageSource_ == nullptr, nullptr, "imageSource_ is nullptr");
    std::unique_ptr<Media::PixelMap> pixelMap = imageSource_->CreatePixelMap(opts, errorCode);
    CHECK_ERROR_RETURN_RET_LOG(pixelMap == nullptr, nullptr, "CreatePixelMap failed");
    return pixelMap;
}

extern "C" ImageSourceIntf *createImageSourceIntf()
{
    return new ImageSourceAdapter();
}
}  // namespace CameraStandard
}  // namespace OHOS