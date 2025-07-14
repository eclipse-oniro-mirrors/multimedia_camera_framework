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

#ifndef OHOS_CAMERA_IMAGE_SOURCE_INTERFACE_H
#define OHOS_CAMERA_IMAGE_SOURCE_INTERFACE_H

#include "image_source.h"
#include "image_type.h"
#include "pixel_map.h"

/**
 * @brief Internal usage only, for camera framework interacts with image source related interfaces.
 * @since 12
 */
namespace OHOS::CameraStandard {
class ImageSourceIntf {
public:
    virtual ~ImageSourceIntf() = default;
    virtual int32_t CreateImageSource(const uint8_t *data, uint32_t size, const Media::SourceOptions& opts,
        uint32_t& errorCode) = 0;
    virtual std::unique_ptr<Media::PixelMap> CreatePixelMap(const Media::DecodeOptions& opts, uint32_t& errorCode) = 0;
};
} // namespace OHOS::CameraStandard
#endif // OHOS_CAMERA_IMAGE_SOURCE_INTERFACE_H