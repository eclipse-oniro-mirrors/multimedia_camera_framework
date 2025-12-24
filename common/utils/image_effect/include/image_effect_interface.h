/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_IMAGE_EFFECT_INTERFACE_H
#define OHOS_CAMERA_IMAGE_EFFECT_INTERFACE_H

#include <cstdint>
#include <string>
#include "surface.h"

namespace OHOS::CameraStandard {

const std::string COLOR_FILTER_ORIGIN = "Origin";
const std::string COLOR_FILTER_CLASSIC = "Classic";
const std::string COLOR_FILTER_MOODY = "Moody";
const std::string COLOR_FILTER_NATURAL = "Natural";
const std::string COLOR_FILTER_BLOSSOM = "Blossom";
const std::string COLOR_FILTER_FAIR = "Fair";
const std::string COLOR_FILTER_PINK = "Pink";

class ImageEffectIntf {
public:
    virtual ~ImageEffectIntf() = default;

    virtual void GetSupportedFilters(std::vector<std::string>& filterNames) = 0;
    virtual int32_t Init() = 0;
    virtual int32_t Start() = 0;
    virtual int32_t Stop() = 0;
    virtual int32_t Reset() = 0;
    virtual sptr<Surface> GetInputSurface() = 0;
    virtual int32_t SetOutputSurface(sptr<Surface> surface) = 0;
    virtual int32_t SetImageEffect(const std::string& filter, const std::string& filterParam) = 0;
};
} // namespace OHOS::CameraStandard
#endif // OHOS_CAMERA_IMAGE_EFFECT_INTERFACE_H