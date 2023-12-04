/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "cubic_bezier.h"
#include "smooth_zoom.h"

namespace OHOS {
namespace CameraStandard {
std::shared_ptr<IZoomAlgorithm> SmoothZoom::GetZoomAlgorithm(SmoothZoomType mode)
{
    std::shared_ptr<IZoomAlgorithm> algorithm;
    switch (mode) {
        case SmoothZoomType::NORMAL:
            algorithm = std::make_shared<CubicBezier>();
            break;
        default:
            algorithm = std::make_shared<CubicBezier>();
            break;
    }
    return algorithm;
};
} // namespace CameraStandard
} // namespace OHOS