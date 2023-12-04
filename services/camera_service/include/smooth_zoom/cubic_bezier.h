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

#ifndef OHOS_CAMERA_CUBIC_BEZIER_H
#define OHOS_CAMERA_CUBIC_BEZIER_H

#include "izoom_algorithm.h"

namespace OHOS {
namespace CameraStandard {
class CubicBezier : public IZoomAlgorithm {
public:
    CubicBezier() = default;
    ~CubicBezier() = default;

    std::vector<float> GetZoomArray(const float& currentZoom, const float& targetZoom,
        const float& frameInterval) override;

private:
    static float GetDuration(const float& currentZoom, const float& targetZoom);

    static float GetCubicBezierY(const float& time);

    static float GetCubicBezierX(const float& time);

    static float BinarySearch(const float& value);

    static float GetInterpolation(const float& input);
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CUBIC_BEZIER_H