/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_MOON_CAPTURE_BOOST_FEATURE_H
#define OHOS_CAMERA_MOON_CAPTURE_BOOST_FEATURE_H

#include "abilities/sketch_ability.h"
#include "camera_metadata_info.h"
#include "capture_scene_const.h"

namespace OHOS {
namespace CameraStandard {
class MoonCaptureBoostFeature {
public:
    explicit MoonCaptureBoostFeature(
        SceneMode relatedMode, const std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceAbility);
    ~MoonCaptureBoostFeature() = default;
    float GetSketchEnableRatio();
    float GetSketchReferenceFovRatio(float inputZoomRatio);
    bool IsSupportedMoonCaptureBoostFeature();
    SceneMode GetRelatedMode();

private:
    SceneMode relatedMode_;
    std::vector<SketchReferenceFovRange> sketchFovRangeList_;
    SketchZoomRatioRange sketchZoomRatioRange_;
};
} // namespace CameraStandard
} // namespace OHOS

#endif