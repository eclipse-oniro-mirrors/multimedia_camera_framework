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

#include "features/moon_capture_boost_feature.h"

#include <cstdint>

#include "abilities/sketch_ability.h"
#include "camera_log.h"
#include "capture_scene_const.h"

namespace OHOS {
namespace CameraStandard {
constexpr uint32_t INVALID_MODE = 0xffffffff;
constexpr float INVALID_ZOOM_RATIO = -1.0f;
constexpr float SKETCH_DEFAULT_FOV_RATIO = 1.0f;
constexpr float SKETCH_DIV = 100.0f;
MoonCaptureBoostFeature::MoonCaptureBoostFeature(
    SceneMode relatedMode, const std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceAbility)
    : relatedMode_(relatedMode)
{
    MEDIA_INFO_LOG("MoonCaptureBoostFeature::MoonCaptureBoostFeature SceneMode:%{public}d", relatedMode);
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(deviceAbility->get(), OHOS_ABILITY_MOON_CAPTURE_BOOST, &item);
    if (ret != CAM_META_SUCCESS || item.count <= 0) {
        MEDIA_ERR_LOG("MoonCaptureBoostFeature get OHOS_ABILITY_MOON_CAPTURE_BOOST failed");
        return;
    }

    uint32_t currentMode = INVALID_MODE;
    float currentMinRatio = INVALID_ZOOM_RATIO;
    float currentMaxRatio = INVALID_ZOOM_RATIO;
    for (uint32_t i = 0; i < item.count; i++) {
        if (currentMode == INVALID_MODE) {
            currentMode = static_cast<SceneMode>(item.data.ui32[i]);
            continue;
        }
        if (currentMinRatio == INVALID_ZOOM_RATIO) {
            currentMinRatio = static_cast<float>(item.data.ui32[i]) / SKETCH_DIV;
            continue;
        }
        if (currentMaxRatio == INVALID_ZOOM_RATIO) {
            currentMaxRatio = static_cast<float>(item.data.ui32[i]) / SKETCH_DIV;
            continue;
        }
        SketchReferenceFovRange fovRange;
        fovRange.zoomMin = static_cast<float>(item.data.ui32[i]) / SKETCH_DIV;
        fovRange.zoomMax = static_cast<float>(item.data.ui32[i + 1]) / SKETCH_DIV;        // Offset 1 data
        fovRange.referenceValue = static_cast<float>(item.data.ui32[i + 2]) / SKETCH_DIV; // Offset 2 data
        i = i + 2;                                                                        // Offset 2 data
        sketchFovRangeList_.emplace_back(fovRange);
        MEDIA_DEBUG_LOG(
            "MoonCaptureBoostFeature::MoonCaptureBoostFeature get sketch reference fov ratio:mode->%{public}d "
            "%{public}f-%{public}f value->%{public}f",
            currentMode, fovRange.zoomMin, fovRange.zoomMax, fovRange.referenceValue);
        if (fovRange.zoomMax - currentMaxRatio >= -std::numeric_limits<float>::epsilon()) {
            if (currentMode == static_cast<uint32_t>(relatedMode_)) {
                sketchZoomRatioRange_.zoomMin = currentMinRatio;
                sketchZoomRatioRange_.zoomMax = currentMaxRatio;
                break;
            }
            currentMode = INVALID_MODE;
            currentMinRatio = INVALID_ZOOM_RATIO;
            currentMaxRatio = INVALID_ZOOM_RATIO;
            sketchFovRangeList_.clear();
        }
    }
}

float MoonCaptureBoostFeature::GetSketchEnableRatio()
{
    return sketchZoomRatioRange_.zoomMin;
}

float MoonCaptureBoostFeature::GetSketchReferenceFovRatio(float inputZoomRatio)
{
    auto itRange =
        std::find_if(sketchFovRangeList_.begin(), sketchFovRangeList_.end(), [inputZoomRatio](const auto& range) {
            return inputZoomRatio - range.zoomMin >= -std::numeric_limits<float>::epsilon() &&
                   inputZoomRatio - range.zoomMax < -std::numeric_limits<float>::epsilon();
        });
    if (itRange != sketchFovRangeList_.end()) {
        return itRange->referenceValue;
    }
    MEDIA_WARNING_LOG("MoonCaptureBoostFeature::GetSketchReferenceFovRatio fail input:%{public}f, "
                      "zoomRange:%{public}f-%{public}f ,return default value.",
        inputZoomRatio, sketchZoomRatioRange_.zoomMin, sketchZoomRatioRange_.zoomMax);
    return SKETCH_DEFAULT_FOV_RATIO;
}

bool MoonCaptureBoostFeature::IsSupportedMoonCaptureBoostFeature()
{
    return !sketchFovRangeList_.empty();
}

SceneMode MoonCaptureBoostFeature::GetRelatedMode()
{
    return relatedMode_;
}
} // namespace CameraStandard
} // namespace OHOS