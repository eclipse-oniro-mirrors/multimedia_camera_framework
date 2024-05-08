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

#ifndef OHOS_CAMERA_CAPTURE_SCENE_CONST_H
#define OHOS_CAMERA_CAPTURE_SCENE_CONST_H

#include <cstdint>
#include <set>
#include <sstream>

namespace OHOS {
namespace CameraStandard {
enum JsSceneMode : int32_t {
    JS_NORMAL = 0,
    JS_CAPTURE = 1,
    JS_VIDEO = 2,
    JS_PORTRAIT = 3,
    JS_NIGHT = 4,
    JS_PROFESSIONAL_PHOTO = 5,
    JS_PROFESSIONAL_VIDEO = 6,
    JS_SLOW_MOTION = 7,
    JS_CAPTURE_MARCO = 8,
    JS_VIDEO_MARCO = 9,
    JS_HIGH_RES_PHOTO = 11,
    JS_SECURE_CAMERA = 15,
};

enum SceneMode : int32_t {
    NORMAL = 0,
    CAPTURE = 1,
    VIDEO = 2,
    PORTRAIT = 3,
    NIGHT = 4,
    PROFESSIONAL = 5,
    SLOW_MOTION = 6,
    SCAN = 7,
    CAPTURE_MACRO = 8,
    VIDEO_MACRO = 9,
    PROFESSIONAL_PHOTO = 11,
    PROFESSIONAL_VIDEO = 12,
    HIGH_FRAME_RATE = 13,
    HIGH_RES_PHOTO = 14,
    SECURE = 15
};

enum SceneFeature : int32_t {
    FEATURE_ENUM_MIN = 0,
    FEATURE_MOON_CAPTURE_BOOST = 0,
    FEATURE_TRIPOD_DETECTION,
    FEATURE_MACRO,
    FEATURE_ENUM_MAX
};

struct SceneFeaturesMode {
public:
    SceneFeaturesMode() = default;
    SceneFeaturesMode(SceneMode sceneMode, std::set<SceneFeature> sceneFeatures)
    {
        sceneMode_ = sceneMode;
        sceneFeatures_ = sceneFeatures;
    }

    bool IsEnableFeature(SceneFeature sceneFeature) const
    {
        auto it = sceneFeatures_.find(sceneFeature);
        if (it == sceneFeatures_.end()) {
            return false;
        }
        return true;
    }

    void SwitchFeature(SceneFeature sceneFeature, bool enable)
    {
        if (enable) {
            sceneFeatures_.insert(sceneFeature);
        } else {
            sceneFeatures_.erase(sceneFeature);
        }
    }

    void SetSceneMode(SceneMode sceneMode)
    {
        sceneMode_ = sceneMode;
    }

    SceneMode GetSceneMode() const
    {
        return sceneMode_;
    }

    SceneMode GetFeaturedMode() const
    {
        if (IsEnableFeature(FEATURE_MACRO)) {
            if (sceneMode_ == CAPTURE) {
                return CAPTURE_MACRO;
            } else if (sceneMode_ == VIDEO) {
                return VIDEO_MACRO;
            }
        }
        return sceneMode_;
    }

    std::set<SceneFeature> GetFeatures() const
    {
        return sceneFeatures_;
    }

    bool operator<(const SceneFeaturesMode& sceneFeaturesMode) const
    {
        if (sceneMode_ < sceneFeaturesMode.sceneMode_) {
            return true;
        } else if (sceneMode_ > sceneFeaturesMode.sceneMode_) {
            return false;
        }
        return sceneFeatures_ < sceneFeaturesMode.sceneFeatures_;
    }

    bool operator==(const SceneFeaturesMode& sceneFeaturesMode) const
    {
        return sceneMode_ == sceneFeaturesMode.sceneMode_ && sceneFeatures_ == sceneFeaturesMode.sceneFeatures_;
    }

    std::string Dump()
    {
        std::stringstream stringStream;
        stringStream << "SceneMode:" << sceneMode_;
        stringStream << "..Features:";
        stringStream << "[";
        bool isFirstElement = true;
        auto featuresIt = sceneFeatures_.begin();
        while (featuresIt != sceneFeatures_.end()) {
            if (isFirstElement) {
                stringStream << *featuresIt;
                isFirstElement = false;
            } else {
                stringStream << "," << *featuresIt;
            }
            featuresIt++;
        }
        stringStream << "]";
        return stringStream.str();
    }

private:
    SceneMode sceneMode_ = NORMAL;
    std::set<SceneFeature> sceneFeatures_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif