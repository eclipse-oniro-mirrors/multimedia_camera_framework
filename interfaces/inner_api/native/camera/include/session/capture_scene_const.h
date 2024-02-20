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
};

enum SceneFeature : int32_t { MACRO = 1, MOON_CAPTURE_BOOST = 2 };

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
        if (IsEnableFeature(MACRO)) {
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