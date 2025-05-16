/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef FRAMEWORKS_TAIHE_INCLUDE_CAMERA_UTILS_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_CAMERA_UTILS_TAIHE_H

#include "taihe/runtime.hpp"
#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "camera_output_capability.h"
#include "camera_device.h"
#include "capture_session.h"
#include "capture_scene_const.h"
#include "metadata_output.h"
#include "video_session.h"
#include "time_lapse_photo_session.h"
#include "slow_motion_session.h"


namespace Ani::Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;
using namespace OHOS;

class CameraUtilsTaihe {
public:
    static string ToTaiheString(const std::string &src);
    static CameraPosition ToTaihePosition(OHOS::CameraStandard::CameraPosition position);
    static CameraType ToTaiheCameraType(OHOS::CameraStandard::CameraType type);
    static CameraDevice ToTaiheCameraDevice(sptr<OHOS::CameraStandard::CameraDevice> &obj);
    static ConnectionType ToTaiheConnectionType(OHOS::CameraStandard::ConnectionType type);
    static CameraFormat ToTaiheCameraFormat(OHOS::CameraStandard::CameraFormat format);
    static FocusState ToTaiheFocusState(OHOS::CameraStandard::FocusCallback::FocusState format);
    static MetadataObjectType ToTaiheMetadataObjectType(OHOS::CameraStandard::MetadataObjectType format);
    static array<MetadataObject> ToTaiheMetadataObjectsAvailableData(
        const std::vector<sptr<OHOS::CameraStandard::MetadataObject>> metadataObjList);
    static array<Profile> ToTaiheArrayProfiles(std::vector<OHOS::CameraStandard::Profile> profile);
    static array<VideoProfile> ToTaiheArrayVideoProfiles(std::vector<OHOS::CameraStandard::VideoProfile> profiles);
    static array<CameraDevice> ToTaiheArrayCameraDevice(
        const std::vector<sptr<OHOS::CameraStandard::CameraDevice>> &src);
    static array<SceneMode> ToTaiheArraySceneMode(const std::vector<OHOS::CameraStandard::SceneMode> &src);
    static CameraOutputCapability ToTaiheCameraOutputCapability(
        sptr<OHOS::CameraStandard::CameraOutputCapability> &src);
    static SketchStatusData ToTaiheSketchStatusData(const OHOS::CameraStandard::SketchStatusData& sketchStatusData);
    static SceneFeatureType ToTaiheSceneFeatureType(OHOS::CameraStandard::SceneFeature type);
    static bool ToTaiheMacroStatus(OHOS::CameraStandard::MacroStatusCallback::MacroStatus status);
    static ohos::multimedia::camera::TimeLapsePreviewType ToTaiheTimeLapsePreviewType(
        OHOS::CameraStandard::TimeLapsePreviewType type);
    static SlowMotionStatus ToTaiheSlowMotionState(OHOS::CameraStandard::SlowMotionState type);
    static EffectSuggestionType ToTaiheEffectSuggestionType(
        OHOS::CameraStandard::EffectSuggestionType effectSuggestionType);
    static LightStatus ToTaiheLightStatus(int32_t status);
    static FocusTrackingMode ToTaiheFocusTrackingMode(OHOS::CameraStandard::FocusTrackingMode mode);
    static int32_t IncrementAndGet(uint32_t& num);
    static bool CheckError(int32_t retCode);
    static ani_object ToBusinessError(ani_env *env, int32_t code, const std::string &message);
    static ani_object ToAniEnum(ani_env *env, int32_t value);
    inline static void ThrowError(int32_t code, const char* message)
    {
        set_business_error(code, message);
    }
    static bool GetEnableSecureCamera();
    static void IsEnableSecureCamera(bool isEnable);
    static uintptr_t GetUndefined(ani_env* env);
    static bool mEnableSecure;
};
} // namespace Ani::Camera

#endif // FRAMEWORKS_TAIHE_INCLUDE_CAMERA_UTILS_TAIHE_H