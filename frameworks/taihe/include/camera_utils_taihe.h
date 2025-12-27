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
#include "ohos.multimedia.cameraPicker.proj.hpp"
#include "ohos.multimedia.cameraPicker.impl.hpp"
#include "camera_output_capability.h"
#include "camera_device.h"
#include "capture_session.h"
#include "capture_scene_const.h"
#include "metadata_output.h"
#include "video_session.h"
#include "video_output.h"
#include "time_lapse_photo_session.h"
#include "slow_motion_session.h"
#include "camera_log.h"

namespace Ani::Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;
using namespace OHOS;

class CameraUtilsTaihe {
public:
    static string ToTaiheString(const std::string &src);
    static CameraDevice ToTaiheCameraDevice(sptr<OHOS::CameraStandard::CameraDevice> &obj);
    static CameraDevice GetNullCameraDevice();
    static array<CameraDevice> GetNullCameraDeviceArray();
    static array<DepthProfile> ToTaiheArrayDepthProfiles(std::vector<OHOS::CameraStandard::DepthProfile> profiles);
    static array<MetadataObjectType> ToTaiheArrayMetadataTypes(
        std::vector<OHOS::CameraStandard::MetadataObjectType> types);
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
    static bool ToTaiheMacroStatus(OHOS::CameraStandard::MacroStatusCallback::MacroStatus status);
    static array<FrameRateRange> ToTaiheArrayFrameRateRange(std::vector<std::vector<int32_t>> ratesRange);
    static array<PhysicalAperture> ToTaiheArrayPhysicalAperture(std::vector<std::vector<float>> physicalApertures);
    static array<ZoomPointInfo> ToTaiheArrayZoomPointInfo(
        std::vector<OHOS::CameraStandard::ZoomPointInfo> vecZoomPointInfoList);
    static int32_t IncrementAndGet(uint32_t& num);
    static int32_t ToTaiheImageRotation(int32_t retCode);
    static bool CheckError(int32_t retCode);
    static ani_object ToBusinessError(ani_env *env, int32_t code, const std::string &message);
    static int32_t EnumGetValueInt32(ani_env *env, ani_enum_item enumItem);
    inline static void ThrowError(int32_t code, const char* message)
    {
        set_business_error(code, message);
    }
    static uintptr_t GetUndefined(ani_env* env);
    static void ToNativeCameraOutputCapability(CameraOutputCapability const& outputCapability,
        std::vector<OHOS::CameraStandard::Profile>& previewProfiles,
        std::vector<OHOS::CameraStandard::Profile>& photoProfiles,
        std::vector<OHOS::CameraStandard::VideoProfile>& videoProfileList);
    static array<CameraConcurrentInfo> ToTaiheCameraConcurrentInfoArray(
        std::vector<sptr<OHOS::CameraStandard::CameraDevice>>& cameraDeviceArray,
        std::vector<bool>& cameraConcurrentType, std::vector<std::vector<OHOS::CameraStandard::SceneMode>>& modes,
        std::vector<std::vector<sptr<OHOS::CameraStandard::CameraOutputCapability>>>& outputCapabilities);
    static ohos::multimedia::camera::CameraConcurrentType ToTaiheCameraConcurrentTypeFromBool(bool isFullCapability);
    template<typename T, typename E>
    static inline array<T> ToTaiheArrayEnum(std::vector<E> src)
    {
        std::vector<T> vec;
        for (auto item : src) {
            T res = T::from_value(static_cast<int32_t>(item));
            vec.emplace_back(res);
        }
        return array<T>(vec);
    }
};
} // namespace Ani::Camera

#endif // FRAMEWORKS_TAIHE_INCLUDE_CAMERA_UTILS_TAIHE_H