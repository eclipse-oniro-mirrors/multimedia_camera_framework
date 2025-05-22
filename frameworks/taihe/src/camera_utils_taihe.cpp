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

#include "camera_const_ability_taihe.h"
#include "camera_manager_taihe.h"
#include "camera_utils_taihe.h"
#include "camera_security_utils_taihe.h"
#include "camera_log.h"

namespace Ani::Camera {

bool CameraUtilsTaihe::mEnableSecure = false;

string CameraUtilsTaihe::ToTaiheString(const std::string &src)
{
    return ::taihe::string(src);
}

CameraPosition CameraUtilsTaihe::ToTaihePosition(OHOS::CameraStandard::CameraPosition position)
{
    auto itr = g_nativeToAniCameraPosition.find(position);
    if (itr == g_nativeToAniCameraPosition.end()) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "ToTaihePosition fail");
        return CameraPosition::key_t::CAMERA_POSITION_UNSPECIFIED;
    }
    MEDIA_ERR_LOG("ToTaihePosition itr->second position = %{public}d ", itr->second.get_value());
    return itr->second;
}

CameraType CameraUtilsTaihe::ToTaiheCameraType(OHOS::CameraStandard::CameraType type)
{
    auto itr = g_nativeToAniCameraType.find(type);
    if (itr == g_nativeToAniCameraType.end()) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "ToTaiheCameraType fail");
        return CameraType::key_t::CAMERA_TYPE_DEFAULT;
    }
    return itr->second;
}

SceneFeatureType CameraUtilsTaihe::ToTaiheSceneFeatureType(OHOS::CameraStandard::SceneFeature type)
{
    auto itr = g_nativeToAniSceneFeatureType.find(type);
    if (itr == g_nativeToAniSceneFeatureType.end()) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "ToTaiheSceneFeatureType fail");
        return SceneFeatureType::key_t::MOON_CAPTURE_BOOST;
    }
    return itr->second;
}

bool CameraUtilsTaihe::ToTaiheMacroStatus(OHOS::CameraStandard::MacroStatusCallback::MacroStatus status)
{
    auto itr = g_nativeToAniMacroStatus.find(status);
    if (itr == g_nativeToAniMacroStatus.end()) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "ToTaiheMacroStatus fail");
        return false;
    }
    return itr->second;
}

ohos::multimedia::camera::TimeLapsePreviewType CameraUtilsTaihe::ToTaiheTimeLapsePreviewType(
    OHOS::CameraStandard::TimeLapsePreviewType type)
{
    auto itr = g_nativeToAniTimeLapsePreviewType.find(type);
    if (itr == g_nativeToAniTimeLapsePreviewType.end()) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "ToTaiheTimeLapsePreviewType fail");
        return ohos::multimedia::camera::TimeLapsePreviewType::key_t::DARK;
    }
    return itr->second;
}

EffectSuggestionType CameraUtilsTaihe::ToTaiheEffectSuggestionType(
    OHOS::CameraStandard::EffectSuggestionType effectSuggestionType)
{
    auto itr = g_nativeToAniEffectSuggestionType.find(effectSuggestionType);
    if (itr == g_nativeToAniEffectSuggestionType.end()) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "ToTaiheEffectSuggestionType fail");
        return EffectSuggestionType::key_t::EFFECT_SUGGESTION_NONE;
    }
    return itr->second;
}

SlowMotionStatus CameraUtilsTaihe::ToTaiheSlowMotionState(OHOS::CameraStandard::SlowMotionState type)
{
    auto itr = g_nativeToAniSlowMotionState.find(type);
    if (itr == g_nativeToAniSlowMotionState.end()) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "ToTaiheSlowMotionState fail");
        return SlowMotionStatus::key_t::DISABLE;
    }
    return itr->second;
}

ConnectionType CameraUtilsTaihe::ToTaiheConnectionType(OHOS::CameraStandard::ConnectionType type)
{
    auto itr = g_nativeToAniConnectionType.find(type);
    if (itr == g_nativeToAniConnectionType.end()) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "ToTaiheConnectionType fail");
        return ConnectionType::key_t::CAMERA_CONNECTION_BUILT_IN;
    }
    return itr->second;
}

LightStatus CameraUtilsTaihe::ToTaiheLightStatus(int32_t status)
{
    auto itr = g_nativeToAniLightStatus.find(status);
    if (itr == g_nativeToAniLightStatus.end()) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "ToTaiheLightStatus fail");
        return LightStatus::key_t::NORMAL;
    }
    return itr->second;
}

FocusTrackingMode CameraUtilsTaihe::ToTaiheFocusTrackingMode(OHOS::CameraStandard::FocusTrackingMode mode)
{
    auto itr = g_nativeToAniFocusTrackingMode.find(mode);
    if (itr == g_nativeToAniFocusTrackingMode.end()) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "ToTaiheLightStatus fail");
        return FocusTrackingMode::key_t::AUTO;
    }
    return itr->second;
}

CameraDevice CameraUtilsTaihe::ToTaiheCameraDevice(sptr<OHOS::CameraStandard::CameraDevice> &obj)
{
    CameraDevice cameraTaihe {
        .cameraId = ToTaiheString(obj->GetID()),
        .cameraPosition = ToTaihePosition(obj->GetPosition()),
        .cameraType = ToTaiheCameraType(obj->GetCameraType()),
        .connectionType = ToTaiheConnectionType(obj->GetConnectionType()),
    };
    return cameraTaihe;
}

array<CameraDevice> CameraUtilsTaihe::ToTaiheArrayCameraDevice(
    const std::vector<sptr<OHOS::CameraStandard::CameraDevice>> &src)
{
    std::vector<CameraDevice> vec;
    for (auto item : src) {
        vec.emplace_back(ToTaiheCameraDevice(item));
    }
    return array<CameraDevice>(vec);
}

array<SceneMode> CameraUtilsTaihe::ToTaiheArraySceneMode(const std::vector<OHOS::CameraStandard::SceneMode> &src)
{
    std::vector<SceneMode> vec;
    std::unordered_map<OHOS::CameraStandard::SceneMode, SceneMode> nativeToAniMap = g_nativeToAniSupportedMode;
    if (OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(false)) {
        nativeToAniMap = g_nativeToAniSupportedModeSys;
    }
    for (auto &item : src) {
        MEDIA_ERR_LOG("ToTaiheArraySceneMode src mode = %{public}d", item);
        auto itr = nativeToAniMap.find(item);
        if (itr != nativeToAniMap.end()) {
            MEDIA_ERR_LOG("ToTaiheArraySceneMode itr->second mode = %{public}d ", itr->second.get_value());
            vec.emplace_back(itr->second);
        }
    }
    return array<SceneMode>(vec);
}

CameraFormat CameraUtilsTaihe::ToTaiheCameraFormat(OHOS::CameraStandard::CameraFormat format)
{
    auto itr = g_nativeToAniCameraFormat.find(format);
    if (itr != g_nativeToAniCameraFormat.end()) {
        return CameraFormat(itr->second);
    }
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "ToTaiheCameraFormat fail");
    return CameraFormat::key_t::CAMERA_FORMAT_YUV_420_SP;
}

FocusState CameraUtilsTaihe::ToTaiheFocusState(OHOS::CameraStandard::FocusCallback::FocusState format)
{
    auto itr = g_nativeToAniFocusState.find(format);
    if (itr != g_nativeToAniFocusState.end()) {
        return FocusState(itr->second);
    }
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "ToTaiheFocusState fail");
    return FocusState::key_t::FOCUS_STATE_SCAN;
}

MetadataObjectType CameraUtilsTaihe::ToTaiheMetadataObjectType(OHOS::CameraStandard::MetadataObjectType format)
{
    auto itr = g_nativeToAniMetadataObjectType.find(format);
    if (itr != g_nativeToAniMetadataObjectType.end()) {
        return MetadataObjectType(itr->second);
    }
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "ToTaiheMetadataObjectType fail");
    return MetadataObjectType::key_t::FACE_DETECTION;
}

array<MetadataObject> CameraUtilsTaihe::ToTaiheMetadataObjectsAvailableData(
    const std::vector<sptr<OHOS::CameraStandard::MetadataObject>> metadataObjList)
{
    MEDIA_DEBUG_LOG("OnMetadataObjectsAvailableCallback is called");
    std::vector<MetadataObject> vec;
    for (auto &it : metadataObjList) {
        OHOS::CameraStandard::Rect boundingbox = it->GetBoundingBox();
        MetadataObject aniMetadataObject = {
            .type = CameraUtilsTaihe::ToTaiheMetadataObjectType(it->GetType()),
            .timestamp = it->GetTimestamp(),
            .boundingBox = ohos::multimedia::camera::Rect { boundingbox.topLeftX, boundingbox.topLeftY,
                                                            boundingbox.width, boundingbox.height },
            .objectId = it->GetObjectId(),
            .confidence = it->GetConfidence()};
        vec.emplace_back(aniMetadataObject);
    }
    return array<MetadataObject>(vec);
}

array<Profile> CameraUtilsTaihe::ToTaiheArrayProfiles(std::vector<OHOS::CameraStandard::Profile> profiles)
{
    std::vector<Profile> vec;
    for (auto &item : profiles) {
        MEDIA_ERR_LOG("ToTaiheArrayProfiles src mode = %{public}d", item.GetSize().height);
        CameraFormat cameraFormat = CameraUtilsTaihe::ToTaiheCameraFormat(item.GetCameraFormat());
        Profile aniProfile {
            .size = {
                .height = item.GetSize().height,
                .width = item.GetSize().width,
            },
            .format = cameraFormat,
        };
        vec.emplace_back(aniProfile);
    }
    return array<Profile>(vec);
}

array<VideoProfile> CameraUtilsTaihe::ToTaiheArrayVideoProfiles(
    std::vector<OHOS::CameraStandard::VideoProfile> profiles)
{
    std::vector<VideoProfile> vec;
    for (auto &item : profiles) {
        MEDIA_ERR_LOG("ToTaiheArrayProfiles src mode = %{public}d", item.GetSize().height);
        auto frameRates = item.GetFrameRates();
        CameraFormat cameraFormat = CameraUtilsTaihe::ToTaiheCameraFormat(item.GetCameraFormat());
        VideoProfile aniProfile {
            .base = {
                .size = {
                    .height = item.GetSize().height,
                    .width = item.GetSize().width,
                },
                .format = cameraFormat,
            },
            .frameRateRange = {
                .min = frameRates[0] >= frameRates[1] ? frameRates[1] : frameRates[0],
                .max = frameRates[0] >= frameRates[1] ? frameRates[0] : frameRates[1],
            },
        };
        vec.emplace_back(aniProfile);
    }
    return array<VideoProfile>(vec);
}

CameraOutputCapability CameraUtilsTaihe::ToTaiheCameraOutputCapability(
    sptr<OHOS::CameraStandard::CameraOutputCapability> &src)
{
    CameraOutputCapability aniCapability {
        .previewProfiles = ToTaiheArrayProfiles(src->GetPreviewProfiles()),
        .photoProfiles = ToTaiheArrayProfiles(src->GetPhotoProfiles()),
        .videoProfiles = ToTaiheArrayVideoProfiles(src->GetVideoProfiles()),
    };
    return aniCapability;
}

SketchStatusData CameraUtilsTaihe::ToTaiheSketchStatusData(
    const OHOS::CameraStandard::SketchStatusData& sketchStatusData)
{
    SketchStatusData aniSketchStatusData {
        .status = static_cast<int32_t>(sketchStatusData.status),
        .sketchRatio = static_cast<float>(sketchStatusData.sketchRatio),
    };
    return aniSketchStatusData;
}

int32_t CameraUtilsTaihe::IncrementAndGet(uint32_t& num)
{
    int32_t temp = num & 0x00ffffff;
    if (temp >= 0xffff) {
        num = num & 0xff000000;
    }
    num++;
    return num;
}

bool CameraUtilsTaihe::CheckError(int32_t retCode)
{
    if ((retCode != 0)) {
        set_business_error(retCode, " ");
        return false;
    }
    return true;
}

ani_object CameraUtilsTaihe::ToBusinessError(ani_env *env, int32_t code, const std::string &message)
{
    ani_object err {};
    ani_class cls {};
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->FindClass(CLASS_NAME_BUSINESSERROR, &cls), err,
        "find class %{public}s failed", CLASS_NAME_BUSINESSERROR);
    ani_method ctor {};
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->Class_FindMethod(cls, "<ctor>", ":V", &ctor), err,
        "find method BusinessError constructor failed");
    ani_object error {};
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->Object_New(cls, ctor, &error), err,
        "new object %{public}s failed", CLASS_NAME_BUSINESSERROR);
    CHECK_ERROR_RETURN_RET_LOG(
        ANI_OK != env->Object_SetPropertyByName_Double(error, "code", static_cast<ani_double>(code)), err,
        "set property BusinessError.code failed");
    ani_string messageRef {};
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->String_NewUTF8(message.c_str(), message.size(), &messageRef), err,
        "new message string failed");
    CHECK_ERROR_RETURN_RET_LOG(
        ANI_OK != env->Object_SetPropertyByName_Ref(error, "message", static_cast<ani_ref>(messageRef)), err,
        "set property BusinessError.message failed");
    return error;
}


ani_object CameraUtilsTaihe::ToAniEnum(ani_env *env, int32_t taiheKey)
{
    ani_enum aniEnum {};
    ani_object res {};
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->FindEnum("I", &aniEnum), res,
        "find class %{public}s failed", CLASS_NAME_ENUM);

    ani_enum_item aniEnumItem {};
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->Enum_GetEnumItemByIndex(aniEnum, static_cast<ani_size>(taiheKey),
        &aniEnumItem), res, "get enum item failed");

    ani_class cls {};
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->FindClass(CLASS_NAME_ENUM, &cls), res,
        "find class %{public}s failed", CLASS_NAME_ENUM);
    ani_method ctor {};
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->Class_FindMethod(cls, "<ctor>", "I:V", &ctor), res,
        "find method BusinessError constructor failed");

    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->Object_New(cls, ctor, &res, aniEnumItem),
        res, "new object %{public}s failed", CLASS_NAME_BUSINESSERROR);
    return res;
}

bool CameraUtilsTaihe::GetEnableSecureCamera()
{
    return mEnableSecure;
}

void CameraUtilsTaihe::IsEnableSecureCamera(bool isEnable)
{
    mEnableSecure = isEnable;
}

uintptr_t CameraUtilsTaihe::GetUndefined(ani_env* env)
{
    ani_ref undefinedRef {};
    if (env == nullptr) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "Invalid env");
        return 0;
    }
    env->GetUndefined(&undefinedRef);
    ani_object undefinedObject = static_cast<ani_object>(undefinedRef);
    return reinterpret_cast<uintptr_t>(undefinedObject);
}
} // namespace Ani::Camera
