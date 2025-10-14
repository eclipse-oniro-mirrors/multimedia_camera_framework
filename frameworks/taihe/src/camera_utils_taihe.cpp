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
#include "input/camera_manager_taihe.h"
#include "camera_utils_taihe.h"
#include "camera_security_utils_taihe.h"
#include "camera_log.h"

namespace Ani::Camera {

constexpr size_t ZOOM_RANGE_SIZE = 2;
constexpr size_t ZOOM_MIN_INDEX = 0;
constexpr size_t ZOOM_MAX_INDEX = 1;

enum Rotation {
    ROTATION_0 = 0,
    ROTATION_90 = 90,
    ROTATION_180 = 180,
    ROTATION_270 = 270
};

enum ReturnValues {
    RETURN_VAL_0 = 0,
    RETURN_VAL_1 = 1,
    RETURN_VAL_2 = 2,
    RETURN_VAL_3 = 3,
    RETURN_VAL_DEFAULT = -1
};

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
    MEDIA_DEBUG_LOG("ToTaihePosition itr->second position = %{public}d ", itr->second.get_value());
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

SystemPressureLevel CameraUtilsTaihe::ToTaiheSystemPressureLevel(
    OHOS::CameraStandard::PressureStatus systemPressureLevel)
{
    auto itr = g_nativeToAniSystemPressureLevel.find(systemPressureLevel);
    if (itr == g_nativeToAniSystemPressureLevel.end()) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "ToTaiheSystemPressureLevel fail");
        return SystemPressureLevel::key_t::SYSTEM_PRESSURE_NORMAL;
    }
    return itr->second;
}

SlowMotionStatus CameraUtilsTaihe::ToTaiheSlowMotionState(OHOS::CameraStandard::SlowMotionState type)
{
    auto itr = g_nativeToAniSlowMotionState.find(type);
    if (itr == g_nativeToAniSlowMotionState.end()) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "ToTaiheSlowMotionState fail");
        return SlowMotionStatus::key_t::DISABLED;
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
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "ToTaiheFocusTrackingMode fail");
        return FocusTrackingMode::key_t::AUTO;
    }
    return itr->second;
}

array<FrameRateRange> CameraUtilsTaihe::ToTaiheArrayFrameRateRange(std::vector<std::vector<int32_t>> ratesRange)
{
    std::vector<FrameRateRange> vec;
    for (auto item : ratesRange) {
        FrameRateRange res {
            .min = item[0],
            .max = item[1],
        };
        vec.emplace_back(res);
    }
    return array<FrameRateRange>(vec);
}

array<ZoomPointInfo> CameraUtilsTaihe::ToTaiheArrayZoomPointInfo(
    std::vector<OHOS::CameraStandard::ZoomPointInfo> vecZoomPointInfoList)
{
    std::vector<ZoomPointInfo> vec;
    for (auto item : vecZoomPointInfoList) {
        ZoomPointInfo res {
            .zoomRatio = static_cast<double>(item.zoomRatio),
            .equivalentFocalLength = item.equivalentFocalLength,
        };
        vec.emplace_back(res);
    }
    return array<ZoomPointInfo>(vec);
}

array<PhysicalAperture> CameraUtilsTaihe::ToTaiheArrayPhysicalAperture(
    std::vector<std::vector<float>> physicalApertures)
{
    std::vector<PhysicalAperture> resVec;
    size_t zoomRangeSize = ZOOM_RANGE_SIZE;
    size_t zoomMinIndex = ZOOM_MIN_INDEX;
    size_t zoomMaxIndex = ZOOM_MAX_INDEX;
    std::vector<double> apertures;
    for (size_t i = 0; i < physicalApertures.size(); i++) {
        if (physicalApertures[i].size() <= zoomRangeSize) {
            continue;
        }
        PhysicalAperture res {};
        for (size_t y = 0; y < physicalApertures[i].size(); y++) {
            if (y == zoomMinIndex) {
                res.zoomRange.min = physicalApertures[i][y];
                continue;
            }
            if (y == zoomMaxIndex) {
                res.zoomRange.max = physicalApertures[i][y];
                continue;
            }
            apertures.push_back(static_cast<double>(physicalApertures[i][y]));
        }
        res.apertures = array<double>(apertures);
        apertures.clear();
        resVec.push_back(res);
    }
    return array<PhysicalAperture>(resVec);
}

CameraDevice CameraUtilsTaihe::ToTaiheCameraDevice(sptr<OHOS::CameraStandard::CameraDevice> &obj)
{
    CameraDevice cameraTaihe {
        .cameraId = ToTaiheString(obj->GetID()),
        .cameraPosition = ToTaihePosition(obj->GetPosition()),
        .cameraType = ToTaiheCameraType(obj->GetCameraType()),
        .connectionType = ToTaiheConnectionType(obj->GetConnectionType()),
        .isRetractable = optional<bool>::make(obj->GetisRetractable()),
        .hostDeviceType = HostDeviceType::from_value(static_cast<int32_t>(obj->GetDeviceType())),
        .hostDeviceName = ToTaiheString(obj->GetHostName()),
        .cameraOrientation = obj->GetCameraOrientation(),
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
        MEDIA_DEBUG_LOG("ToTaiheArraySceneMode src mode = %{public}d", item);
        auto itr = nativeToAniMap.find(item);
        if (itr != nativeToAniMap.end()) {
            MEDIA_DEBUG_LOG("ToTaiheArraySceneMode itr->second mode = %{public}d ", itr->second.get_value());
            vec.emplace_back(itr->second);
        }
    }
    return array<SceneMode>(vec);
}

array<CameraConcurrentInfo> CameraUtilsTaihe::ToTaiheCameraConcurrentInfoArray(
    std::vector<sptr<OHOS::CameraStandard::CameraDevice>>& cameraDeviceArray,
    std::vector<bool>& cameraConcurrentType, std::vector<std::vector<OHOS::CameraStandard::SceneMode>>& modes,
    std::vector<std::vector<sptr<OHOS::CameraStandard::CameraOutputCapability>>>& outputCapabilities)
{
    std::vector<CameraConcurrentInfo> aniCameraConcurrentInfoArray = {};
    std::vector<CameraOutputCapability> vec;
    size_t cameraDeviceArraySize = cameraDeviceArray.size();
    CHECK_RETURN_RET_ELOG(outputCapabilities.size() < cameraDeviceArraySize ||
        cameraConcurrentType.size() < cameraDeviceArraySize || modes.size() < cameraDeviceArraySize,
        array<CameraConcurrentInfo>(aniCameraConcurrentInfoArray),
        "ToTaiheCameraConcurrentInfoArray failed, out of range");
    for (size_t i = 0; i < cameraDeviceArraySize; ++i) {
        for (size_t j = 0; j < outputCapabilities[i].size(); j++) {
            if (outputCapabilities[i][j] == nullptr) {
                continue;
            }
            vec.push_back(CameraUtilsTaihe::ToTaiheCameraOutputCapability(outputCapabilities[i][j]));
        }
        CameraConcurrentInfo aniCameraConcurrentInfo = {
            .device = ToTaiheCameraDevice(cameraDeviceArray[i]),
            .type = ToTaiheCameraConcurrentTypeFromBool(cameraConcurrentType[i]),
            .modes = ToTaiheArraySceneMode(modes[i]),
            .outputCapabilities = array<CameraOutputCapability>(vec),
        };
        aniCameraConcurrentInfoArray.push_back(aniCameraConcurrentInfo);
        vec.clear();
    }
    return array<CameraConcurrentInfo>(aniCameraConcurrentInfoArray);
}

ohos::multimedia::camera::CameraConcurrentType CameraUtilsTaihe::ToTaiheCameraConcurrentTypeFromBool(
    bool isFullCapability)
{
    return isFullCapability ? ohos::multimedia::camera::CameraConcurrentType::key_t::CAMERA_FULL_CAPABILITY :
        ohos::multimedia::camera::CameraConcurrentType::key_t::CAMERA_LIMITED_CAPABILITY;
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

DepthDataQualityLevel CameraUtilsTaihe::ToTaiheDepthDataQualityLevel(int32_t level)
{
    auto itr = g_nativeToAniDepthDataQualityLevel.find(level);
    if (itr != g_nativeToAniDepthDataQualityLevel.end()) {
        return DepthDataQualityLevel(itr->second);
    }
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "ToTaiheDepthDataQualityLevel fail");
    return DepthDataQualityLevel::key_t::DEPTH_DATA_QUALITY_BAD;
}

DepthDataAccuracy CameraUtilsTaihe::ToTaiheDepthDataAccuracy(OHOS::CameraStandard::DepthDataAccuracy dataAccuracy)
{
    auto itr = g_nativeToAniDepthDataAccuracy.find(dataAccuracy);
    if (itr != g_nativeToAniDepthDataAccuracy.end()) {
        return DepthDataAccuracy(itr->second);
    }
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "ToTaiheDepthDataAccuracy fail");
    return DepthDataAccuracy::key_t::DEPTH_DATA_ACCURACY_RELATIVE;
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

int32_t CameraUtilsTaihe::ToTaiheImageRotation(int32_t retCode)
{
    switch (retCode) {
        case ROTATION_0:
            return RETURN_VAL_0;
        case ROTATION_90:
            return RETURN_VAL_1;
        case ROTATION_180:
            return RETURN_VAL_2;
        case ROTATION_270:
            return RETURN_VAL_3;
        default:
            return RETURN_VAL_DEFAULT;
    }
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

array<DepthProfile> CameraUtilsTaihe::ToTaiheArrayDepthProfiles(
    std::vector<OHOS::CameraStandard::DepthProfile> profiles)
{
    std::vector<DepthProfile> vec;
    for (auto &item : profiles) {
        CameraFormat cameraFormat = CameraUtilsTaihe::ToTaiheCameraFormat(item.GetCameraFormat());
        DepthProfile aniProfile {
            .size = {
                .height = item.GetSize().height,
                .width = item.GetSize().width,
            },
            .format = cameraFormat,
            .dataAccuracy = ToTaiheDepthDataAccuracy(item.GetDataAccuracy()),
        };
        vec.emplace_back(aniProfile);
    }
    return array<DepthProfile>(vec);
}

MetadataObjectType MapMetadataObjSupportedTypesEnum(OHOS::CameraStandard::MetadataObjectType nativeMetadataObjType)
{
    switch (nativeMetadataObjType) {
        case OHOS::CameraStandard::MetadataObjectType::FACE:
            return MetadataObjectType::key_t::FACE_DETECTION;
        case OHOS::CameraStandard::MetadataObjectType::HUMAN_BODY:
            return MetadataObjectType::key_t::HUMAN_BODY;
        case OHOS::CameraStandard::MetadataObjectType::CAT_FACE:
            return MetadataObjectType::key_t::CAT_FACE;
        case OHOS::CameraStandard::MetadataObjectType::CAT_BODY:
            return MetadataObjectType::key_t::CAT_BODY;
        case OHOS::CameraStandard::MetadataObjectType::DOG_FACE:
            return MetadataObjectType::key_t::DOG_FACE;
        case OHOS::CameraStandard::MetadataObjectType::DOG_BODY:
            return MetadataObjectType::key_t::DOG_BODY;
        case OHOS::CameraStandard::MetadataObjectType::SALIENT_DETECTION:
            return MetadataObjectType::key_t::SALIENT_DETECTION;
        case OHOS::CameraStandard::MetadataObjectType::BAR_CODE_DETECTION:
            return MetadataObjectType::key_t::BAR_CODE_DETECTION;
        default:
            // do nothing
            break;
    }
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "MapMetadataObjSupportedTypesEnum fail");
    return MetadataObjectType::key_t::FACE_DETECTION;
}

array<MetadataObjectType> CameraUtilsTaihe::ToTaiheArrayMetadataTypes(
    std::vector<OHOS::CameraStandard::MetadataObjectType> types)
{
    std::vector<MetadataObjectType> vec;
    for (auto item : types) {
        if (item > OHOS::CameraStandard::MetadataObjectType::BAR_CODE_DETECTION) {
            continue;
        }
        MetadataObjectType type = MapMetadataObjSupportedTypesEnum(item);
        vec.emplace_back(type);
    }
    return array<MetadataObjectType>(vec);
}

CameraOutputCapability CameraUtilsTaihe::ToTaiheCameraOutputCapability(
    sptr<OHOS::CameraStandard::CameraOutputCapability> &src)
{
    CameraOutputCapability aniCapability {
        .previewProfiles = ToTaiheArrayProfiles(src->GetPreviewProfiles()),
        .photoProfiles = ToTaiheArrayProfiles(src->GetPhotoProfiles()),
        .videoProfiles = ToTaiheArrayVideoProfiles(src->GetVideoProfiles()),
        .depthProfiles = ToTaiheArrayDepthProfiles(src->GetDepthProfiles()),
        .supportedMetadataObjectTypes = ToTaiheArrayMetadataTypes(src->GetSupportedMetadataObjectType()),
    };
    return aniCapability;
}

SketchStatusData CameraUtilsTaihe::ToTaiheSketchStatusData(
    const OHOS::CameraStandard::SketchStatusData& sketchStatusData)
{
    SketchStatusData aniSketchStatusData {
        .status = static_cast<int32_t>(sketchStatusData.status),
        .sketchRatio = sketchStatusData.sketchRatio,
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
        set_business_error(retCode, "Throw Error");
        return false;
    }
    return true;
}

ani_object CameraUtilsTaihe::ToBusinessError(ani_env *env, int32_t code, const std::string &message)
{
    ani_object err {};
    ani_class cls {};
    CHECK_RETURN_RET_ELOG(env == nullptr, err, "env is nullptr");
    CHECK_RETURN_RET_ELOG(ANI_OK != env->FindClass(CLASS_NAME_BUSINESSERROR, &cls), err,
        "find class %{public}s failed", CLASS_NAME_BUSINESSERROR);
    ani_method ctor {};
    CHECK_RETURN_RET_ELOG(ANI_OK != env->Class_FindMethod(cls, "<ctor>", ":", &ctor), err,
        "find method BusinessError constructor failed");
    ani_object error {};
    CHECK_RETURN_RET_ELOG(ANI_OK != env->Object_New(cls, ctor, &error), err,
        "new object %{public}s failed", CLASS_NAME_BUSINESSERROR);
    CHECK_RETURN_RET_ELOG(
        ANI_OK != env->Object_SetPropertyByName_Int(error, "code", static_cast<ani_int>(code)), err,
        "set property BusinessError.code failed");
    ani_string messageRef {};
    CHECK_RETURN_RET_ELOG(ANI_OK != env->String_NewUTF8(message.c_str(), message.size(), &messageRef), err,
        "new message string failed");
    CHECK_RETURN_RET_ELOG(
        ANI_OK != env->Object_SetPropertyByName_Ref(error, "message", static_cast<ani_ref>(messageRef)), err,
        "set property BusinessError.message failed");
    return error;
}

int32_t CameraUtilsTaihe::EnumGetValueInt32(ani_env *env, ani_enum_item enumItem)
{
    CHECK_RETURN_RET_ELOG(env == nullptr, -1, "Invalid env");
    ani_int aniInt {};
    CHECK_RETURN_RET_ELOG(ANI_OK != env->EnumItem_GetValue_Int(enumItem, &aniInt), -1,
        "EnumItem_GetValue_Int failed");
    return static_cast<int32_t>(aniInt);
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

void CameraUtilsTaihe::ToNativeCameraOutputCapability(CameraOutputCapability const& outputCapability,
    std::vector<OHOS::CameraStandard::Profile>& previewProfiles,
    std::vector<OHOS::CameraStandard::Profile>& photoProfiles,
    std::vector<OHOS::CameraStandard::VideoProfile>& videoProfiles)
{
    for (auto item : outputCapability.previewProfiles) {
        OHOS::CameraStandard::Profile nativeProfile(
            static_cast<OHOS::CameraStandard::CameraFormat>(item.format.get_value()),
                { .height = item.size.height, .width = item.size.width });
        previewProfiles.push_back(nativeProfile);
    }
    for (auto item : outputCapability.photoProfiles) {
        OHOS::CameraStandard::Profile nativeProfile(
            static_cast<OHOS::CameraStandard::CameraFormat>(item.format.get_value()),
                { .height = item.size.height, .width = item.size.width });
        photoProfiles.push_back(nativeProfile);
    }

    for (auto item : outputCapability.videoProfiles) {
        std::vector<int32_t> framerates;
        framerates.push_back(item.frameRateRange.min);
        framerates.push_back(item.frameRateRange.max);
        OHOS::CameraStandard::VideoProfile nativeProfile(
            static_cast<OHOS::CameraStandard::CameraFormat>(item.base.format.get_value()),
                { .height = item.base.size.height, .width = item.base.size.width }, framerates);
        videoProfiles.push_back(nativeProfile);
    }
}
} // namespace Ani::Camera
