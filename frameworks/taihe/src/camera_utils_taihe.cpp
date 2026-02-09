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

namespace Ani::Camera {

constexpr size_t ZOOM_RANGE_SIZE = 2;
constexpr size_t ZOOM_MIN_INDEX = 0;
constexpr size_t ZOOM_MAX_INDEX = 1;
constexpr int32_t FRAME_RATES_SIZE = 2;

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
    RETURN_VAL_3 = 3
};

string CameraUtilsTaihe::ToTaiheString(const std::string &src)
{
    return ::taihe::string(src);
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

CameraDevice CameraUtilsTaihe::GetNullCameraDevice()
{
    std::string defaultString = "";
    CameraDevice cameraTaihe {
        .cameraId = CameraUtilsTaihe::ToTaiheString(defaultString),
        .cameraPosition = CameraPosition::key_t::CAMERA_POSITION_UNSPECIFIED,
        .cameraType = CameraType::key_t::CAMERA_TYPE_DEFAULT,
        .connectionType = ConnectionType::key_t::CAMERA_CONNECTION_BUILT_IN,
        .isRetractable = optional<bool>(std::nullopt),
        .hostDeviceType = HostDeviceType::key_t::UNKNOWN_TYPE,
        .hostDeviceName = CameraUtilsTaihe::ToTaiheString(defaultString),
        .cameraOrientation = 0,
        .lensEquivalentFocalLength = optional<array<int32_t>>(std::nullopt),
        .automotiveCameraPosition = optional<AutomotiveCameraPosition>(std::nullopt),
    };
    return cameraTaihe;
}

array<CameraDevice> CameraUtilsTaihe::GetNullCameraDeviceArray()
{
    std::vector<CameraDevice> cameraDeviceVec;
    cameraDeviceVec.emplace_back(GetNullCameraDevice());
    return array<CameraDevice>(cameraDeviceVec);
}

CameraDevice CameraUtilsTaihe::ToTaiheCameraDevice(sptr<OHOS::CameraStandard::CameraDevice> &obj)
{
    CameraDevice cameraTaihe = CameraUtilsTaihe::GetNullCameraDevice();
    CHECK_RETURN_RET_ELOG(!obj, cameraTaihe, "obj is null");
    cameraTaihe.cameraId = ToTaiheString(obj->GetID());
    cameraTaihe.cameraPosition = CameraPosition::from_value(static_cast<int32_t>(obj->GetPosition()));
    cameraTaihe.cameraType = CameraType::from_value(static_cast<int32_t>(obj->GetCameraType()));
    cameraTaihe.connectionType = ConnectionType::from_value(static_cast<int32_t>(obj->GetConnectionType()));
    cameraTaihe.isRetractable = optional<bool>::make(obj->GetisRetractable());
    cameraTaihe.hostDeviceType = HostDeviceType::from_value(static_cast<int32_t>(obj->GetDeviceType()));
    cameraTaihe.hostDeviceName = ToTaiheString(obj->GetHostName());
    cameraTaihe.cameraOrientation = obj->GetCameraOrientation();
    std::vector<int32_t> lensEquivalentFocalLength = obj->GetLensEquivalentFocalLength();
    cameraTaihe.lensEquivalentFocalLength =
        optional<array<int32_t>>(std::in_place, array<int32_t>(lensEquivalentFocalLength));
    cameraTaihe.automotiveCameraPosition = optional<AutomotiveCameraPosition>(std::in_place,
        AutomotiveCameraPosition::from_value(static_cast<int32_t>(obj->GetAutomotivePosition())));
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
            return RETURN_VAL_0;
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
            .type = MetadataObjectType::from_value(static_cast<int32_t>(it->GetType())),
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
        CameraFormat cameraFormat = CameraFormat::from_value(static_cast<int32_t>(item.GetCameraFormat()));
        CHECK_CONTINUE_ELOG(!cameraFormat.is_valid(),
            "ToTaiheArrayProfiles failed, cameraFormat is error");
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
        CHECK_CONTINUE_ELOG(frameRates.size() < FRAME_RATES_SIZE,
            "ToTaiheArrayVideoProfiles failed, frameRates is error");
        CameraFormat cameraFormat = CameraFormat::from_value(static_cast<int32_t>(item.GetCameraFormat()));
        CHECK_CONTINUE_ELOG(!cameraFormat.is_valid(),
            "ToTaiheArrayVideoProfiles failed, cameraFormat is error");
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
        CameraFormat cameraFormat = CameraFormat::from_value(static_cast<int32_t>(item.GetCameraFormat()));
        CHECK_CONTINUE_ELOG(!cameraFormat.is_valid(),
            "ToTaiheArrayDepthProfiles failed, cameraFormat is error");
        DepthProfile aniProfile {
            .size = {
                .height = item.GetSize().height,
                .width = item.GetSize().width,
            },
            .format = cameraFormat,
            .dataAccuracy = DepthDataAccuracy::from_value(static_cast<int32_t>(item.GetDataAccuracy())),
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
        if (item < OHOS::CameraStandard::MetadataObjectType::FACE
            || item > OHOS::CameraStandard::MetadataObjectType::BAR_CODE_DETECTION) {
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
        .centerPointOffset = {
            .x = static_cast<double>(sketchStatusData.offsetx),
            .y = static_cast<double>(sketchStatusData.offsety),
        },
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
    for (const auto& item : outputCapability.previewProfiles) {
        OHOS::CameraStandard::Profile nativeProfile(
            static_cast<OHOS::CameraStandard::CameraFormat>(item.format.get_value()),
                { .height = item.size.height, .width = item.size.width });
        previewProfiles.push_back(nativeProfile);
    }
    for (const auto& item : outputCapability.photoProfiles) {
        OHOS::CameraStandard::Profile nativeProfile(
            static_cast<OHOS::CameraStandard::CameraFormat>(item.format.get_value()),
                { .height = item.size.height, .width = item.size.width });
        photoProfiles.push_back(nativeProfile);
    }

    for (const auto& item : outputCapability.videoProfiles) {
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
