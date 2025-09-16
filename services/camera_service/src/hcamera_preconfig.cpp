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

#include "hcamera_preconfig.h"

#include <cstdint>
#include <memory>
#include <queue>
#include <string>
#include <utility>

#include "ability/camera_ability_parse_util.h"
#include "camera_stream_info_parse.h"
#include "camera_device_ability_items.h"
#include "camera_metadata_info.h"
#include "hcamera_host_manager.h"
#include "v1_3/types.h"

namespace OHOS {
namespace CameraStandard {
namespace {

static constexpr float RATIO_VALUE_1_1 = 1.0f;
static constexpr float RATIO_VALUE_4_3 = 4.0f / 3;
static constexpr float RATIO_VALUE_16_9 = 16.0f / 9;

enum PreconfigType {
    PRECONFIG_TYPE_720P,
    PRECONFIG_TYPE_1080P,
    PRECONFIG_TYPE_4K,
    PRECONFIG_TYPE_HIGH_QUALITY,
};

enum PreconfigRatio {
    RATIO_1_1,
    RATIO_4_3,
    RATIO_16_9,
};

struct CameraInfo {
    std::string cameraId;
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability;
};

template<typename T>
std::shared_ptr<T> GetMaxSizeDetailInfo(std::vector<T>& detailInfos, float targetRatioValue, camera_format_t format)
{
    CHECK_RETURN_RET(targetRatioValue <= 0, nullptr);
    std::shared_ptr<T> maxSizeProfile = nullptr;
    for (auto& detailInfo : detailInfos) {
        if (detailInfo.width == 0 || detailInfo.height == 0 || detailInfo.format != format) {
            continue;
        }
        float ratio = ((float)detailInfo.width) / detailInfo.height;
        if (abs(ratio - targetRatioValue) / targetRatioValue > 0.05f) { // 0.05f is 5% tolerance.
            continue;
        }
        if (maxSizeProfile == nullptr || detailInfo.width > maxSizeProfile->width) {
            maxSizeProfile = std::make_shared<T>(detailInfo);
        }
    }
    return maxSizeProfile;
}

struct PreconfigProfile {
    std::string format;
    int32_t width;
    int32_t height;
    int32_t fpsMin;
    int32_t fpsMax;
    int32_t fpsPrefer;
    bool followSensorMax = false;
    PreconfigRatio followSensorMaxRatio = RATIO_4_3;

    std::string toString()
    {
        return "Format:" + format + "\tSize:" + std::to_string(width) + "x" + std::to_string(height) +
               "\tFps:" + std::to_string(fpsMin) + "-" + std::to_string(fpsMax) +
               ",prefer:" + std::to_string(fpsPrefer);
    }

    float GetRatioValue(PreconfigRatio preconfigRatio)
    {
        float ratioValue = RATIO_VALUE_4_3;
        switch (preconfigRatio) {
            case RATIO_1_1:
                ratioValue = RATIO_VALUE_1_1;
                break;
            case RATIO_4_3:
                ratioValue = RATIO_VALUE_4_3;
                break;
            case RATIO_16_9:
                ratioValue = RATIO_VALUE_16_9;
                break;
            default:
                // Do nothing
                break;
        }
        return ratioValue;
    }

    std::shared_ptr<ProfileDetailInfo> FindMaxDetailInfoFromProfileLevel(
        CameraInfo& cameraInfo, HDI::Camera::V1_3::OperationMode modeName)
    {
        camera_metadata_item_t item;
        int ret = OHOS::Camera::CameraMetadata::FindCameraMetadataItem(
            cameraInfo.ability->get(), OHOS_ABILITY_AVAILABLE_PROFILE_LEVEL, &item);
        CHECK_RETURN_RET(ret != CAM_META_SUCCESS || item.count == 0, nullptr);
        std::vector<SpecInfo> specInfos;
        ProfileLevelInfo modeInfo = {};
        CameraAbilityParseUtil::GetModeInfo(modeName, item, modeInfo);
        specInfos.insert(specInfos.end(), modeInfo.specInfos.begin(), modeInfo.specInfos.end());
        for (SpecInfo& specInfo : specInfos) {
            for (StreamInfo& streamInfo : specInfo.streamInfos) {
                if (streamInfo.streamType != HDI::Camera::V1_3::StreamType::STREAM_TYPE_STILL_CAPTURE) {
                    continue;
                }
                float ratioValue = GetRatioValue(followSensorMaxRatio);
                return GetMaxSizeDetailInfo(streamInfo.detailInfos, ratioValue, OHOS_CAMERA_FORMAT_JPEG);
            }
        }
        return nullptr;
    }

    std::shared_ptr<DetailInfo> FindMaxDetailInfoFromExtendConfig(
        CameraInfo& cameraInfo, HDI::Camera::V1_3::OperationMode modeName)
    {
        camera_metadata_item_t item;
        int ret = OHOS::Camera::CameraMetadata::FindCameraMetadataItem(
            cameraInfo.ability->get(), OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, &item);
        CHECK_RETURN_RET(ret != CAM_META_SUCCESS || item.count == 0, nullptr);
        ExtendInfo extendInfo = {};
        std::shared_ptr<CameraStreamInfoParse> modeStreamParse = std::make_shared<CameraStreamInfoParse>();
        modeStreamParse->getModeInfo(item.data.i32, item.count, extendInfo); // 解析tag中带的数据信息意义
        for (auto& modeInfo : extendInfo.modeInfo) {
            if (modeInfo.modeName != modeName) {
                continue;
            }
            for (auto& streamInfo : modeInfo.streamInfo) {
                if (streamInfo.streamType != HDI::Camera::V1_3::StreamType::STREAM_TYPE_STILL_CAPTURE) {
                    continue;
                }
                float ratioValue = GetRatioValue(followSensorMaxRatio);
                return GetMaxSizeDetailInfo(streamInfo.detailInfo, ratioValue, OHOS_CAMERA_FORMAT_JPEG);
            }
        }
        return nullptr;
    }

    std::string toString(std::vector<CameraInfo>& cameraInfos, HDI::Camera::V1_3::OperationMode modeName)
    {
        CHECK_RETURN_RET(!followSensorMax, toString());
        std::string maxSizeInfo = "";
        for (auto& cameraInfo : cameraInfos) {
            camera_metadata_item_t item;
            CHECK_RETURN_RET(cameraInfo.ability == nullptr, "cameraInfo.ability is null");
            int ret = OHOS::Camera::CameraMetadata::FindCameraMetadataItem(
                cameraInfo.ability->get(), OHOS_ABILITY_CAMERA_TYPE, &item);
            CHECK_RETURN_RET(ret != CAM_META_SUCCESS || item.count == 0, "device camera type info error");
            camera_type_enum_t cameraType = static_cast<camera_type_enum_t>(item.data.u8[0]);
            if (cameraType != OHOS_CAMERA_TYPE_UNSPECIFIED) {
                continue;
            }
            auto maxDetail = FindMaxDetailInfoFromProfileLevel(cameraInfo, modeName);
            if (maxDetail) {
                maxSizeInfo += std::to_string(maxDetail->width) + "x" + std::to_string(maxDetail->height) + "(" +
                    cameraInfo.cameraId + ") ";
                continue;
            }
            auto maxDetailInfo = FindMaxDetailInfoFromExtendConfig(cameraInfo, modeName);
            if (maxDetailInfo == nullptr) {
                continue;
            }
            maxSizeInfo += std::to_string(maxDetailInfo->width) + "x" + std::to_string(maxDetailInfo->height) + "(" +
                           cameraInfo.cameraId + ") ";
        }
        return "Format:" + format + "\tSize:" + maxSizeInfo + "\tFps:" + std::to_string(fpsMin) + "-" +
               std::to_string(fpsMax) + ",prefer:" + std::to_string(fpsPrefer);
    }
};

struct PhotoSessionPreconfig {
    std::string colorSpace;
    PreconfigProfile previewProfile;
    PreconfigProfile photoProfile;
};

struct VideoSessionPreconfig {
    std::string colorSpace;
    PreconfigProfile previewProfile;
    PreconfigProfile photoProfile;
    PreconfigProfile videoProfile;
};

PhotoSessionPreconfig GeneratePhotoSessionPreconfigRatio1v1(PreconfigType preconfigType)
{
    PhotoSessionPreconfig sessionPreconfig { .colorSpace = "P3" };
    switch (preconfigType) {
        case PRECONFIG_TYPE_720P:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 720, 720, 12, 30, 30 };
            sessionPreconfig.photoProfile = { "CAMERA_FORMAT_JPEG", 720, 720, 0, 0, 0 };
            break;
        case PRECONFIG_TYPE_1080P:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 1080, 1080, 12, 30, 30 };
            sessionPreconfig.photoProfile = { "CAMERA_FORMAT_JPEG", 1080, 1080, 0, 0, 0 };
            break;
        case PRECONFIG_TYPE_4K:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 1080, 1080, 12, 30, 30 };
            sessionPreconfig.photoProfile = { "CAMERA_FORMAT_JPEG", 2160, 2160, 0, 0, 0 };
            break;
        case PRECONFIG_TYPE_HIGH_QUALITY:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 1440, 1440, 12, 30, 30 };
            sessionPreconfig.photoProfile = { "CAMERA_FORMAT_JPEG", 0, 0, 0, 0, 0, true, RATIO_1_1 };
            break;
        default:
            return sessionPreconfig;
    }
    return sessionPreconfig;
};

PhotoSessionPreconfig GeneratePhotoSessionPreconfigRatio4v3(PreconfigType preconfigType)
{
    PhotoSessionPreconfig sessionPreconfig { .colorSpace = "P3" };
    switch (preconfigType) {
        case PRECONFIG_TYPE_720P:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 960, 720, 12, 30, 30 };
            sessionPreconfig.photoProfile = { "CAMERA_FORMAT_JPEG", 960, 720, 0, 0, 0 };
            break;
        case PRECONFIG_TYPE_1080P:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 1440, 1080, 12, 30, 30 };
            sessionPreconfig.photoProfile = { "CAMERA_FORMAT_JPEG", 1440, 1080, 0, 0, 0 };
            break;
        case PRECONFIG_TYPE_4K:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 1440, 1080, 12, 30, 30 };
            sessionPreconfig.photoProfile = { "CAMERA_FORMAT_JPEG", 2880, 2160, 0, 0, 0 };
            break;
        case PRECONFIG_TYPE_HIGH_QUALITY:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 1920, 1440, 12, 30, 30 };
            sessionPreconfig.photoProfile = { "CAMERA_FORMAT_JPEG", 0, 0, 0, 0, 0, true, RATIO_4_3 };
            break;
        default:
            return sessionPreconfig;
    }
    return sessionPreconfig;
};

PhotoSessionPreconfig GeneratePhotoSessionPreconfigRatio16v9(PreconfigType preconfigType)
{
    PhotoSessionPreconfig sessionPreconfig { .colorSpace = "P3" };
    switch (preconfigType) {
        case PRECONFIG_TYPE_720P:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 1280, 720, 12, 30, 30 };
            sessionPreconfig.photoProfile = { "CAMERA_FORMAT_JPEG", 1280, 720, 0, 0, 0 };
            break;
        case PRECONFIG_TYPE_1080P:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 1920, 1080, 12, 30, 30 };
            sessionPreconfig.photoProfile = { "CAMERA_FORMAT_JPEG", 1920, 1080, 0, 0, 0 };
            break;
        case PRECONFIG_TYPE_4K:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 1920, 1080, 12, 30, 30 };
            sessionPreconfig.photoProfile = { "CAMERA_FORMAT_JPEG", 3840, 2160, 0, 0, 0 };
            break;
        case PRECONFIG_TYPE_HIGH_QUALITY:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 2560, 1440, 12, 30, 30 };
            sessionPreconfig.photoProfile = { "CAMERA_FORMAT_JPEG", 0, 0, 0, 0, 0, true, RATIO_16_9 };
            break;
        default:
            return sessionPreconfig;
    }
    return sessionPreconfig;
};

VideoSessionPreconfig GenerateVideoSessionPreconfigRatio1v1(PreconfigType preconfigType)
{
    VideoSessionPreconfig sessionPreconfig { .colorSpace = "BT709" };
    sessionPreconfig.photoProfile = { "CAMERA_FORMAT_JPEG", 2304, 2304, 0, 0, 0 };
    switch (preconfigType) {
        case PRECONFIG_TYPE_720P:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 720, 720, 24, 30, 30 };
            sessionPreconfig.videoProfile = sessionPreconfig.previewProfile;
            break;
        case PRECONFIG_TYPE_1080P:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 1080, 1080, 24, 30, 30 };
            sessionPreconfig.videoProfile = sessionPreconfig.previewProfile;
            break;
        case PRECONFIG_TYPE_4K:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 1080, 1080, 24, 30, 30 };
            sessionPreconfig.videoProfile = { "CAMERA_FORMAT_YUV_420_SP", 2160, 2160, 24, 30, 30 };
            break;
        case PRECONFIG_TYPE_HIGH_QUALITY:
            sessionPreconfig.colorSpace = "BT2020_HLG_LIMIT";
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YCRCB_P010", 1080, 1080, 24, 30, 30 };
            sessionPreconfig.videoProfile = { "CAMERA_FORMAT_YCRCB_P010", 2160, 2160, 24, 30, 30 };
            break;
        default:
            return sessionPreconfig;
    }
    return sessionPreconfig;
};

VideoSessionPreconfig GenerateVideoSessionPreconfigRatio4v3(PreconfigType preconfigType)
{
    VideoSessionPreconfig sessionPreconfig { .colorSpace = "BT709" };
    sessionPreconfig.photoProfile = { "CAMERA_FORMAT_JPEG", 3072, 2304, 0, 0, 0 };
    switch (preconfigType) {
        case PRECONFIG_TYPE_720P:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 960, 720, 24, 30, 30 };
            sessionPreconfig.videoProfile = sessionPreconfig.previewProfile;
            break;
        case PRECONFIG_TYPE_1080P:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 1440, 1080, 24, 30, 30 };
            sessionPreconfig.videoProfile = sessionPreconfig.previewProfile;
            break;
        case PRECONFIG_TYPE_4K:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 1440, 1080, 24, 30, 30 };
            sessionPreconfig.videoProfile = { "CAMERA_FORMAT_YUV_420_SP", 2880, 2160, 24, 30, 30 };
            break;
        case PRECONFIG_TYPE_HIGH_QUALITY:
            sessionPreconfig.colorSpace = "BT2020_HLG_LIMIT";
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YCRCB_P010", 1440, 1080, 24, 30, 30 };
            sessionPreconfig.videoProfile = { "CAMERA_FORMAT_YCRCB_P010", 2880, 2160, 24, 30, 30 };
            break;
        default:
            return sessionPreconfig;
    }
    return sessionPreconfig;
};

VideoSessionPreconfig GenerateVideoSessionPreconfigRatio16v9(PreconfigType preconfigType)
{
    VideoSessionPreconfig sessionPreconfig { .colorSpace = "BT709" };
    sessionPreconfig.photoProfile = { "CAMERA_FORMAT_JPEG", 4096, 2304, 0, 0, 0 };
    switch (preconfigType) {
        case PRECONFIG_TYPE_720P:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 1280, 720, 24, 30, 30 };
            sessionPreconfig.videoProfile = sessionPreconfig.previewProfile;
            break;
        case PRECONFIG_TYPE_1080P:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 1920, 1080, 24, 30, 30 };
            sessionPreconfig.videoProfile = sessionPreconfig.previewProfile;
            break;
        case PRECONFIG_TYPE_4K:
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YUV_420_SP", 1920, 1080, 24, 30, 30 };
            sessionPreconfig.videoProfile = { "CAMERA_FORMAT_YUV_420_SP", 3840, 2160, 24, 30, 30 };
            break;
        case PRECONFIG_TYPE_HIGH_QUALITY:
            sessionPreconfig.colorSpace = "BT2020_HLG_LIMIT";
            sessionPreconfig.previewProfile = { "CAMERA_FORMAT_YCRCB_P010", 1920, 1080, 12, 30, 30 };
            sessionPreconfig.videoProfile = { "CAMERA_FORMAT_YCRCB_P010", 3840, 2160, 24, 30, 30 };
            sessionPreconfig.photoProfile.followSensorMax = true;
            sessionPreconfig.photoProfile.followSensorMaxRatio = RATIO_16_9;
            break;
        default:
            return sessionPreconfig;
    }
    return sessionPreconfig;
};
} // namespace

void DumpPreconfigInfo(CameraInfoDumper& infoDumper, sptr<HCameraHostManager>& hostManager)
{
    std::map<PreconfigType, std::string> preconfigTypeMap = { { PRECONFIG_TYPE_720P, "PRECONFIG_720P" },
        { PRECONFIG_TYPE_1080P, "PRECONFIG_1080P" }, { PRECONFIG_TYPE_4K, "PRECONFIG_4K" },
        { PRECONFIG_TYPE_HIGH_QUALITY, "PRECONFIG_HIGH_QUALITY" } };
    std::map<PreconfigRatio, std::string> preconfigRatioMap = { { RATIO_1_1, "ratio 1:1" }, { RATIO_4_3, "ratio 4:3" },
        { RATIO_16_9, "ratio 16:9" } };
    std::vector<std::string> cameraIds;
    std::vector<CameraInfo> cameraInfos;
    CHECK_RETURN_ELOG(hostManager == nullptr, "DumpPreconfigInfo hostManager is nullptr.");
    hostManager->GetCameras(cameraIds);
    for (auto& cameraId : cameraIds) {
        CameraInfo cameraInfo { .cameraId = cameraId };
        hostManager->GetCameraAbility(cameraId, cameraInfo.ability);
        cameraInfos.emplace_back(cameraInfo);
    }
    for (const auto& typePair : preconfigTypeMap) {
        for (const auto& ratioPair : preconfigRatioMap) {
            PhotoSessionPreconfig photoPreconfig;
            VideoSessionPreconfig videoPreconfig;
            switch (ratioPair.first) {
                case RATIO_1_1:
                    photoPreconfig = GeneratePhotoSessionPreconfigRatio1v1(typePair.first);
                    videoPreconfig = GenerateVideoSessionPreconfigRatio1v1(typePair.first);
                    break;
                case RATIO_4_3:
                    photoPreconfig = GeneratePhotoSessionPreconfigRatio4v3(typePair.first);
                    videoPreconfig = GenerateVideoSessionPreconfigRatio4v3(typePair.first);
                    break;
                case RATIO_16_9:
                    photoPreconfig = GeneratePhotoSessionPreconfigRatio16v9(typePair.first);
                    videoPreconfig = GenerateVideoSessionPreconfigRatio16v9(typePair.first);
                    break;
                default:
                    // Do nothing.
                    break;
            }
            infoDumper.Title(typePair.second + " " + ratioPair.second + " :");
            infoDumper.Push();
            infoDumper.Title("PhotoSession:");
            infoDumper.Msg("Colorspace:" + photoPreconfig.colorSpace);
            infoDumper.Msg("[Preview]\t" + photoPreconfig.previewProfile.toString());
            infoDumper.Msg("[Photo]\t" + photoPreconfig.photoProfile.toString(cameraInfos, HDI::Camera::V1_3::CAPTURE));
            infoDumper.Title("VideoSession:");
            infoDumper.Msg("Colorspace:" + videoPreconfig.colorSpace);
            infoDumper.Msg("[Preview]\t" + videoPreconfig.previewProfile.toString());
            infoDumper.Msg("[Video]\t" + videoPreconfig.videoProfile.toString());
            infoDumper.Msg("[Photo]\t" + videoPreconfig.photoProfile.toString(cameraInfos, HDI::Camera::V1_3::VIDEO));
            infoDumper.Pop();
        }
    }
}
} // namespace CameraStandard
} // namespace OHOS
