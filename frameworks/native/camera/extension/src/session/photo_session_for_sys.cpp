/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "session/photo_session_for_sys.h"

#include <algorithm>
#include <cstdint>
#include <memory>

#include "camera_device.h"
#include "camera_error_code.h"
#include "camera_log.h"
#include "capture_scene_const.h"
#include "capture_session.h"
#include "input/camera_manager.h"
#include "output/camera_output_capability.h"

namespace OHOS {
namespace CameraStandard {
namespace {
std::shared_ptr<PreconfigProfiles> GeneratePreconfigProfiles1_1(PreconfigType preconfigType)
{
    std::shared_ptr<PreconfigProfiles> configs = std::make_shared<PreconfigProfiles>(ColorSpace::DISPLAY_P3);
    switch (preconfigType) {
        case PRECONFIG_720P:
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 720, .height = 720 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 12, .maxFps = 30 };

            configs->photoProfile = configs->previewProfile;
            configs->photoProfile.format_ = CameraFormat::CAMERA_FORMAT_JPEG;
            break;
        case PRECONFIG_1080P:
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1080, .height = 1080 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 12, .maxFps = 30 };

            configs->photoProfile = configs->previewProfile;
            configs->photoProfile.format_ = CameraFormat::CAMERA_FORMAT_JPEG;
            break;
        case PRECONFIG_4K:
        // LCOV_EXCL_START
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1080, .height = 1080 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 12, .maxFps = 30 };

            configs->photoProfile = configs->previewProfile;
            configs->photoProfile.size_ = { .width = 2160, .height = 2160 };
            configs->photoProfile.format_ = CameraFormat::CAMERA_FORMAT_JPEG;
            break;
        case PRECONFIG_HIGH_QUALITY:
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1440, .height = 1440 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 12, .maxFps = 30 };

            configs->photoProfile = { CameraFormat::CAMERA_FORMAT_JPEG, { .width = 0, .height = 0 } };
            configs->photoProfile.sizeRatio_ = RATIO_1_1;
            configs->photoProfile.sizeFollowSensorMax_ = true;
            break;
        case PRECONFIG_HIGH_QUALITY_PHOTOSESSION_BT2020:
            configs->colorSpace = ColorSpace::BT2020_HLG;
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YCRCB_P010, { .width = 1440, .height = 1440 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 12, .maxFps = 30 };

            configs->photoProfile = { CameraFormat::CAMERA_FORMAT_JPEG, { .width = 0, .height = 0 } };
            configs->photoProfile.sizeRatio_ = RATIO_1_1;
            configs->photoProfile.sizeFollowSensorMax_ = true;
            break;
        default:
            MEDIA_ERR_LOG(
                "PhotoSessionForSys::GeneratePreconfigProfiles1_1 not support this config:%{public}d", preconfigType);
            return nullptr;
        // LCOV_EXCL_STOP
    }
    return configs;
}

std::shared_ptr<PreconfigProfiles> GeneratePreconfigProfiles4_3(PreconfigType preconfigType)
{
    std::shared_ptr<PreconfigProfiles> configs = std::make_shared<PreconfigProfiles>(ColorSpace::DISPLAY_P3);
    switch (preconfigType) {
        case PRECONFIG_720P:
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 960, .height = 720 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 12, .maxFps = 30 };

            configs->photoProfile = configs->previewProfile;
            configs->photoProfile.format_ = CameraFormat::CAMERA_FORMAT_JPEG;
            break;
        case PRECONFIG_1080P:
        // LCOV_EXCL_START
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1440, .height = 1080 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 12, .maxFps = 30 };

            configs->photoProfile = configs->previewProfile;
            configs->photoProfile.format_ = CameraFormat::CAMERA_FORMAT_JPEG;
            break;
        case PRECONFIG_4K:
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1440, .height = 1080 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 12, .maxFps = 30 };

            configs->photoProfile = configs->previewProfile;
            configs->photoProfile.size_ = { .width = 2880, .height = 2160 };
            configs->photoProfile.format_ = CameraFormat::CAMERA_FORMAT_JPEG;
            break;
        case PRECONFIG_HIGH_QUALITY:
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1920, .height = 1440 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 12, .maxFps = 30 };

            configs->photoProfile = { CameraFormat::CAMERA_FORMAT_JPEG, { .width = 0, .height = 0 } };
            configs->photoProfile.sizeRatio_ = RATIO_4_3;
            configs->photoProfile.sizeFollowSensorMax_ = true;
            break;
        case PRECONFIG_HIGH_QUALITY_PHOTOSESSION_BT2020:
            configs->colorSpace = ColorSpace::BT2020_HLG;
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YCRCB_P010, { .width = 1920, .height = 1440 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 12, .maxFps = 30 };

            configs->photoProfile = { CameraFormat::CAMERA_FORMAT_JPEG, { .width = 0, .height = 0 } };
            configs->photoProfile.sizeRatio_ = RATIO_4_3;
            configs->photoProfile.sizeFollowSensorMax_ = true;
            break;
        default:
            MEDIA_ERR_LOG(
                "PhotoSessionForSys::GeneratePreconfigProfiles4_3 not support this config:%{public}d", preconfigType);
            return nullptr;
        // LCOV_EXCL_STOP
    }
    return configs;
}

std::shared_ptr<PreconfigProfiles> GeneratePreconfigProfiles16_9(PreconfigType preconfigType)
{
    // LCOV_EXCL_START
    std::shared_ptr<PreconfigProfiles> configs = std::make_shared<PreconfigProfiles>(ColorSpace::DISPLAY_P3);
    switch (preconfigType) {
        case PRECONFIG_720P:
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1280, .height = 720 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 12, .maxFps = 30 };

            configs->photoProfile = configs->previewProfile;
            configs->photoProfile.format_ = CameraFormat::CAMERA_FORMAT_JPEG;
            break;
        case PRECONFIG_1080P:
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1920, .height = 1080 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 12, .maxFps = 30 };

            configs->photoProfile = configs->previewProfile;
            configs->photoProfile.format_ = CameraFormat::CAMERA_FORMAT_JPEG;
            break;
        case PRECONFIG_4K:
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1920, .height = 1080 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 12, .maxFps = 30 };

            configs->photoProfile = configs->previewProfile;
            configs->photoProfile.size_ = { .width = 3840, .height = 2160 };
            configs->photoProfile.format_ = CameraFormat::CAMERA_FORMAT_JPEG;
            break;
        case PRECONFIG_HIGH_QUALITY:
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 2560, .height = 1440 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 12, .maxFps = 30 };

            configs->photoProfile = { CameraFormat::CAMERA_FORMAT_JPEG, { .width = 0, .height = 0 } };
            configs->photoProfile.sizeRatio_ = RATIO_16_9;
            configs->photoProfile.sizeFollowSensorMax_ = true;
            break;
        case PRECONFIG_HIGH_QUALITY_PHOTOSESSION_BT2020:
            configs->colorSpace = ColorSpace::BT2020_HLG;
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YCRCB_P010, { .width = 2560, .height = 1440 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 12, .maxFps = 30 };

            configs->photoProfile = { CameraFormat::CAMERA_FORMAT_JPEG, { .width = 0, .height = 0 } };
            configs->photoProfile.sizeRatio_ = RATIO_16_9;
            configs->photoProfile.sizeFollowSensorMax_ = true;
            break;
        default:
            MEDIA_ERR_LOG(
                "PhotoSessionForSys::GeneratePreconfigProfiles16_9 not support this config:%{public}d", preconfigType);
            return nullptr;
    }
    return configs;
    // LCOV_EXCL_STOP
}
} // namespace

bool PhotoSessionForSys::CanAddOutput(sptr<CaptureOutput>& output)
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("Enter Into PhotoSessionForSys::CanAddOutput");
    CHECK_RETURN_RET(output == nullptr, false);
    return output->GetOutputType() != CAPTURE_OUTPUT_TYPE_VIDEO && CaptureSession::CanAddOutput(output);
    // LCOV_EXCL_STOP
}

std::shared_ptr<PreconfigProfiles> PhotoSessionForSys::GeneratePreconfigProfiles(
    PreconfigType preconfigType, ProfileSizeRatio preconfigRatio)
{
    // LCOV_EXCL_START
    switch (preconfigRatio) {
        case RATIO_1_1:
            return GeneratePreconfigProfiles1_1(preconfigType);
        case UNSPECIFIED:
        // Fall through
        case RATIO_4_3:
            return GeneratePreconfigProfiles4_3(preconfigType);
        case RATIO_16_9:
            return GeneratePreconfigProfiles16_9(preconfigType);
        default:
            MEDIA_ERR_LOG("PhotoSessionForSys::GeneratePreconfigProfiles unknow profile size ratio.");
            break;
    }
    return nullptr;
    // LCOV_EXCL_STOP
}

bool PhotoSessionForSys::IsPreconfigProfilesLegal(std::shared_ptr<PreconfigProfiles> configs)
{
    auto cameraList = CameraManager::GetInstance()->GetSupportedCameras();
    int32_t supportedCameraNum = 0;
    for (auto& device : cameraList) {
        MEDIA_INFO_LOG("PhotoSessionForSys::IsPreconfigProfilesLegal check camera:%{public}s type:%{public}d",
            device->GetID().c_str(), device->GetCameraType());
        if (device->GetCameraType() != CAMERA_TYPE_DEFAULT) {
            continue;
        }
        // Check photo
        bool isPhotoCanPreconfig = IsPhotoProfileLegal(device, configs->photoProfile);
        CHECK_RETURN_RET_ELOG(!isPhotoCanPreconfig, false,
            "PhotoSessionForSys::IsPreconfigProfilesLegal check photo profile fail,"
            "no matched photo profiles:%{public}d "
            "%{public}dx%{public}d",
            configs->photoProfile.format_, configs->photoProfile.size_.width, configs->photoProfile.size_.height);

        // Check preview
        bool isPreviewCanPreconfig = IsPreviewProfileLegal(device, configs->previewProfile);
        CHECK_RETURN_RET_ELOG(!isPreviewCanPreconfig, false,
            "PhotoSessionForSys::IsPreconfigProfilesLegal check preview profile fail,"
            "no matched preview profiles:%{public}d "
            "%{public}dx%{public}d",
            configs->previewProfile.format_, configs->previewProfile.size_.width, configs->previewProfile.size_.height);
        supportedCameraNum++;
    }
    MEDIA_INFO_LOG(
        "PhotoSessionForSys::IsPreconfigProfilesLegal check pass, supportedCameraNum is%{public}d", supportedCameraNum);
    return supportedCameraNum > 0;
}

bool PhotoSessionForSys::IsPhotoProfileLegal(sptr<CameraDevice>& device, Profile& photoProfile)
{
    auto photoProfilesIt = device->modePhotoProfiles_.find(SceneMode::CAPTURE);
    CHECK_RETURN_RET_ELOG(photoProfilesIt == device->modePhotoProfiles_.end(), false,
        "PhotoSessionForSys::CanPreconfig check photo profile fail, empty photo profiles");
    auto photoProfiles = photoProfilesIt->second;
    return std::any_of(photoProfiles.begin(), photoProfiles.end(), [&photoProfile](auto& profile) {
        CHECK_RETURN_RET(!photoProfile.sizeFollowSensorMax_, profile == photoProfile);
        return IsProfileSameRatio(profile, photoProfile.sizeRatio_, RATIO_VALUE_4_3);
    });
}

bool PhotoSessionForSys::IsPreviewProfileLegal(sptr<CameraDevice>& device, Profile& previewProfile)
{
    auto previewProfilesIt = device->modePreviewProfiles_.find(SceneMode::CAPTURE);
    CHECK_RETURN_RET_ELOG(previewProfilesIt == device->modePreviewProfiles_.end(), false,
        "PhotoSessionForSys::CanPreconfig check preview profile fail, empty preview profiles");
    auto previewProfiles = previewProfilesIt->second;
    return std::any_of(previewProfiles.begin(), previewProfiles.end(),
        [&previewProfile](auto& profile) { return profile == previewProfile; });
}

bool PhotoSessionForSys::CanPreconfig(PreconfigType preconfigType, ProfileSizeRatio preconfigRatio)
{
    MEDIA_INFO_LOG(
        "PhotoSessionForSys::CanPreconfig check type:%{public}d, check ratio:%{public}d",
        preconfigType, preconfigRatio);
    std::shared_ptr<PreconfigProfiles> configs = GeneratePreconfigProfiles(preconfigType, preconfigRatio);
    CHECK_RETURN_RET_ELOG(configs == nullptr, false, "PhotoSessionForSys::CanPreconfig get configs fail.");
    return IsPreconfigProfilesLegal(configs);
}

int32_t PhotoSessionForSys::Preconfig(PreconfigType preconfigType, ProfileSizeRatio preconfigRatio)
{
    MEDIA_INFO_LOG("PhotoSessionForSys::Preconfig type:%{public}d ratio:%{public}d", preconfigType, preconfigRatio);
    std::shared_ptr<PreconfigProfiles> configs = GeneratePreconfigProfiles(preconfigType, preconfigRatio);
    CHECK_RETURN_RET_ELOG(configs == nullptr, SERVICE_FATL_ERROR,
        "PhotoSessionForSys::Preconfig not support this type:%{public}d ratio:%{public}d", preconfigType,
        preconfigRatio);
    CHECK_RETURN_RET_ELOG(!IsPreconfigProfilesLegal(configs), SERVICE_FATL_ERROR,
        "PhotoSessionForSys::Preconfig preconfigProfile is illegal.");
    SetPreconfigProfiles(configs);
    MEDIA_INFO_LOG("PhotoSessionForSys::Preconfig profile info\n%{public}s", configs->ToString().c_str());
    return SUCCESS;
}

bool PhotoSessionForSys::CanSetFrameRateRange(int32_t minFps, int32_t maxFps, CaptureOutput* curOutput)
{
    return CanSetFrameRateRangeForOutput(minFps, maxFps, curOutput) ? true : false;
}

bool PhotoSessionForSys::IsExternalCameraLensBoostSupported()
{
    MEDIA_INFO_LOG("PhotoSessionForSys::IsExternalCameraLensBoostSupported E");
    bool isSupported = false;
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice, isSupported,
        "PhotoSessionForSys::IsExternalCameraLensBoostSupported Failed inputDevice is nullptr");
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, isSupported,
        "PhotoSessionForSys::IsExternalCameraLensBoostSupported error!, cameraObj is nullptr");
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, isSupported,
        "PhotoSessionForSys::IsExternalCameraLensBoostSupported error!, metadata is nullptr");
    camera_metadata_item_t item;
    int result = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_EXTERNAL_CAMERA_LENS_BOOST, &item);
    CHECK_RETURN_RET_ELOG(result != CAM_META_SUCCESS || item.count <= 0, isSupported,
        "PhotoSessionForSys::IsExternalCameraLensBoostSupported error!, FindCameraMetadataItem error");
    isSupported = static_cast<bool>(item.data.u8[0]);
    return isSupported;
}

int32_t PhotoSessionForSys::EnableExternalCameraLensBoost(bool enabled)
{
    MEDIA_INFO_LOG("PhotoSessionForSys::EnableExternalCameraLensBoost E");
    bool isSupported = IsExternalCameraLensBoostSupported();
    CHECK_RETURN_RET_ELOG(!isSupported, OPERATION_NOT_ALLOWED,
        "PhotoSessionForSys::EnableExternalCameraLensBoost error!is not supported");
    LockForControl();
    int32_t status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_EXTERNAL_CAMERA_LENS_BOOST, &enabled, 1);
    UnlockForControl();
    return status;
}
} // namespace CameraStandard
} // namespace OHOS