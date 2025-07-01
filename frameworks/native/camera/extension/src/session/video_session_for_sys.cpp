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

#include "session/video_session_for_sys.h"

#include "camera_error_code.h"
#include "camera_log.h"
#include "input/camera_manager.h"
#include "output/camera_output_capability.h"

namespace OHOS {
namespace CameraStandard {
namespace {
constexpr int32_t FOCUS_TRACKING_REGION_DATA_CNT = 4;

std::shared_ptr<PreconfigProfiles> GeneratePreconfigProfiles1_1(PreconfigType preconfigType)
{
    std::shared_ptr<PreconfigProfiles> configs = std::make_shared<PreconfigProfiles>(ColorSpace::BT709);
    configs->photoProfile = { CameraFormat::CAMERA_FORMAT_JPEG, { .width = 0, .height = 0 } };
    configs->photoProfile.sizeRatio_ = RATIO_1_1;
    configs->photoProfile.sizeFollowSensorMax_ = true;
    switch (preconfigType) {
        case PRECONFIG_720P:
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 720, .height = 720 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 24, .maxFps = 30 };

            configs->videoProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, configs->previewProfile.size_,
                { configs->previewProfile.fps_.minFps, configs->previewProfile.fps_.maxFps } };
            break;
        case PRECONFIG_1080P:
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1080, .height = 1080 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 24, .maxFps = 30 };

            configs->videoProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, configs->previewProfile.size_,
                { configs->previewProfile.fps_.minFps, configs->previewProfile.fps_.maxFps } };
            break;
        case PRECONFIG_4K:
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1080, .height = 1080 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 24, .maxFps = 30 };

            configs->videoProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 2160, .height = 2160 },
                { configs->previewProfile.fps_.minFps, configs->previewProfile.fps_.maxFps } };
            break;
        case PRECONFIG_HIGH_QUALITY:
            configs->colorSpace = ColorSpace::BT2020_HLG_LIMIT;
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YCRCB_P010, { .width = 1080, .height = 1080 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 24, .maxFps = 30 };

            configs->videoProfile = { CameraFormat::CAMERA_FORMAT_YCRCB_P010, { .width = 2160, .height = 2160 },
                { configs->previewProfile.fps_.minFps, configs->previewProfile.fps_.maxFps } };
            break;
        default:
            MEDIA_ERR_LOG(
                "VideoSessionForSys::GeneratePreconfigProfiles1_1 not support this config:%{public}d", preconfigType);
            return nullptr;
    }
    return configs;
}

std::shared_ptr<PreconfigProfiles> GeneratePreconfigProfiles4_3(PreconfigType preconfigType)
{
    std::shared_ptr<PreconfigProfiles> configs = std::make_shared<PreconfigProfiles>(ColorSpace::BT709);
    configs->photoProfile = { CameraFormat::CAMERA_FORMAT_JPEG, { .width = 0, .height = 0 } };
    configs->photoProfile.sizeRatio_ = RATIO_4_3;
    configs->photoProfile.sizeFollowSensorMax_ = true;
    switch (preconfigType) {
        case PRECONFIG_720P:
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 960, .height = 720 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 24, .maxFps = 30 };

            configs->videoProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, configs->previewProfile.size_,
                { configs->previewProfile.fps_.minFps, configs->previewProfile.fps_.maxFps } };
            break;
        case PRECONFIG_1080P:
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1440, .height = 1080 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 24, .maxFps = 30 };

            configs->videoProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, configs->previewProfile.size_,
                { configs->previewProfile.fps_.minFps, configs->previewProfile.fps_.maxFps } };
            break;
        case PRECONFIG_4K:
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1440, .height = 1080 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 24, .maxFps = 30 };

            configs->videoProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 2880, .height = 2160 },
                { configs->previewProfile.fps_.minFps, configs->previewProfile.fps_.maxFps } };
            break;
        case PRECONFIG_HIGH_QUALITY:
            configs->colorSpace = ColorSpace::BT2020_HLG_LIMIT;
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YCRCB_P010, { .width = 1440, .height = 1080 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 24, .maxFps = 30 };

            configs->videoProfile = { CameraFormat::CAMERA_FORMAT_YCRCB_P010, { .width = 2880, .height = 2160 },
                { configs->previewProfile.fps_.minFps, configs->previewProfile.fps_.maxFps } };
            break;
        default:
            MEDIA_ERR_LOG(
                "VideoSessionForSys::GeneratePreconfigProfiles4_3 not support this config:%{public}d", preconfigType);
            return nullptr;
    }
    return configs;
}

std::shared_ptr<PreconfigProfiles> GeneratePreconfigProfiles16_9(PreconfigType preconfigType)
{
    std::shared_ptr<PreconfigProfiles> configs = std::make_shared<PreconfigProfiles>(ColorSpace::BT709);
    configs->photoProfile = { CameraFormat::CAMERA_FORMAT_JPEG, { .width = 0, .height = 0 } };
    configs->photoProfile.sizeRatio_ = RATIO_16_9;
    configs->photoProfile.sizeFollowSensorMax_ = true;
    switch (preconfigType) {
        case PRECONFIG_720P:
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1280, .height = 720 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 24, .maxFps = 30 };

            configs->videoProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, configs->previewProfile.size_,
                { configs->previewProfile.fps_.minFps, configs->previewProfile.fps_.maxFps } };
            break;
        case PRECONFIG_1080P:
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1920, .height = 1080 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 24, .maxFps = 30 };

            configs->videoProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, configs->previewProfile.size_,
                { configs->previewProfile.fps_.minFps, configs->previewProfile.fps_.maxFps } };
            break;
        case PRECONFIG_4K:
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1920, .height = 1080 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 24, .maxFps = 30 };

            configs->videoProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 3840, .height = 2160 },
                { configs->previewProfile.fps_.minFps, configs->previewProfile.fps_.maxFps } };
            break;
        case PRECONFIG_HIGH_QUALITY:
            configs->colorSpace = ColorSpace::BT2020_HLG_LIMIT;
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YCRCB_P010, { .width = 1920, .height = 1080 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 24, .maxFps = 30 };

            configs->videoProfile = { CameraFormat::CAMERA_FORMAT_YCRCB_P010, { .width = 3840, .height = 2160 },
                { configs->previewProfile.fps_.minFps, configs->previewProfile.fps_.maxFps } };
            break;
        default:
            MEDIA_ERR_LOG(
                "VideoSessionForSys::GeneratePreconfigProfiles16_9 not support this config:%{public}d", preconfigType);
            return nullptr;
    }
    return configs;
}
} // namespace

const std::unordered_map<camera_focus_tracking_mode_t, FocusTrackingMode>
    VideoSessionForSys::metaToFwFocusTrackingMode_ = {
    { OHOS_CAMERA_FOCUS_TRACKING_AUTO, FocusTrackingMode::FOCUS_TRACKING_MODE_AUTO }
};

FocusTrackingInfo::FocusTrackingInfo(const FocusTrackingMode mode, const Rect rect) : mode_(mode), region_(rect)
{}

FocusTrackingInfo::FocusTrackingInfo(const FocusTrackingInfoParms& parms)
{
    mode_ = parms.trackingMode;
    region_ = parms.trackingRegion;
}

VideoSessionForSys::~VideoSessionForSys()
{
    focusTrackingInfoCallback_ = nullptr;
    lightStatusCallback_ = nullptr;
}

bool VideoSessionForSys::CanAddOutput(sptr<CaptureOutput>& output)
{
    MEDIA_DEBUG_LOG("Enter Into VideoSessionForSys::CanAddOutput");
    CHECK_ERROR_RETURN_RET_LOG(
        !IsSessionConfiged() || output == nullptr, false, "VideoSessionForSys::CanAddOutput operation is Not allowed!");
    return CaptureSession::CanAddOutput(output);
}

std::shared_ptr<PreconfigProfiles> VideoSessionForSys::GeneratePreconfigProfiles(
    PreconfigType preconfigType, ProfileSizeRatio preconfigRatio)
{
    switch (preconfigRatio) {
        case RATIO_1_1:
            return GeneratePreconfigProfiles1_1(preconfigType);
        case RATIO_4_3:
            return GeneratePreconfigProfiles4_3(preconfigType);
        case UNSPECIFIED:
        // Fall through
        case RATIO_16_9:
            return GeneratePreconfigProfiles16_9(preconfigType);
        default:
            MEDIA_ERR_LOG("VideoSessionForSys::GeneratePreconfigProfiles unknow profile size ratio.");
            break;
    }
    return nullptr;
}

bool VideoSessionForSys::IsPreconfigProfilesLegal(std::shared_ptr<PreconfigProfiles> configs)
{
    auto cameraList = CameraManager::GetInstance()->GetSupportedCameras();
    int32_t supportedCameraNum = 0;
    for (auto& device : cameraList) {
        MEDIA_INFO_LOG("VideoSessionForSys::IsPreconfigProfilesLegal check camera:%{public}s type:%{public}d",
            device->GetID().c_str(), device->GetCameraType());
        if (device->GetCameraType() != CAMERA_TYPE_DEFAULT) {
            continue;
        }
        // Check photo
        bool isPhotoCanPreconfig = IsPhotoProfileLegal(device, configs->photoProfile);
        CHECK_ERROR_RETURN_RET_LOG(!isPhotoCanPreconfig, false,
            "VideoSessionForSys::IsPreconfigProfilesLegal check photo profile fail, "
            "no matched photo profiles:%{public}d %{public}dx%{public}d",
            configs->photoProfile.format_, configs->photoProfile.size_.width, configs->photoProfile.size_.height);

        // Check preview
        bool isPreviewCanPreconfig = IsPreviewProfileLegal(device, configs->previewProfile);
        CHECK_ERROR_RETURN_RET_LOG(!isPreviewCanPreconfig, false,
            "VideoSessionForSys::IsPreconfigProfilesLegal check preview profile fail, "
            "no matched preview profiles:%{public}d %{public}dx%{public}d",
            configs->previewProfile.format_, configs->previewProfile.size_.width, configs->previewProfile.size_.height);

        // Check video
        auto isVideoCanPreconfig = IsVideoProfileLegal(device, configs->videoProfile);
        CHECK_ERROR_RETURN_RET_LOG(!isVideoCanPreconfig, false,
            "VideoSessionForSys::IsPreconfigProfilesLegal check video profile fail, "
            "no matched video profiles:%{public}d %{public}dx%{public}d",
            configs->videoProfile.format_, configs->videoProfile.size_.width, configs->videoProfile.size_.height);
        supportedCameraNum++;
    }
    MEDIA_INFO_LOG(
        "VideoSessionForSys::IsPreconfigProfilesLegal check pass, supportedCameraNum is%{public}d", supportedCameraNum);
    return supportedCameraNum > 0;
}

bool VideoSessionForSys::IsPhotoProfileLegal(sptr<CameraDevice>& device, Profile& photoProfile)
{
    auto photoProfilesIt = device->modePhotoProfiles_.find(SceneMode::VIDEO);
    CHECK_ERROR_RETURN_RET_LOG(photoProfilesIt == device->modePhotoProfiles_.end(), false,
        "VideoSessionForSys::CanPreconfig check photo profile fail, empty photo profiles");
    auto photoProfiles = photoProfilesIt->second;
    return std::any_of(photoProfiles.begin(), photoProfiles.end(), [&photoProfile](auto& profile) {
        CHECK_ERROR_RETURN_RET(!photoProfile.sizeFollowSensorMax_, profile == photoProfile);
        return IsProfileSameRatio(profile, photoProfile.sizeRatio_, RATIO_VALUE_16_9);
    });
}

bool VideoSessionForSys::IsPreviewProfileLegal(sptr<CameraDevice>& device, Profile& previewProfile)
{
    auto previewProfilesIt = device->modePreviewProfiles_.find(SceneMode::VIDEO);
    CHECK_ERROR_RETURN_RET_LOG(previewProfilesIt == device->modePreviewProfiles_.end(), false,
        "VideoSessionForSys::CanPreconfig check preview profile fail, empty preview profiles");
    auto previewProfiles = previewProfilesIt->second;
    return std::any_of(previewProfiles.begin(), previewProfiles.end(),
        [&previewProfile](auto& profile) { return profile == previewProfile; });
}

bool VideoSessionForSys::IsVideoProfileLegal(sptr<CameraDevice>& device, VideoProfile& videoProfile)
{
    auto videoProfilesIt = device->modeVideoProfiles_.find(SceneMode::VIDEO);
    CHECK_ERROR_RETURN_RET_LOG(videoProfilesIt == device->modeVideoProfiles_.end(), false,
        "VideoSessionForSys::CanPreconfig check video profile fail, empty video profiles");
    auto videoProfiles = videoProfilesIt->second;
    return std::any_of(videoProfiles.begin(), videoProfiles.end(),
        [&videoProfile](auto& profile) { return profile.IsContains(videoProfile); });
}

bool VideoSessionForSys::CanPreconfig(PreconfigType preconfigType, ProfileSizeRatio preconfigRatio)
{
    MEDIA_INFO_LOG("VideoSessionForSys::CanPreconfig check type:%{public}d, check ratio:%{public}d",
        preconfigType, preconfigRatio);
    std::shared_ptr<PreconfigProfiles> configs = GeneratePreconfigProfiles(preconfigType, preconfigRatio);
    CHECK_ERROR_RETURN_RET_LOG(configs == nullptr, false, "VideoSessionForSys::CanPreconfig get configs fail.");
    return IsPreconfigProfilesLegal(configs);
}

int32_t VideoSessionForSys::Preconfig(PreconfigType preconfigType, ProfileSizeRatio preconfigRatio)
{
    MEDIA_INFO_LOG("VideoSessionForSys::Preconfig type:%{public}d ratio:%{public}d", preconfigType, preconfigRatio);
    std::shared_ptr<PreconfigProfiles> configs = GeneratePreconfigProfiles(preconfigType, preconfigRatio);
    CHECK_ERROR_RETURN_RET_LOG(configs == nullptr, SERVICE_FATL_ERROR,
        "VideoSessionForSys::Preconfig not support this type:%{public}d ratio:%{public}d",
        preconfigType, preconfigRatio);
    CHECK_ERROR_RETURN_RET_LOG(!IsPreconfigProfilesLegal(configs), SERVICE_FATL_ERROR,
        "VideoSessionForSys::Preconfig preconfigProfile is illegal.");
    SetPreconfigProfiles(configs);
    MEDIA_INFO_LOG("VideoSessionForSys::Preconfig %s", configs->ToString().c_str());
    return SUCCESS;
}

bool VideoSessionForSys::CanSetFrameRateRange(int32_t minFps, int32_t maxFps, CaptureOutput* curOutput)
{
    return CanSetFrameRateRangeForOutput(minFps, maxFps, curOutput) ? true : false;
}

void VideoSessionForSys::SetFocusTrackingInfoCallback(std::shared_ptr<FocusTrackingCallback> focusTrackingInfoCallback)
{
    std::lock_guard<std::mutex> lock(videoSessionCallbackMutex_);
    focusTrackingInfoCallback_ = focusTrackingInfoCallback;
}

std::shared_ptr<FocusTrackingCallback> VideoSessionForSys::GetFocusTrackingCallback()
{
    std::lock_guard<std::mutex> lock(videoSessionCallbackMutex_);
    return focusTrackingInfoCallback_;
}

void VideoSessionForSys::ProcessFocusTrackingInfo(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    FocusTrackingMode mode = FOCUS_TRACKING_MODE_AUTO;
    Rect region = {0.0, 0.0, 0.0, 0.0};

    auto focusTrackingCallback = GetFocusTrackingCallback();
    if (focusTrackingCallback == nullptr) {
        MEDIA_DEBUG_LOG("%{public}s focusTrackingCallback is null", __FUNCTION__);
        return;
    }

    bool ret = ProcessFocusTrackingModeInfo(result, mode);
    if (!ret) {
        MEDIA_DEBUG_LOG("ProcessFocusTrackingModeInfo failed");
        return;
    }
    ret = ProcessRectInfo(result, region);
    if (!ret) {
        MEDIA_DEBUG_LOG("ProcessRectInfo failed");
        return;
    }
    FocusTrackingInfo focusTrackingInfo(mode, region);
    focusTrackingCallback->OnFocusTrackingInfoAvailable(focusTrackingInfo);
}

bool VideoSessionForSys::ProcessFocusTrackingModeInfo(const std::shared_ptr<OHOS::Camera::CameraMetadata>& metadata,
    FocusTrackingMode& mode)
{
    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, false, "metadata is nullptr");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_FOCUS_TRACKING_MODE, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_DEBUG_LOG("%{public}s FindCameraMetadataItem failed", __FUNCTION__);
        return false;
    }
    auto itr = metaToFwFocusTrackingMode_.find(static_cast<camera_focus_tracking_mode_t>(item.data.u8[0]));
    CHECK_ERROR_RETURN_RET_LOG(itr == metaToFwFocusTrackingMode_.end(), false,
        "%{public}s trackingMode data error", __FUNCTION__);
    mode = itr->second;
    return true;
}

bool VideoSessionForSys::ProcessRectInfo(const std::shared_ptr<OHOS::Camera::CameraMetadata>& metadata,
    Rect& rect)
{
    constexpr int32_t scale = 1000000;
    constexpr int32_t offsetOne = 1;
    constexpr int32_t offsetTwo = 2;
    constexpr int32_t offsetThree = 3;

    CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, false, "metadata is nullptr");
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FOCUS_TRACKING_REGION, &item);
    if (ret != CAM_META_SUCCESS || item.count < FOCUS_TRACKING_REGION_DATA_CNT) {
        MEDIA_DEBUG_LOG("%{public}s FindCameraMetadataItem failed", __FUNCTION__);
        return false;
    }
    int32_t offsetTopLeftX = item.data.i32[0];
    int32_t offsetTopLeftY = item.data.i32[offsetOne];
    int32_t offsetBottomRightX = item.data.i32[offsetTwo];
    int32_t offsetBottomRightY = item.data.i32[offsetThree];

    double topLeftX = scale - offsetBottomRightY;
    double topLeftY = offsetTopLeftX;
    double width = offsetBottomRightY - offsetTopLeftY;
    double height = offsetBottomRightX - offsetTopLeftX;

    topLeftX = topLeftX < 0 ? 0 : topLeftX;
    topLeftX = topLeftX > scale ? scale : topLeftX;
    topLeftY = topLeftY < 0 ? 0 : topLeftY;
    topLeftY = topLeftY > scale ? scale : topLeftY;

    rect = { topLeftX / scale, topLeftY / scale, width / scale, height / scale};
    return true;
}

void VideoSessionForSys::SetLightStatusCallback(std::shared_ptr<LightStatusCallback> callback)
{
    std::lock_guard<std::mutex> lock(videoSessionCallbackMutex_);
    lightStatusCallback_ = callback;
}

std::shared_ptr<LightStatusCallback> VideoSessionForSys::GetLightStatusCallback()
{
    std::lock_guard<std::mutex> lock(videoSessionCallbackMutex_);
    return lightStatusCallback_;
}

void VideoSessionForSys::ProcessLightStatusChange(const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    MEDIA_DEBUG_LOG("VideoSessionForSys::ProcessLightStatusChange is called");
    auto lightStatusCallback = GetLightStatusCallback();
    if (lightStatusCallback == nullptr) {
        MEDIA_DEBUG_LOG("%{public}s lightStatusCallback is null", __FUNCTION__);
        return;
    }
    camera_metadata_item_t item;
    common_metadata_header_t *metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_LIGHT_STATUS, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_DEBUG_LOG("can't get OHOS_STATUS_LIGHT_STATUS value");
        return;
    } else {
        uint8_t value = item.data.u8[0];
        MEDIA_DEBUG_LOG("the isInsufficientLightDetected is %{public}d", value);
        MEDIA_DEBUG_LOG("the lightStatus_ is %{public}d", lightStatus_);
        if (value != lightStatus_) {
            SetLightStatus(value);
            LightStatus light;
            light.status = value;
            MEDIA_DEBUG_LOG("the current light status is %{public}d", light.status);
            lightStatusCallback->OnLightStatusChanged(light);
        }
    }
    MEDIA_DEBUG_LOG("VideoSessionForSys::ProcessLightStatusChange is end");
}

void VideoSessionForSys::VideoSessionMetadataResultProcessor::ProcessCallbacks(const uint64_t timestamp,
    const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    MEDIA_DEBUG_LOG("%{public}s is called", __FUNCTION__);
    auto session = session_.promote();
    CHECK_ERROR_RETURN_LOG(session == nullptr, "%{public}s session is null", __FUNCTION__);

    (void)timestamp;
    session->ProcessAutoFocusUpdates(result);
    session->ProcessMacroStatusChange(result);
    session->ProcessLcdFlashStatusUpdates(result);
    session->ProcessFocusTrackingInfo(result);
    session->ProcessLightStatusChange(result);
    session->ProcessEffectSuggestionTypeUpdates(result);
}
} // namespace CameraStandard
} // namespace OHOS