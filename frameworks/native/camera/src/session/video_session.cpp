/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "session/video_session.h"

#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_util.h"
#include "input/camera_input.h"
#include "input/camera_manager.h"
#include "output/camera_output_capability.h"

namespace OHOS {
namespace CameraStandard {
VideoSession::~VideoSession() {}
bool VideoSession::CanAddOutput(sptr<CaptureOutput>& output)
{
    MEDIA_DEBUG_LOG("Enter Into VideoSession::CanAddOutput");
    if (!IsSessionConfiged() || output == nullptr) {
        MEDIA_ERR_LOG("VideoSession::CanAddOutput operation is Not allowed!");
        return false;
    }
    return CaptureSession::CanAddOutput(output);
}

std::shared_ptr<PreconfigProfiles> VideoSession::GeneratePreconfigProfiles(PreconfigType preconfigType)
{
    std::shared_ptr<PreconfigProfiles> configs = std::make_shared<PreconfigProfiles>();
    switch (preconfigType) {
        case PRECONFIG_720P: {
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YCRCB_P010, { .width = 1280, .height = 720 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 1, .maxFps = 30 };

            configs->videoProfile = { CameraFormat::CAMERA_FORMAT_YCRCB_P010, configs->previewProfile.size_,
                { configs->previewProfile.fps_.minFps, configs->previewProfile.fps_.maxFps } };

            configs->photoProfile = configs->previewProfile;
            configs->photoProfile.format_ = CameraFormat::CAMERA_FORMAT_JPEG;
            break;
        }
        case PRECONFIG_1080P: {
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YCRCB_P010, { .width = 1920, .height = 1080 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 1, .maxFps = 30 };

            configs->videoProfile = { CameraFormat::CAMERA_FORMAT_YCRCB_P010, configs->previewProfile.size_,
                { configs->previewProfile.fps_.minFps, configs->previewProfile.fps_.maxFps } };

            configs->photoProfile = configs->previewProfile;
            configs->photoProfile.format_ = CameraFormat::CAMERA_FORMAT_JPEG;
            break;
        }
        case PRECONFIG_4K: {
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YCRCB_P010, { .width = 1920, .height = 1080 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 1, .maxFps = 30 };

            configs->videoProfile = { CameraFormat::CAMERA_FORMAT_YCRCB_P010, { .width = 3840, .height = 2160 },
                { configs->previewProfile.fps_.minFps, configs->previewProfile.fps_.maxFps } };

            configs->photoProfile = configs->previewProfile;
            configs->photoProfile.size_ = { .width = 3840, .height = 2160 };
            configs->photoProfile.format_ = CameraFormat::CAMERA_FORMAT_JPEG;
            break;
        }
        case PRECONFIG_HIGH_QUALITY: {
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YCRCB_P010, { .width = 1920, .height = 1440 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 1, .maxFps = 30 };

            configs->videoProfile = { CameraFormat::CAMERA_FORMAT_YCRCB_P010, { .width = 3840, .height = 2160 },
                { configs->previewProfile.fps_.minFps, configs->previewProfile.fps_.maxFps } };

            configs->photoProfile = configs->previewProfile;
            configs->photoProfile.size_ = { .width = 3840, .height = 2160 };
            configs->photoProfile.format_ = CameraFormat::CAMERA_FORMAT_JPEG;
            break;
        }
        default:
            MEDIA_ERR_LOG("PhotoSession::GeneratePreconfigProfiles not support this config:%{public}d", preconfigType);
            return nullptr;
    }
    return configs;
}

bool VideoSession::CanPreconfig(PreconfigType preconfigType)
{
    std::shared_ptr<PreconfigProfiles> configs = GeneratePreconfigProfiles(preconfigType);
    MEDIA_INFO_LOG("VideoSession::CanPreconfig check type:%{public}d", preconfigType);
    auto cameraList = CameraManager::GetInstance()->GetSupportedCameras();
    for (auto& device : cameraList) {
        MEDIA_INFO_LOG("VideoSession::CanPreconfig check camera:%{public}s", device->GetID().c_str());
        // Check photo
        auto photoProfilesIt = device->modePhotoProfiles_.find(SceneMode::VIDEO);
        if (photoProfilesIt == device->modePhotoProfiles_.end()) {
            MEDIA_ERR_LOG("VideoSession::CanPreconfig check photo profile fail, empty photo profiles");
            return false;
        }
        auto photoProfiles = photoProfilesIt->second;
        bool isPhotoCanPreconfig = std::any_of(photoProfiles.begin(), photoProfiles.end(),
            [&configs](auto& profile) { return profile == configs->photoProfile; });
        if (!isPhotoCanPreconfig) {
            MEDIA_ERR_LOG("VideoSession::CanPreconfig check photo profile fail, no matched photo profiles");
            return false;
        }
        // Check preview
        auto previewProfilesIt = device->modePreviewProfiles_.find(SceneMode::VIDEO);
        if (previewProfilesIt == device->modePreviewProfiles_.end()) {
            MEDIA_ERR_LOG("VideoSession::CanPreconfig check preview profile fail, empty preview profiles");
            return false;
        }
        auto previewProfiles = previewProfilesIt->second;
        bool isPreviewCanPreconfig = std::any_of(previewProfiles.begin(), previewProfiles.end(),
            [&configs](auto& profile) { return profile == configs->previewProfile; });
        if (!isPreviewCanPreconfig) {
            MEDIA_ERR_LOG("VideoSession::CanPreconfig check preview profile fail, no matched preview profiles");
            return false;
        }
        // Check video
        auto videoProfilesIt = device->modeVideoProfiles_.find(SceneMode::VIDEO);
        if (videoProfilesIt == device->modeVideoProfiles_.end()) {
            MEDIA_ERR_LOG("VideoSession::CanPreconfig check video profile fail, empty video profiles");
            return false;
        }
        auto videoProfiles = videoProfilesIt->second;
        bool isVideoCanPreconfig = std::any_of(videoProfiles.begin(), videoProfiles.end(),
            [&configs](auto& profile) { return profile == configs->videoProfile; });
        if (!isVideoCanPreconfig) {
            MEDIA_ERR_LOG("VideoSession::CanPreconfig check video profile fail, no matched video profiles");
            return false;
        }
    }
    MEDIA_INFO_LOG("VideoSession::CanPreconfig check pass");
    return true;
}

int32_t VideoSession::Preconfig(PreconfigType preconfigType)
{
    std::shared_ptr<PreconfigProfiles> configs = GeneratePreconfigProfiles(preconfigType);
    SetPreconfigProfiles(configs);
    if (configs == nullptr) {
        MEDIA_ERR_LOG("VideoSession::Preconfig not support this config:%{public}d", preconfigType);
        return OPERATION_NOT_ALLOWED;
    }
    MEDIA_INFO_LOG("VideoSession::Preconfig type:%{public}d success", preconfigType);
    return SUCCESS;
}

bool VideoSession::CanSetFrameRateRange(int32_t minFps, int32_t maxFps, CaptureOutput* curOutput)
{
    return CanSetFrameRateRangeForOutput(minFps, maxFps, curOutput) ? true : false;
}
} // namespace CameraStandard
} // namespace OHOS