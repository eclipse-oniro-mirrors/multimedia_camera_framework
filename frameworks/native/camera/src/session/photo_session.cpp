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

#include "session/photo_session.h"
#include <algorithm>
#include <memory>

#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_util.h"
#include "capture_scene_const.h"
#include "capture_session.h"
#include "input/camera_input.h"
#include "input/camera_manager.h"
#include "output/camera_output_capability.h"

namespace OHOS {
namespace CameraStandard {
PhotoSession::~PhotoSession() {}

bool PhotoSession::CanAddOutput(sptr<CaptureOutput>& output)
{
    MEDIA_DEBUG_LOG("Enter Into PhotoSession::CanAddOutput");
    if (output == nullptr) {
        return false;
    }
    return output->GetOutputType() != CAPTURE_OUTPUT_TYPE_VIDEO && CaptureSession::CanAddOutput(output);
}

std::shared_ptr<PreconfigProfiles> PhotoSession::GeneratePreconfigProfiles(PreconfigType preconfigType)
{
    std::shared_ptr<PreconfigProfiles> configs = std::make_shared<PreconfigProfiles>();
    switch (preconfigType) {
        case PRECONFIG_720P: {
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1280, .height = 720 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 1, .maxFps = 30 };
            configs->photoProfile = configs->previewProfile;
            configs->photoProfile.format_ = CameraFormat::CAMERA_FORMAT_JPEG;
            break;
        }
        case PRECONFIG_1080P: {
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1920, .height = 1080 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 1, .maxFps = 30 };
            configs->photoProfile = configs->previewProfile;
            configs->photoProfile.format_ = CameraFormat::CAMERA_FORMAT_JPEG;
            break;
        }
        case PRECONFIG_4K: {
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1920, .height = 1080 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 1, .maxFps = 30 };
            configs->photoProfile = configs->previewProfile;
            configs->photoProfile.size_ = { .width = 3840, .height = 2160 };
            configs->photoProfile.format_ = CameraFormat::CAMERA_FORMAT_JPEG;
            break;
        }
        case PRECONFIG_HIGH_QUALITY: {
            configs->previewProfile = { CameraFormat::CAMERA_FORMAT_YUV_420_SP, { .width = 1920, .height = 1440 } };
            configs->previewProfile.fps_ = { .fixedFps = 30, .minFps = 1, .maxFps = 30 };
            configs->photoProfile = configs->previewProfile;
            configs->photoProfile.size_ = { .width = 4096, .height = 3072 };
            configs->photoProfile.format_ = CameraFormat::CAMERA_FORMAT_JPEG;
            break;
        }
        default:
            MEDIA_ERR_LOG("PhotoSession::GeneratePreconfigProfiles not support this config:%{public}d", preconfigType);
            return nullptr;
    }
    return configs;
}

bool PhotoSession::CanPreconfig(PreconfigType preconfigType)
{
    std::shared_ptr<PreconfigProfiles> configs = GeneratePreconfigProfiles(preconfigType);
    MEDIA_INFO_LOG("PhotoSession::CanPreconfig check type:%{public}d", preconfigType);
    auto cameraList = CameraManager::GetInstance()->GetSupportedCameras();
    for (auto& device : cameraList) {
        MEDIA_INFO_LOG("PhotoSession::CanPreconfig check camera:%{public}s", device->GetID().c_str());
        // Check photo
        auto photoProfilesIt = device->modePhotoProfiles_.find(SceneMode::CAPTURE);
        if (photoProfilesIt == device->modePhotoProfiles_.end()) {
            MEDIA_ERR_LOG("PhotoSession::CanPreconfig check photo profile fail, empty photo profiles");
            return false;
        }
        auto photoProfiles = photoProfilesIt->second;
        bool isPhotoCanPreconfig = std::any_of(photoProfiles.begin(), photoProfiles.end(),
            [&configs](auto& profile) { return profile == configs->photoProfile; });
        if (!isPhotoCanPreconfig) {
            MEDIA_ERR_LOG("PhotoSession::CanPreconfig check photo profile fail, no matched photo profiles");
            return false;
        }

        // Check preview
        auto previewProfilesIt = device->modePreviewProfiles_.find(SceneMode::CAPTURE);
        if (previewProfilesIt == device->modePreviewProfiles_.end()) {
            MEDIA_ERR_LOG("PhotoSession::CanPreconfig check preview profile fail, empty preview profiles");
            return false;
        }
        auto previewProfiles = previewProfilesIt->second;
        bool isPreviewCanPreconfig = std::any_of(previewProfiles.begin(), previewProfiles.end(),
            [&configs](auto& profile) { return profile == configs->previewProfile; });
        if (!isPreviewCanPreconfig) {
            MEDIA_ERR_LOG("PhotoSession::CanPreconfig check preview profile fail, no matched preview profiles");
            return false;
        }
    }
    MEDIA_INFO_LOG("PhotoSession::CanPreconfig check pass");
    return true;
}

int32_t PhotoSession::Preconfig(PreconfigType preconfigType)
{
    std::shared_ptr<PreconfigProfiles> configs = GeneratePreconfigProfiles(preconfigType);
    SetPreconfigProfiles(configs);
    if (configs == nullptr) {
        MEDIA_ERR_LOG("PhotoSession::Preconfig not support this config:%{public}d", preconfigType);
        return OPERATION_NOT_ALLOWED;
    }
    MEDIA_INFO_LOG("PhotoSession::Preconfig type:%{public}d success", preconfigType);
    return SUCCESS;
}
} // namespace CameraStandard
} // namespace OHOS