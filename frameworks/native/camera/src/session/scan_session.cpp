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
 
#include "session/scan_session.h"
#include "input/camera_input.h"
#include "input/camera_manager.h"
#include "output/camera_output_capability.h"
#include "camera_log.h"
#include "camera_error_code.h"
#include "camera_util.h"
 
namespace OHOS {
namespace CameraStandard {
ScanSession::~ScanSession()
{
}
 
int32_t ScanSession::AddOutput(sptr<CaptureOutput> &output)
{
    int32_t result = CAMERA_UNKNOWN_ERROR;
    if (inputDevice_) {
        sptr<CameraDevice> device = inputDevice_->GetCameraDeviceInfo();
        sptr<CameraManager> cameraManager = CameraManager::GetInstance();
        sptr<CameraOutputCapability> outputCapability = nullptr;
        if (device != nullptr && cameraManager != nullptr) {
            outputCapability = cameraManager->GetSupportedOutputCapability(device, SceneMode::SCAN);
        } else {
            MEDIA_ERR_LOG("ScanSession::AddOutput get nullptr to device or cameraManager");
            return CameraErrorCode::DEVICE_DISABLED;
        }
        if ((outputCapability != nullptr && outputCapability->GetPreviewProfiles().size() != 0 &&
            output->GetOutputType() == CAPTURE_OUTPUT_TYPE_PREVIEW)) {
            result = CaptureSession::AddOutput(output);
        } else {
            MEDIA_ERR_LOG("ScanSession::AddOutput can not add current type of output");
            return CameraErrorCode::SESSION_NOT_CONFIG;
        }
    } else {
        MEDIA_ERR_LOG("ScanSession::AddOutput get nullptr to inputDevice_");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    return result;
}

bool ScanSession::CanAddOutput(sptr<CaptureOutput> &output)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into ScanSession::CanAddOutput");
    if (!IsSessionConfiged() || output == nullptr) {
        MEDIA_ERR_LOG("ScanSession::CanAddOutput operation Not allowed!");
        return false;
    }
    int32_t scan = 7;
    if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_PREVIEW) {
        std::vector<Profile> previewProfiles = inputDevice_->GetCameraDeviceInfo()->modePreviewProfiles_[scan];
        Profile vaildateProfile = output->GetPreviewProfile();
        for (auto& previewProfile : previewProfiles) {
            if (vaildateProfile == previewProfile) {
                return true;
            }
        }
    } else if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_PHOTO) {
        std::vector<Profile> photoProfiles = inputDevice_->GetCameraDeviceInfo()->modePhotoProfiles_[scan];
        Profile vaildateProfile = output->GetPhotoProfile();
        for (auto& photoProfile : photoProfiles) {
            if (vaildateProfile == photoProfile) {
                return true;
            }
        }
    } else if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_METADATA) {
        MEDIA_INFO_LOG("ScanSession::CanAddOutput MetadataOutput");
        return true;
    }
    return false;
}
} // namespace CameraStandard
} // namespace OHOS