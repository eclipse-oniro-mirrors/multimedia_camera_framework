/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "camera_device_ability_items.h"

namespace OHOS {
namespace CameraStandard {

const uint8_t SWTCH_ON = 1;
const uint8_t SWTCH_OFF = 0;

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
    MEDIA_DEBUG_LOG("Enter Into ScanSession::CanAddOutput");
    if (!IsSessionConfiged() || output == nullptr) {
        MEDIA_ERR_LOG("ScanSession::CanAddOutput operation is Not allowed!");
        return false;
    }
    return output->GetOutputType() != CAPTURE_OUTPUT_TYPE_VIDEO && CaptureSession::CanAddOutput(output);
}

bool ScanSession::IsBrightnessStatusSupported()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ScanSession::IsBrightnessStatusSupported Session is not Commited");
        return false;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("ScanSession::IsBrightnessStatusSupported camera device is null");
        return false;
    }
    sptr<CameraDevice> device = inputDevice_->GetCameraDeviceInfo();
    std::shared_ptr<Camera::CameraMetadata> metadata = device->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FLASH_SUGGESTION_SUPPORTED, &item);
    if (ret == CAM_META_SUCCESS) {
        camera_supported_enum_t status = static_cast<camera_supported_enum_t>(item.data.ui32[0]);
        if (status == camera_supported_enum_t::OHOS_CAMERA_SUPPORTED) {
            return true;
        }
    }
    return false;
}
 
void ScanSession::SetBrightnessStatusReport(uint8_t state)
{
    this->LockForControl();
    MEDIA_DEBUG_LOG("ScanSession::SetBrightnessStatusReport set brightness status report");
    bool status = false;
    uint32_t count = 1;
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(
        changedMetadata_->get(), OHOS_CONTROL_FLASH_SUGGESTION_SWITCH, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_FLASH_SUGGESTION_SWITCH, &state, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_FLASH_SUGGESTION_SWITCH, &state, count);
    }
    if (!status) {
        MEDIA_ERR_LOG("ScanSession::SetBrightnessStatusReport Failed to set brightness status report!");
    }
    this->UnlockForControl();
}
 
void ScanSession::RegisterBrightnessStatusCallback(std::shared_ptr<BrightnessStatusCallback> brightnessStatusCallback)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ScanSession::RegisterBrightnessStatusCallback Session is not Commited");
        return;
    }
    brightnessStatusCallback_ = brightnessStatusCallback;
    SetBrightnessStatusReport(SWTCH_ON);
}
 
void ScanSession::UnRegisterBrightnessStatusCallback()
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("ScanSession::UnRegisterBrightnessStatusCallback Session is not Commited");
        return;
    }
    brightnessStatusCallback_ = nullptr;
    SetBrightnessStatusReport(SWTCH_OFF);
}
 
void ScanSession::ProcessBrightnessStatusChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    MEDIA_DEBUG_LOG("Entry ProcessBrightnessStatusChange");
    if (brightnessStatusCallback_ != nullptr) {
        camera_metadata_item_t item;
        common_metadata_header_t* metadata = result->get();
        int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_FLASH_SUGGESTION, &item);
        if (ret != CAM_META_SUCCESS) {
            MEDIA_DEBUG_LOG("ScanSession::ProcessBrightnessStatusChange get brightness status failed");
            return;
        }
        bool state = true;
        uint32_t brightnessStatus = item.data.ui32[0];
        if (brightnessStatus == 1) {
            state = false;
        }
        MEDIA_DEBUG_LOG("ScanSession::ProcessBrightnessStatusChange state = %{public}d", state);
        if (!firstBrightnessStatusCome_) {
            brightnessStatusCallback_->OnBrightnessStatusChanged(state);
            firstBrightnessStatusCome_ = true;
            lastBrightnessStatus_ = state;
            return;
        }
        if (state != lastBrightnessStatus_) {
            brightnessStatusCallback_->OnBrightnessStatusChanged(state);
            lastBrightnessStatus_ = state;
        }
    }
}
 
void ScanSession::ScanSessionMetadataResultProcessor::ProcessCallbacks(
    const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    MEDIA_DEBUG_LOG("ScanSession::ScanSessionMetadataResultProcessor ProcessCallbacks");
    auto session = session_.promote();
    if (session == nullptr) {
        MEDIA_ERR_LOG("ScanSession::ScanSessionMetadataResultProcessor ProcessCallbacks but session is null");
        return;
    }
    session->ProcessAutoFocusUpdates(result);
    session->ProcessBrightnessStatusChange(result);
}
} // namespace CameraStandard
} // namespace OHOS