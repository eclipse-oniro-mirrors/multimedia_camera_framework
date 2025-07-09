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
    CHECK_RETURN_RET_ELOG(output == nullptr, CameraErrorCode::INVALID_ARGUMENT,
        "ScanSession::AddOutput output is nullptr");
    int32_t result = CAMERA_UNKNOWN_ERROR;
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
        "ScanSession::AddOutput get nullptr to inputDevice");

    sptr<CameraDevice> device = inputDevice->GetCameraDeviceInfo();
    sptr<CameraManager> cameraManager = CameraManager::GetInstance();
    sptr<CameraOutputCapability> outputCapability = nullptr;

    CHECK_RETURN_RET_ELOG(device == nullptr || cameraManager == nullptr, CameraErrorCode::DEVICE_DISABLED,
        "ScanSession::AddOutput get nullptr to device or cameraManager");
    outputCapability = cameraManager->GetSupportedOutputCapability(device, SceneMode::SCAN);

    CHECK_RETURN_RET_ELOG((outputCapability == nullptr || outputCapability->GetPreviewProfiles().size() == 0 ||
        output->GetOutputType() != CAPTURE_OUTPUT_TYPE_PREVIEW), CameraErrorCode::SESSION_NOT_CONFIG,
        "ScanSession::AddOutput can not add current type of output");
    result = CaptureSession::AddOutput(output);
    return result;
}

bool ScanSession::CanAddOutput(sptr<CaptureOutput> &output)
{
    MEDIA_DEBUG_LOG("Enter Into ScanSession::CanAddOutput");
    CHECK_RETURN_RET_ELOG(!IsSessionConfiged() || output == nullptr, false,
        "ScanSession::CanAddOutput operation is Not allowed!");
    return output->GetOutputType() != CAPTURE_OUTPUT_TYPE_VIDEO && CaptureSession::CanAddOutput(output);
}

bool ScanSession::IsBrightnessStatusSupported()
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), false,
        "ScanSession::IsBrightnessStatusSupported Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice, false,
        "ScanSession::IsBrightnessStatusSupported camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, false,
        "ScanSession::IsBrightnessStatusSupported camera deviceInfo is null");
    sptr<CameraDevice> device = inputDeviceInfo;
    std::shared_ptr<Camera::CameraMetadata> metadata = device->GetCachedMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_FLASH_SUGGESTION_SUPPORTED, &item);
    if (ret == CAM_META_SUCCESS) {
        camera_supported_enum_t status = static_cast<camera_supported_enum_t>(item.data.ui32[0]);
        CHECK_RETURN_RET(status == camera_supported_enum_t::OHOS_CAMERA_SUPPORTED, true);
    }
    return false;
}
 
void ScanSession::SetBrightnessStatusReport(uint8_t state)
{
    this->LockForControl();
    MEDIA_DEBUG_LOG("ScanSession::SetBrightnessStatusReport set brightness status report");
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_FLASH_SUGGESTION_SWITCH, &state, 1);
    CHECK_PRINT_ELOG(!status, "ScanSession::SetBrightnessStatusReport Failed to set brightness status report!");
    this->UnlockForControl();
}

void ScanSession::RegisterBrightnessStatusCallback(std::shared_ptr<BrightnessStatusCallback> brightnessStatusCallback)
{
    CHECK_RETURN_ELOG(!IsSessionCommited(),
        "ScanSession::RegisterBrightnessStatusCallback Session is not Commited");
    SetBrightnessStatusCallback(brightnessStatusCallback);
    SetBrightnessStatusReport(SWTCH_ON);
}
 
void ScanSession::UnRegisterBrightnessStatusCallback()
{
    CHECK_RETURN_ELOG(!IsSessionCommited(),
        "ScanSession::UnRegisterBrightnessStatusCallback Session is not Commited");
    SetBrightnessStatusCallback(nullptr);
    SetBrightnessStatusReport(SWTCH_OFF);
}

void ScanSession::ProcessBrightnessStatusChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    CHECK_RETURN_ELOG(result == nullptr, "ScanSession::ProcessBrightnessStatusChange result is null.");
    MEDIA_DEBUG_LOG("Entry ProcessBrightnessStatusChange");
    auto callback = GetBrightnessStatusCallback();
    if (callback != nullptr) {
        camera_metadata_item_t item;
        common_metadata_header_t* metadata = result->get();
        int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_FLASH_SUGGESTION, &item);
        CHECK_RETURN_ELOG(ret != CAM_META_SUCCESS,
            "ScanSession::ProcessBrightnessStatusChange get brightness status failed");
        bool state = true;
        uint32_t brightnessStatus = item.data.ui32[0];
        if (brightnessStatus == 1) {
            state = false;
        }
        MEDIA_DEBUG_LOG("ScanSession::ProcessBrightnessStatusChange state = %{public}d", state);
        if (!firstBrightnessStatusCome_) {
            callback->OnBrightnessStatusChanged(state);
            firstBrightnessStatusCome_ = true;
            lastBrightnessStatus_ = state;
            return;
        }
        if (state != lastBrightnessStatus_) {
            callback->OnBrightnessStatusChanged(state);
            lastBrightnessStatus_ = state;
        }
    }
}

void ScanSession::ScanSessionMetadataResultProcessor::ProcessCallbacks(
    const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    CHECK_RETURN_ELOG(result == nullptr,
        "ScanSession::ScanSessionMetadataResultProcessor ProcessCallbacks result is null.");
    MEDIA_DEBUG_LOG("ScanSession::ScanSessionMetadataResultProcessor ProcessCallbacks");
    auto session = session_.promote();
    CHECK_RETURN_ELOG(session == nullptr,
        "ScanSession::ScanSessionMetadataResultProcessor ProcessCallbacks but session is null");
    session->ProcessAutoFocusUpdates(result);
    session->ProcessBrightnessStatusChange(result);
}
} // namespace CameraStandard
} // namespace OHOS