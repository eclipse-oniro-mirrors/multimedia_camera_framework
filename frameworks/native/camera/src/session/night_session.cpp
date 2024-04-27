/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "session/night_session.h"
#include "camera_util.h"
#include "input/camera_input.h"
#include "camera_log.h"
#include "output/photo_output.h"
#include "output/preview_output.h"
#include "output/video_output.h"

namespace OHOS {
namespace CameraStandard {
NightSession::~NightSession()
{
    MEDIA_DEBUG_LOG("Enter Into NightSession::~NightSession()");
}

int32_t NightSession::GetExposureRange(std::vector<uint32_t> &exposureRange)
{
    exposureRange.clear();
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("NightSession::GetExposureRange Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("NightSession::GetExposureRange camera device is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    if (metadata == nullptr) {
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("CaptureSession::GetFilter Failed with return code %{public}d", ret);
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    for (uint32_t i = 0; i < item.count; i++) {
        exposureRange.emplace_back(item.data.ui32[i]);
    }
    return CameraErrorCode::SUCCESS;
}

int32_t NightSession::SetExposure(uint32_t exposureValue)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("NightSession::SetExposure Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (changedMetadata_ == nullptr) {
        MEDIA_ERR_LOG("NightSession::SetExposureValue Need to call LockForControl() "
            "before setting camera properties");
        return CameraErrorCode::SUCCESS;
    }
    bool status = false;
    int32_t count = 1;
    camera_metadata_item_t item;
    MEDIA_DEBUG_LOG("NightSession::SetExposureValue exposure compensation: %{public}d", exposureValue);
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("NightSession::SetExposure camera device is null");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }

    std::vector<uint32_t> exposureRange;
    if ((GetExposureRange(exposureRange) != CameraErrorCode::SUCCESS) && exposureRange.empty()) {
        MEDIA_ERR_LOG("NightSession::SetExposureValue range is empty");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    const uint32_t autoLongExposure = 0;
    if (std::find(exposureRange.begin(), exposureRange.end(), exposureValue) == exposureRange.end() &&
            exposureValue != autoLongExposure) {
        MEDIA_ERR_LOG("NightSession::SetExposureValue value(%{public}d)is not supported!", exposureValue);
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }

    uint32_t exposureCompensation = exposureValue;
    int ret = Camera::FindCameraMetadataItem(changedMetadata_->get(), OHOS_CONTROL_MANUAL_EXPOSURE_TIME, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = changedMetadata_->addEntry(OHOS_CONTROL_MANUAL_EXPOSURE_TIME, &exposureCompensation, count);
    } else if (ret == CAM_META_SUCCESS) {
        status = changedMetadata_->updateEntry(OHOS_CONTROL_MANUAL_EXPOSURE_TIME, &exposureCompensation, count);
    }
    if (!status) {
        MEDIA_ERR_LOG("NightSession::SetExposureValue Failed to set exposure compensation");
    }
    return CameraErrorCode::SUCCESS;
}

int32_t NightSession::GetExposure(uint32_t &exposureValue)
{
    if (!IsSessionCommited()) {
        MEDIA_ERR_LOG("NightSession::GetExposure Session is not Commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (!inputDevice_ || !inputDevice_->GetCameraDeviceInfo()) {
        MEDIA_ERR_LOG("NightSession::GetExposure camera device is null");
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDevice_->GetCameraDeviceInfo()->GetMetadata();
    if (metadata == nullptr) {
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_MANUAL_EXPOSURE_TIME, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_ERR_LOG("NightSession::GetExposure Failed with return code %{public}d", ret);
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    exposureValue = item.data.ui32[0];
    MEDIA_DEBUG_LOG("exposureValue: %{public}d", exposureValue);
    return CameraErrorCode::SUCCESS;
}

void NightSession::NightSessionMetadataResultProcessor::ProcessCallbacks(
    const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    MEDIA_INFO_LOG("CaptureSession::NightSessionMetadataResultProcessor ProcessCallbacks");
    auto session = session_.promote();
    if (session == nullptr) {
        MEDIA_ERR_LOG("CaptureSession::NightSessionMetadataResultProcessor ProcessCallbacks but session is null");
        return;
    }

    session->ProcessFaceRecUpdates(timestamp, result);
    session->ProcessAutoFocusUpdates(result);
}

bool NightSession::CanAddOutput(sptr<CaptureOutput>& output)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into NightSession::CanAddOutput");
    if (!IsSessionConfiged() || output == nullptr) {
        MEDIA_ERR_LOG("NightSession::CanAddOutput operation is Not allowed!");
        return false;
    }
    return output->GetOutputType() != CAPTURE_OUTPUT_TYPE_VIDEO && CaptureSession::CanAddOutput(output);
}
} // CameraStandard
} // OHOS
