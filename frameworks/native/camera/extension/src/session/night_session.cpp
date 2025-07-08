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
#include "camera_log.h"
#include "metadata_common_utils.h"

namespace OHOS {
namespace CameraStandard {
NightSession::~NightSession()
{
    MEDIA_DEBUG_LOG("Enter Into NightSession::~NightSession()");
}

int32_t NightSession::GetExposureRange(std::vector<uint32_t> &exposureRange)
{
    exposureRange.clear();
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "NightSession::GetExposureRange Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice, CameraErrorCode::INVALID_ARGUMENT,
        "NightSession::GetExposureRange camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, CameraErrorCode::INVALID_ARGUMENT,
        "NightSession::GetExposureRange camera deviceInfo is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET(metadata == nullptr, CameraErrorCode::INVALID_ARGUMENT);
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::INVALID_ARGUMENT,
        "NightSession::GetExposureRange Failed with return code %{public}d", ret);
    for (uint32_t i = 0; i < item.count; i++) {
        exposureRange.emplace_back(item.data.ui32[i]);
    }
    return CameraErrorCode::SUCCESS;
}

int32_t NightSession::SetExposure(uint32_t exposureValue)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "NightSession::SetExposure Session is not Commited");
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "NightSession::SetExposure Need to call LockForControl() before setting camera properties");
    MEDIA_DEBUG_LOG("NightSession::SetExposure exposure compensation: %{public}d", exposureValue);
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice || !inputDevice->GetCameraDeviceInfo(),
        CameraErrorCode::OPERATION_NOT_ALLOWED, "NightSession::SetExposure camera device is null");

    std::vector<uint32_t> exposureRange;
    CHECK_RETURN_RET_ELOG((GetExposureRange(exposureRange) != CameraErrorCode::SUCCESS) && exposureRange.empty(),
        CameraErrorCode::OPERATION_NOT_ALLOWED, "NightSession::SetExposure range is empty");
    const uint32_t autoLongExposure = 0;
    bool result = std::find(exposureRange.begin(), exposureRange.end(), exposureValue) == exposureRange.end();
    CHECK_RETURN_RET_ELOG(result && exposureValue != autoLongExposure, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "NightSession::SetExposure value(%{public}d)is not supported!", exposureValue);
    uint32_t exposureCompensation = exposureValue;
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_MANUAL_EXPOSURE_TIME, &exposureCompensation, 1);
    CHECK_PRINT_ELOG(!status, "NightSession::SetExposure Failed to set exposure compensation");
    return CameraErrorCode::SUCCESS;
}

int32_t NightSession::GetExposure(uint32_t &exposureValue)
{
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "NightSession::GetExposure Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice, CameraErrorCode::INVALID_ARGUMENT,
        "NightSession::GetExposure camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, CameraErrorCode::INVALID_ARGUMENT,
        "NightSession::GetExposure camera deviceInfo is null");
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET(metadata == nullptr, CameraErrorCode::INVALID_ARGUMENT);
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_MANUAL_EXPOSURE_TIME, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, CameraErrorCode::INVALID_ARGUMENT,
        "NightSession::GetExposure Failed with return code %{public}d", ret);
    exposureValue = item.data.ui32[0];
    MEDIA_DEBUG_LOG("exposureValue: %{public}d", exposureValue);
    return CameraErrorCode::SUCCESS;
}

void NightSession::NightSessionMetadataResultProcessor::ProcessCallbacks(
    const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    MEDIA_DEBUG_LOG("CaptureSession::NightSessionMetadataResultProcessor ProcessCallbacks");
    auto session = session_.promote();
    CHECK_RETURN_ELOG(session == nullptr,
        "CaptureSession::NightSessionMetadataResultProcessor ProcessCallbacks but session is null");

    session->ProcessAutoFocusUpdates(result);
    session->ProcessLcdFlashStatusUpdates(result);
}

bool NightSession::CanAddOutput(sptr<CaptureOutput>& output)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter Into NightSession::CanAddOutput");
    CHECK_RETURN_RET_ELOG(!IsSessionConfiged() || output == nullptr, false,
        "NightSession::CanAddOutput operation is Not allowed!");
    return output->GetOutputType() != CAPTURE_OUTPUT_TYPE_VIDEO && CaptureSession::CanAddOutput(output);
}
} // CameraStandard
} // OHOS
