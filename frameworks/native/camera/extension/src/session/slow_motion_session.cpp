/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
 
#include "session/slow_motion_session.h"
#include "camera_log.h"
#include "camera_error_code.h"
#include "metadata_common_utils.h"

namespace OHOS {
namespace CameraStandard {

const std::unordered_map<camera_slow_motion_status_type_t, SlowMotionState> SlowMotionSession::metaMotionStateMap_ = {
    {OHOS_CONTROL_SLOW_MOTION_STATUS_DISABLE, SlowMotionState::DISABLE},
    {OHOS_CONTROL_SLOW_MOTION_STATUS_READY, SlowMotionState::READY},
    {OHOS_CONTROL_SLOW_MOTION_STATUS_START, SlowMotionState::START},
    {OHOS_CONTROL_SLOW_MOTION_STATUS_RECORDING, SlowMotionState::RECORDING},
    {OHOS_CONTROL_SLOW_MOTION_STATUS_FINISH, SlowMotionState::FINISH}
};

void SlowMotionSession::SlowMotionSessionMetadataResultProcessor::ProcessCallbacks(
    const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    MEDIA_DEBUG_LOG("SlowMotionSessionMetadataResultProcessor::ProcessCallbacks is called");
    auto session = session_.promote();
    CHECK_RETURN_ELOG(session == nullptr,
        "SlowMotionSessionMetadataResultProcessor ProcessCallbacks but session is null");

    session->ProcessAutoFocusUpdates(result);
    session->OnSlowMotionStateChange(result);
}

SlowMotionSession::~SlowMotionSession()
{
}

bool SlowMotionSession::CanAddOutput(sptr<CaptureOutput> &output)
{
    MEDIA_DEBUG_LOG("Enter Into CanAddOutput");
    return CaptureSession::CanAddOutput(output);
}

bool SlowMotionSession::IsSlowMotionDetectionSupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("IsSlowMotionDetectionSupported is called");
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), false,
        "IsSlowMotionDetectionSupported Session is not Commited");
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice, false,
        "IsSlowMotionDetectionSupported camera device is null");
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!inputDeviceInfo, false,
        "IsSlowMotionDetectionSupported camera deviceInfo is null");
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetCachedMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_MOTION_DETECTION_SUPPORT, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, false,
        "IsSlowMotionDetectionSupported Failed with return code %{public}d", ret);
    MEDIA_INFO_LOG("IsSlowMotionDetectionSupported value: %{public}u", item.data.u8[0]);
    CHECK_RETURN_RET(item.data.u8[0] == 1, true);
    return false;
}

void SlowMotionSession::NormalizeRect(Rect& rect)
{
    // Validate and adjust topLeftX and topLeftY
    rect.topLeftX = std::max(0.0, std::min(1.0, rect.topLeftX));
    rect.topLeftY = std::max(0.0, std::min(1.0, rect.topLeftY));

    // Validate and adjust width and height
    rect.width = std::max(0.0, std::min(1.0, rect.width));
    rect.height = std::max(0.0, std::min(1.0, rect.height));
}

void SlowMotionSession::SetSlowMotionDetectionArea(Rect rect)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("SetSlowMotionDetectionArea is called");
    CHECK_RETURN_ELOG(!IsSessionCommited(),
        "SetSlowMotionDetectionArea Session is not Commited");
    this->LockForControl();
    CHECK_RETURN_ELOG(changedMetadata_ == nullptr,
        "SetSlowMotionDetectionArea changedMetadata is null");
    int32_t retCode = EnableMotionDetection(true);
    CHECK_RETURN_ELOG(retCode != CameraErrorCode::SUCCESS, "EnableMotionDetection call failed");
    MEDIA_INFO_LOG("topLeftX: %{public}f, topLeftY: %{public}f, width: %{public}f, height: %{public}f",
        rect.topLeftX, rect.topLeftY, rect.width, rect.height);
    NormalizeRect(rect);
    std::vector<float> rectVec = {static_cast<float>(rect.topLeftX), static_cast<float>(rect.topLeftY),
        static_cast<float>(rect.width), static_cast<float>(rect.height)};
    bool status = AddOrUpdateMetadata(
        changedMetadata_, OHOS_CONTROL_MOTION_DETECTION_CHECK_AREA, rectVec.data(), rectVec.size());
    this->UnlockForControl();
    CHECK_PRINT_ELOG(!status, "SetSlowMotionDetectionArea failed to set motion rect");
    return;
}

void SlowMotionSession::OnSlowMotionStateChange(std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult)
{
    std::shared_ptr<SlowMotionStateCallback> appCallback = GetApplicationCallback();
    CHECK_RETURN_ELOG(appCallback == nullptr, "OnSlowMotionStateChange appCallback is null");
    SlowMotionState state = SlowMotionState::DISABLE;
    if (cameraResult != nullptr) {
        camera_metadata_item_t item;
        common_metadata_header_t* metadata = cameraResult->get();
        int ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_SLOW_MOTION_DETECTION, &item);
        if (ret != CAM_META_SUCCESS) {
            MEDIA_ERR_LOG("OnSlowMotionStateChange Failed with return code %{public}d", ret);
        } else {
            MEDIA_DEBUG_LOG("slowMotionState: %{public}d", item.data.u8[0]);
            auto itr = metaMotionStateMap_.find(static_cast<camera_slow_motion_status_type_t>(item.data.u8[0]));
            if (itr != metaMotionStateMap_.end()) {
                state = itr->second;
            }
        }
    } else {
        MEDIA_ERR_LOG("cameraResult is null");
    }
    if (state != appCallback->GetSlowMotionState()) {
        MEDIA_INFO_LOG("OnSlowMotionStateChange call success, preState: %{public}d, curState: %{public}d",
            appCallback->GetSlowMotionState(), state);
        appCallback->SetSlowMotionState(state);
        appCallback->OnSlowMotionState(state);
    }
}

void SlowMotionSession::SetCallback(std::shared_ptr<SlowMotionStateCallback> callback)
{
    CHECK_RETURN_ELOG(callback == nullptr, "SlowMotionSession::SetCallback callback is null");
    std::lock_guard<std::mutex> lock(stateCallbackMutex_);
    slowMotionStateCallback_ = callback;
}

std::shared_ptr<SlowMotionStateCallback> SlowMotionSession::GetApplicationCallback()
{
    std::lock_guard<std::mutex> lock(stateCallbackMutex_);
    return slowMotionStateCallback_;
}

int32_t SlowMotionSession::EnableMotionDetection(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("Enter EnableMotionDetection, isEnable:%{public}d", isEnable);
    CHECK_RETURN_RET_ELOG(!IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "EnableMotionDetection session not commited");
    uint8_t enableValue = static_cast<uint8_t>(isEnable ?
        OHOS_CAMERA_MOTION_DETECTION_ENABLE : OHOS_CAMERA_MOTION_DETECTION_DISABLE);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_MOTION_DETECTION, &enableValue, 1);
    CHECK_PRINT_ELOG(!status, "EnableMotionDetection Failed to enable motion detection");
    return CameraErrorCode::SUCCESS;
}
} // namespace CameraStandard
} // namespace OHOS