/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "basic_definitions.h"
 
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
ErrorCode MapDpsErrorCode(DpsError errorCode)
{
    ErrorCode code = ErrorCode::ERROR_IMAGE_PROC_ABNORMAL;
    switch (errorCode) {
        case DpsError::DPS_ERROR_SESSION_SYNC_NEEDED:
            code = ErrorCode::ERROR_SESSION_SYNC_NEEDED;
            break;
        case DpsError::DPS_ERROR_SESSION_NOT_READY_TEMPORARILY:
            code = ErrorCode::ERROR_SESSION_NOT_READY_TEMPORARILY;
            break;
        case DpsError::DPS_ERROR_IMAGE_PROC_INVALID_PHOTO_ID:
            code = ErrorCode::ERROR_IMAGE_PROC_INVALID_PHOTO_ID;
            break;
        case DpsError::DPS_ERROR_IMAGE_PROC_FAILED:
            code = ErrorCode::ERROR_IMAGE_PROC_FAILED;
            break;
        case DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT:
            code = ErrorCode::ERROR_IMAGE_PROC_TIMEOUT;
            break;
        case DpsError::DPS_ERROR_IMAGE_PROC_ABNORMAL:
            code = ErrorCode::ERROR_IMAGE_PROC_ABNORMAL;
            break;
        case DpsError::DPS_ERROR_IMAGE_PROC_INTERRUPTED:
            code = ErrorCode::ERROR_IMAGE_PROC_INTERRUPTED;
            break;
        case DpsError::DPS_ERROR_VIDEO_PROC_INVALID_VIDEO_ID:
            code = ErrorCode::ERROR_VIDEO_PROC_INVALID_VIDEO_ID;
            break;
        case DpsError::DPS_ERROR_VIDEO_PROC_FAILED:
            code = ErrorCode::ERROR_VIDEO_PROC_FAILED;
            break;
        case DpsError::DPS_ERROR_VIDEO_PROC_TIMEOUT:
            code = ErrorCode::ERROR_VIDEO_PROC_TIMEOUT;
            break;
        case DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED:
            code = ErrorCode::ERROR_VIDEO_PROC_INTERRUPTED;
            break;
        default:
            DP_WARNING_LOG("unexpected error code: %{public}d", errorCode);
            break;
    }
    return code;
}

StatusCode MapDpsStatus(DpsStatus statusCode)
{
    StatusCode code = StatusCode::SESSION_STATE_IDLE;
    switch (statusCode) {
        case DpsStatus::DPS_SESSION_STATE_IDLE:
            code = StatusCode::SESSION_STATE_IDLE;
            break;
        case DpsStatus::DPS_SESSION_STATE_RUNNALBE:
            code = StatusCode::SESSION_STATE_RUNNALBE;
            break;
        case DpsStatus::DPS_SESSION_STATE_RUNNING:
            code = StatusCode::SESSION_STATE_RUNNING;
            break;
        case DpsStatus::DPS_SESSION_STATE_SUSPENDED:
            code = StatusCode::SESSION_STATE_SUSPENDED;
            break;
        case DpsStatus::DPS_SESSION_STATE_PREEMPTED:
            code = StatusCode::SESSION_STATE_PREEMPTED;
            break;
        default:
            DP_WARNING_LOG("unexpected error code: %{public}d", statusCode);
            break;
    }
    return code;
}

DpsError MapHdiError(OHOS::HDI::Camera::V1_2::ErrorCode errorCode)
{
    DpsError code = DpsError::DPS_ERROR_IMAGE_PROC_ABNORMAL;
    switch (errorCode) {
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_INVALID_ID:
            code = DpsError::DPS_ERROR_IMAGE_PROC_INVALID_PHOTO_ID;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_PROCESS:
            code = DpsError::DPS_ERROR_IMAGE_PROC_FAILED;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_TIMEOUT:
            code = DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_HIGH_TEMPERATURE:
            code = DpsError::DPS_ERROR_IMAGE_PROC_HIGH_TEMPERATURE;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_ABNORMAL:
            code = DpsError::DPS_ERROR_IMAGE_PROC_ABNORMAL;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_ABORT:
            code = DpsError::DPS_ERROR_IMAGE_PROC_INTERRUPTED;
            break;
        default:
            DP_ERR_LOG("unexpected error code: %{public}d.", errorCode);
            break;
    }
    return code;
}

HdiStatus MapHdiStatus(OHOS::HDI::Camera::V1_2::SessionStatus statusCode)
{
    HdiStatus code = HdiStatus::HDI_DISCONNECTED;
    switch (statusCode) {
        case OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_READY:
            code = HdiStatus::HDI_READY;
            break;
        case OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_READY_SPACE_LIMIT_REACHED:
            code = HdiStatus::HDI_READY_SPACE_LIMIT_REACHED;
            break;
        case OHOS::HDI::Camera::V1_2::SessionStatus::SESSSON_STATUS_NOT_READY_TEMPORARILY:
            code = HdiStatus::HDI_NOT_READY_TEMPORARILY;
            break;
        case OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_NOT_READY_OVERHEAT:
            code = HdiStatus::HDI_NOT_READY_OVERHEAT;
            break;
        case OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_NOT_READY_PREEMPTED:
            code = HdiStatus::HDI_NOT_READY_PREEMPTED;
            break;
        default:
            DP_ERR_LOG("unexpected error code: %{public}d.", statusCode);
            break;
    }
    return code;
}

OHOS::HDI::Camera::V1_2::ExecutionMode MapToHdiExecutionMode(ExecutionMode executionMode)
{
    auto mode = OHOS::HDI::Camera::V1_2::ExecutionMode::LOW_POWER;
    switch (executionMode) {
        case ExecutionMode::HIGH_PERFORMANCE:
            mode = OHOS::HDI::Camera::V1_2::ExecutionMode::HIGH_PREFORMANCE;
            break;
        case ExecutionMode::LOAD_BALANCE:
            mode = OHOS::HDI::Camera::V1_2::ExecutionMode::BALANCED;
            break;
        case ExecutionMode::LOW_POWER:
            mode = OHOS::HDI::Camera::V1_2::ExecutionMode::LOW_POWER;
            break;
        default:
            DP_ERR_LOG("unexpected error code: %{public}d.", executionMode);
            break;
    }
    return mode;
}

SystemPressureLevel ConvertPhotoThermalLevel(int32_t level)
{
    if (level < LEVEL_0 || level > LEVEL_5) {
        return SystemPressureLevel::SEVERE;
    }
    SystemPressureLevel eventLevel = SystemPressureLevel::SEVERE;
    switch (level) {
        case LEVEL_0:
        case LEVEL_1:
            eventLevel = SystemPressureLevel::NOMINAL;
            break;
        case LEVEL_2:
        case LEVEL_3:
        case LEVEL_4:
            eventLevel = SystemPressureLevel::FAIR;
            break;
        default:
            eventLevel = SystemPressureLevel::SEVERE;
            break;
    }
    return eventLevel;
}

VideoThermalLevel ConvertVideoThermalLevel(int32_t level)
{
    DP_CHECK_RETURN_RET(level == ThermalLevel::LEVEL_0, VideoThermalLevel::COOL);
    return VideoThermalLevel::HOT;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS