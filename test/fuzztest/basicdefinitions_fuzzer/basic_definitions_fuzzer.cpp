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

#include "basic_definitions_fuzzer.h"
#include <cstdint>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

// covers MapDpsErrorCode (11 cases + default) and MapDpsStatus (5 cases + default)
void BasicDefinitionsFuzzTest1(FuzzedDataProvider& fdp)
{
    MapDpsErrorCode(DpsError::DPS_ERROR_SESSION_SYNC_NEEDED);
    MapDpsErrorCode(DpsError::DPS_ERROR_SESSION_NOT_READY_TEMPORARILY);
    MapDpsErrorCode(DpsError::DPS_ERROR_IMAGE_PROC_INVALID_PHOTO_ID);
    MapDpsErrorCode(DpsError::DPS_ERROR_IMAGE_PROC_FAILED);
    MapDpsErrorCode(DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT);
    MapDpsErrorCode(DpsError::DPS_ERROR_IMAGE_PROC_ABNORMAL);
    MapDpsErrorCode(DpsError::DPS_ERROR_IMAGE_PROC_INTERRUPTED);
    MapDpsErrorCode(DpsError::DPS_ERROR_VIDEO_PROC_INVALID_VIDEO_ID);
    MapDpsErrorCode(DpsError::DPS_ERROR_VIDEO_PROC_FAILED);
    MapDpsErrorCode(DpsError::DPS_ERROR_VIDEO_PROC_TIMEOUT);
    MapDpsErrorCode(DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED);
    MapDpsErrorCode(static_cast<DpsError>(fdp.ConsumeIntegral<int32_t>() | 0x1000));
    MapDpsStatus(DpsStatus::DPS_SESSION_STATE_IDLE);
    MapDpsStatus(DpsStatus::DPS_SESSION_STATE_RUNNABLE);
    MapDpsStatus(DpsStatus::DPS_SESSION_STATE_RUNNING);
    MapDpsStatus(DpsStatus::DPS_SESSION_STATE_SUSPENDED);
    MapDpsStatus(DpsStatus::DPS_SESSION_STATE_PREEMPTED);
    MapDpsStatus(static_cast<DpsStatus>(fdp.ConsumeIntegral<int32_t>() | 0x1000));
}

// covers MapHdiError (6 cases + default) and MapHdiVideoError (4 cases + default)
void BasicDefinitionsFuzzTest2(FuzzedDataProvider& fdp)
{
    using HdiErr = OHOS::HDI::Camera::V1_2::ErrorCode;
    MapHdiError(HdiErr::ERROR_INVALID_ID);
    MapHdiError(HdiErr::ERROR_PROCESS);
    MapHdiError(HdiErr::ERROR_TIMEOUT);
    MapHdiError(HdiErr::ERROR_HIGH_TEMPERATURE);
    MapHdiError(HdiErr::ERROR_ABNORMAL);
    MapHdiError(HdiErr::ERROR_ABORT);
    MapHdiError(static_cast<HdiErr>(fdp.ConsumeIntegral<int32_t>() | 0x1000));
    MapHdiVideoError(HdiErr::ERROR_INVALID_ID);
    MapHdiVideoError(HdiErr::ERROR_PROCESS);
    MapHdiVideoError(HdiErr::ERROR_TIMEOUT);
    MapHdiVideoError(HdiErr::ERROR_ABORT);
    MapHdiVideoError(static_cast<HdiErr>(fdp.ConsumeIntegral<int32_t>() | 0x1000));
}

// covers MapHdiStatus (5 cases + default) and MapToHdiExecutionMode (3 cases + default)
void BasicDefinitionsFuzzTest3(FuzzedDataProvider& fdp)
{
    using HdiSess = OHOS::HDI::Camera::V1_2::SessionStatus;
    MapHdiStatus(HdiSess::SESSION_STATUS_READY);
    MapHdiStatus(HdiSess::SESSION_STATUS_READY_SPACE_LIMIT_REACHED);
    MapHdiStatus(HdiSess::SESSSON_STATUS_NOT_READY_TEMPORARILY);
    MapHdiStatus(HdiSess::SESSION_STATUS_NOT_READY_OVERHEAT);
    MapHdiStatus(HdiSess::SESSION_STATUS_NOT_READY_PREEMPTED);
    MapHdiStatus(static_cast<HdiSess>(fdp.ConsumeIntegral<int32_t>() | 0x1000));
    MapToHdiExecutionMode(ExecutionMode::HIGH_PERFORMANCE);
    MapToHdiExecutionMode(ExecutionMode::LOAD_BALANCE);
    MapToHdiExecutionMode(ExecutionMode::LOW_POWER);
    MapToHdiExecutionMode(ExecutionMode::DUMMY);
}

// covers ConvertPhotoThermalLevel (out-of-range / LEVEL_0,1 / 2,3,4 / 5) and
// ConvertVideoThermalLevel (LEVEL_0 -> COOL / else -> HOT)
void BasicDefinitionsFuzzTest4(FuzzedDataProvider& fdp)
{
    ConvertPhotoThermalLevel(-1);
    ConvertPhotoThermalLevel(0);
    ConvertPhotoThermalLevel(1);
    ConvertPhotoThermalLevel(2);
    ConvertPhotoThermalLevel(3);
    ConvertPhotoThermalLevel(4);
    ConvertPhotoThermalLevel(5);
    ConvertPhotoThermalLevel(6);
    ConvertVideoThermalLevel(0);
    ConvertVideoThermalLevel(fdp.ConsumeIntegral<int32_t>() | 1);
}

void Test(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    switch (fdp.ConsumeIntegral<uint8_t>() % 4) {
        case 0:
            BasicDefinitionsFuzzTest1(fdp);
            break;
        case 1:
            BasicDefinitionsFuzzTest2(fdp);
            break;
        case 2:
            BasicDefinitionsFuzzTest3(fdp);
            break;
        default:
            BasicDefinitionsFuzzTest4(fdp);
            break;
    }
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::CameraStandard::DeferredProcessing::Test(data, size);
    return 0;
}
