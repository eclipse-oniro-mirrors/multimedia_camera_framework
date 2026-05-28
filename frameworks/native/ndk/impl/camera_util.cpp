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

#include "kits/native/include/camera/camera.h"
#include "camera_log.h"
#include "camera_error_code.h"
#include "camera_util.h"

namespace OHOS {
namespace CameraStandard {
static const std::unordered_map<int32_t, Camera_ErrorCode> frameworkToNdkErrorMap = {
    {static_cast<int32_t>(CameraErrorCode::SUCCESS), CAMERA_OK},
    {static_cast<int32_t>(CameraErrorCode::NO_SYSTEM_APP_PERMISSION), CAMERA_OPERATION_NOT_ALLOWED},
    {static_cast<int32_t>(CameraErrorCode::PARAMETER_ERROR), CAMERA_INVALID_ARGUMENT},
    {static_cast<int32_t>(CameraErrorCode::INVALID_ARGUMENT), CAMERA_INVALID_ARGUMENT},
    {static_cast<int32_t>(CameraErrorCode::OPERATION_NOT_ALLOWED), CAMERA_OPERATION_NOT_ALLOWED},
    {static_cast<int32_t>(CameraErrorCode::OPERATION_NOT_ALLOWED_OF_SESSION_READY), CAMERA_OPERATION_NOT_ALLOWED},
    {static_cast<int32_t>(CameraErrorCode::OPERATION_NOT_ALLOWED_OF_UNSUPPORTED_FEATURE), CAMERA_OPERATION_NOT_ALLOWED},
    {static_cast<int32_t>(CameraErrorCode::OPERATION_NOT_ALLOWED_OF_DEVICE), CAMERA_OPERATION_NOT_ALLOWED},
    {static_cast<int32_t>(CameraErrorCode::SESSION_NOT_CONFIG), CAMERA_SESSION_NOT_CONFIG},
    {static_cast<int32_t>(CameraErrorCode::SESSION_NOT_RUNNING), CAMERA_SESSION_NOT_RUNNING},
    {static_cast<int32_t>(CameraErrorCode::SESSION_CONFIG_LOCKED), CAMERA_SESSION_CONFIG_LOCKED},
    {static_cast<int32_t>(CameraErrorCode::DEVICE_SETTING_LOCKED), CAMERA_DEVICE_SETTING_LOCKED},
    {static_cast<int32_t>(CameraErrorCode::CONFLICT_CAMERA), CAMERA_CONFLICT_CAMERA},
    {static_cast<int32_t>(CameraErrorCode::DEVICE_DISABLED), CAMERA_DEVICE_DISABLED},
    {static_cast<int32_t>(CameraErrorCode::DEVICE_PREEMPTED), CAMERA_DEVICE_PREEMPTED},
    {static_cast<int32_t>(CameraErrorCode::SERVICE_FATL_ERROR), CAMERA_SERVICE_FATAL_ERROR},
    {static_cast<int32_t>(CameraErrorCode::SERVICE_FATL_ERROR_OF_CONFIG), CAMERA_SERVICE_FATAL_ERROR},
    {static_cast<int32_t>(CameraErrorCode::SERVICE_FATL_ERROR_OF_ALLOC), CAMERA_SERVICE_FATAL_ERROR},
    {static_cast<int32_t>(CameraErrorCode::SERVICE_FATL_ERROR_OF_INVALID_SESSION_CFG), CAMERA_SERVICE_FATAL_ERROR},
    {static_cast<int32_t>(CameraErrorCode::UNRESOLVED_CONFLICTS_BETWEEN_STREAMS),
     CAMERA_UNRESOLVED_CONFLICTS_WITH_CURRENT_CONFIGURATIONS},
    {static_cast<int32_t>(CameraErrorCode::CAPABILITY_NOT_SUPPORTED),
     CAMERA_ERROR_CAPABILITY_NOT_SUPPORTED},
};

Camera_ErrorCode FrameworkToNdkCameraError(int32_t ret)
{
    auto it = frameworkToNdkErrorMap.find(ret);
    if (it != frameworkToNdkErrorMap.end()) {
        return it->second;
    }
    if (ret != static_cast<int32_t>(CameraErrorCode::SUCCESS)) {
        MEDIA_ERR_LOG("FrameworkToNdkCameraError() unknown error code: %{public}d", ret);
    }
    return CAMERA_OK;
}

void ProcessCameraInfos(const std::vector<sptr<CameraDevice>>& cameraObjList, CameraPosition innerPosition,
    int32_t queryConnection, const std::vector<CameraType>& typeFilters,
    std::vector<sptr<CameraDevice>>& matchedDevices)
{
    matchedDevices.clear();
    matchedDevices.reserve(cameraObjList.size());

    for (const auto& cameraDevice : cameraObjList) {
        if (cameraDevice == nullptr) {
            continue;
        }
        if (cameraDevice->GetPosition() != innerPosition) {
            continue;
        }
        if (static_cast<int32_t>(cameraDevice->GetConnectionType()) != queryConnection) {
            continue;
        }
        CameraType deviceType = cameraDevice->GetCameraType();
        if (!typeFilters.empty()) {
            auto it = std::find(typeFilters.begin(), typeFilters.end(), deviceType);
            if (it == typeFilters.end()) {
                continue;
            }
        }
        matchedDevices.emplace_back(cameraDevice);
    }
}
} // namespace CameraStandard
} // namespace OHOS