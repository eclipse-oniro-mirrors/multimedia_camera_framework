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
Camera_ErrorCode FrameworkToNdkCameraError(int32_t ret)
{
    Camera_ErrorCode err = CAMERA_OK;
    switch (ret) {
        case CameraErrorCode::SUCCESS:
            err = CAMERA_OK;
            break;
        case CameraErrorCode::NO_SYSTEM_APP_PERMISSION:
            err = CAMERA_OPERATION_NOT_ALLOWED;
            break;
        case CameraErrorCode::INVALID_ARGUMENT:
            err = CAMERA_INVALID_ARGUMENT;
            break;
        case CameraErrorCode::OPERATION_NOT_ALLOWED:
            err = CAMERA_OPERATION_NOT_ALLOWED;
            break;
        case CameraErrorCode::SESSION_NOT_CONFIG:
            err = CAMERA_SESSION_NOT_CONFIG;
            break;
        case CameraErrorCode::SESSION_NOT_RUNNING:
            err = CAMERA_SESSION_NOT_RUNNING;
            break;
        case CameraErrorCode::SESSION_CONFIG_LOCKED:
            err = CAMERA_SESSION_CONFIG_LOCKED;
            break;
        case CameraErrorCode::DEVICE_SETTING_LOCKED:
            err = CAMERA_DEVICE_SETTING_LOCKED;
            break;
        case CameraErrorCode::CONFLICT_CAMERA:
            err = CAMERA_CONFLICT_CAMERA;
            break;
        case CameraErrorCode::DEVICE_DISABLED:
            err = CAMERA_DEVICE_DISABLED;
            break;
        case CameraErrorCode::DEVICE_PREEMPTED:
            err = CAMERA_DEVICE_PREEMPTED;
            break;
        case CameraErrorCode::SERVICE_FATL_ERROR:
            err = CAMERA_SERVICE_FATAL_ERROR;
            break;
        default:
            MEDIA_ERR_LOG("ServiceToCameraError() error code from service: %{public}d", ret);
            break;
    }
    return err;
}
} // namespace CameraStandard
} // namespace OHOS