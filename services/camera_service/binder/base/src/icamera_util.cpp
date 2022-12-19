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

#include "icamera_util.h"
#include "camera_error_code.h"
#include "camera_util.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
int32_t ServiceToCameraError(int32_t ret)
{
    int32_t err = CameraErrorCode::SERVICE_FATL_ERROR;
    switch (ret) {
        case CAMERA_OK:
            err = 0;
            break;
        case CAMERA_ALLOC_ERROR:
            err = CameraErrorCode::SERVICE_FATL_ERROR;
            break;
        case CAMERA_INVALID_ARG:
            err = CameraErrorCode::SERVICE_FATL_ERROR;
            break;
        case CAMERA_UNSUPPORTED:
            err = CameraErrorCode::DEVICE_DISABLED;
            break;
        case CAMERA_DEVICE_BUSY:
            err = CameraErrorCode::CONFILICT_CAMERA;
            break;
        case CAMERA_DEVICE_CLOSED:
            err = CameraErrorCode::DEVICE_DISABLED;
            break;
        case CAMERA_DEVICE_REQUEST_TIMEOUT:
            err = CameraErrorCode::SERVICE_FATL_ERROR;
            break;
        case CAMERA_STREAM_BUFFER_LOST:
            err = CameraErrorCode::SERVICE_FATL_ERROR;
            break;
        case CAMERA_INVALID_SESSION_CFG:
            err = CameraErrorCode::SERVICE_FATL_ERROR;
            break;
        case CAMERA_CAPTURE_LIMIT_EXCEED:
            err = CameraErrorCode::SERVICE_FATL_ERROR;
            break;
        case CAMERA_INVALID_STATE:
            err = CameraErrorCode::SERVICE_FATL_ERROR;
            break;
        case CAMERA_UNKNOWN_ERROR:
            err = CameraErrorCode::SERVICE_FATL_ERROR;
            break;
        case CAMERA_DEVICE_PREEMPTED:
            err = CameraErrorCode::SERVICE_FATL_ERROR;
            break;
        case CAMERA_OPERATION_NOT_ALLOWED:
            err = CameraErrorCode::OPERATION_NOT_ALLOWED;
            break;
        case IPC_PROXY_ERR:
        case IPC_PROXY_DEAD_OBJECT_ERR:
        case IPC_PROXY_NULL_INVOKER_ERR:
        case IPC_PROXY_TRANSACTION_ERR:
        case IPC_PROXY_INVALID_CODE_ERR:
        case IPC_STUB_ERR:
        case IPC_STUB_WRITE_PARCEL_ERR:
        case IPC_STUB_INVOKE_THREAD_ERR:
        case IPC_STUB_INVALID_DATA_ERR:
        case IPC_STUB_CURRENT_NULL_ERR:
        case IPC_STUB_UNKNOW_TRANS_ERR:
        case IPC_STUB_CREATE_BUS_SERVER_ERR:
            err = CameraErrorCode::SERVICE_FATL_ERROR;
            break;
        default:
            MEDIA_ERR_LOG("ServiceToCameraError() error code from service: %{public}d", ret);
            break;
    }
    return err;
}
} // namespace CameraStandard
} // namespace OHOS
