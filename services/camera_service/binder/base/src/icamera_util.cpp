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
            err = CameraErrorCode::CONFLICT_CAMERA;
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
            err = CameraErrorCode::DEVICE_PREEMPTED;
            break;
        case CAMERA_OPERATION_NOT_ALLOWED:
            err = CameraErrorCode::OPERATION_NOT_ALLOWED;
            break;
        case CAMERA_DEVICE_ERROR:
            err = CameraErrorCode::OPERATION_NOT_ALLOWED;
            break;
        case CAMERA_NO_PERMISSION:
            err = CameraErrorCode::OPERATION_NOT_ALLOWED;
            break;
        case CAMERA_DEVICE_CONFLICT:
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
        case CAMERA_DEVICE_SWITCH_FREQUENT:
            err = CameraErrorCode::DEVICE_SWITCH_FREQUENT;
            break;
        case CAMERA_DEVICE_LENS_RETRACTED:
            err = CameraErrorCode::CAMERA_LENS_RETRACTED;
            break;
        case CAMERA_UNSUPPORTED_COMBINATION:
            err = CameraErrorCode::UNSUPPORTED_MULTI_CAMERA_COMBINATION;
            break;
        default:
            MEDIA_ERR_LOG("ServiceToCameraError() error code from service: %{public}d", ret);
            break;
    }
    return err;
}


static const std::unordered_map<int32_t, int32_t> ServiceToCameraErrorrMap = {
    {CAMERA_OK, 0},
    {CAMERA_ALLOC_ERROR, CameraErrorCode::SERVICE_FATL_ERROR_OF_ALLOC},
    {CAMERA_INVALID_ARG, CameraErrorCode::SERVICE_FATL_ERROR},
    {CAMERA_UNSUPPORTED, CameraErrorCode::DEVICE_DISABLED},
    {CAMERA_DEVICE_BUSY, CameraErrorCode::CONFLICT_CAMERA},
    {CAMERA_DEVICE_CLOSED, CameraErrorCode::DEVICE_DISABLED},
    {CAMERA_DEVICE_REQUEST_TIMEOUT, CameraErrorCode::SERVICE_FATL_ERROR},
    {CAMERA_STREAM_BUFFER_LOST, CameraErrorCode::SERVICE_FATL_ERROR},
    {CAMERA_INVALID_SESSION_CFG, CameraErrorCode::SERVICE_FATL_ERROR_OF_INVALID_SESSION_CFG},
    {CAMERA_CAPTURE_LIMIT_EXCEED, CameraErrorCode::SERVICE_FATL_ERROR},
    {CAMERA_INVALID_STATE, CameraErrorCode::SERVICE_FATL_ERROR},
    {CAMERA_UNKNOWN_ERROR, CameraErrorCode::SERVICE_FATL_ERROR},
    {CAMERA_SERVICE_NULL, CameraErrorCode::SERVICE_FATL_ERROR_OF_SERVICE_NULL},
    {CAMERA_DEVICE_PREEMPTED, CameraErrorCode::DEVICE_PREEMPTED},
    {CAMERA_OPERATION_NOT_ALLOWED, CameraErrorCode::OPERATION_NOT_ALLOWED},
    {CAMERA_DEVICE_ERROR, CameraErrorCode::OPERATION_NOT_ALLOWED},
    {CAMERA_NO_PERMISSION, CameraErrorCode::OPERATION_NOT_ALLOWED},
    {CAMERA_DEVICE_CONFLICT, CameraErrorCode::OPERATION_NOT_ALLOWED_OF_DEVICE_CONFLICT},
    {CAMERA_DEVICE_CONFLICT, CameraErrorCode::OPERATION_NOT_ALLOWED},
    {CAMERA_DEVICE_SWITCH_FREQUENT, CameraErrorCode::DEVICE_SWITCH_FREQUENT},
    {CAMERA_DEVICE_LENS_RETRACTED, CameraErrorCode::CAMERA_LENS_RETRACTED},
    {CAMERA_UNSUPPORTED_COMBINATION, CameraErrorCode::UNSUPPORTED_MULTI_CAMERA_COMBINATION},
    
    // IPC错误组
    {IPC_PROXY_ERR, CameraErrorCode::SERVICE_FATL_ERROR},
    {IPC_PROXY_DEAD_OBJECT_ERR, CameraErrorCode::SERVICE_FATL_ERROR},
    {IPC_PROXY_NULL_INVOKER_ERR, CameraErrorCode::SERVICE_FATL_ERROR},
    {IPC_PROXY_TRANSACTION_ERR, CameraErrorCode::SERVICE_FATL_ERROR},
    {IPC_PROXY_INVALID_CODE_ERR, CameraErrorCode::SERVICE_FATL_ERROR},
    {IPC_STUB_ERR, CameraErrorCode::SERVICE_FATL_ERROR},
    {IPC_STUB_WRITE_PARCEL_ERR, CameraErrorCode::SERVICE_FATL_ERROR},
    {IPC_STUB_INVOKE_THREAD_ERR, CameraErrorCode::SERVICE_FATL_ERROR},
    {IPC_STUB_INVALID_DATA_ERR, CameraErrorCode::SERVICE_FATL_ERROR},
    {IPC_STUB_CURRENT_NULL_ERR, CameraErrorCode::SERVICE_FATL_ERROR},
    {IPC_STUB_UNKNOW_TRANS_ERR, CameraErrorCode::SERVICE_FATL_ERROR},
    {IPC_STUB_CREATE_BUS_SERVER_ERR, CameraErrorCode::SERVICE_FATL_ERROR}
};

int32_t ServiceToCameraErrorV2(int32_t ret)
{
    auto it = ServiceToCameraErrorrMap.find(ret);
    if (it != ServiceToCameraErrorrMap.end()) {
        return it->second;
    }
    MEDIA_ERR_LOG("ServiceToCameraError() error code from service: %{public}d", ret);
    return CameraErrorCode::SERVICE_FATL_ERROR;
}
} // namespace CameraStandard
} // namespace OHOS
