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

#ifndef CAMERA_ERROR_CODE_H
#define CAMERA_ERROR_CODE_H

#include <cstdint>
namespace OHOS {
namespace CameraStandard {
/**
 * @brief Camera device remote request code for IPC.
 *
 * @since 1.0
 * @version 1.0
 */
enum CameraErrorCode : int32_t {
    SUCCESS = 0,
    NO_SYSTEM_APP_PERMISSION = 202,
    PARAMETER_ERROR = 401,
    INVALID_ARGUMENT = 7400101,
    OPERATION_NOT_ALLOWED = 7400102,
    SESSION_NOT_CONFIG = 7400103,
    SESSION_NOT_RUNNING = 7400104,
    SESSION_CONFIG_LOCKED = 7400105,
    DEVICE_SETTING_LOCKED = 7400106,
    CONFLICT_CAMERA = 7400107,
    DEVICE_DISABLED = 7400108,
    DEVICE_PREEMPTED = 7400109,
    UNRESOLVED_CONFLICTS_BETWEEN_STREAMS = 7400110,
    DEVICE_SWITCH_FREQUENT = 7400111,
    CAMERA_LENS_RETRACTED = 7400112,
    SERVICE_FATL_ERROR = 7400201
};
} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_ERROR_CODE_H
