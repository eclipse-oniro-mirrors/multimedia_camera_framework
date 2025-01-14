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

#ifndef CAMERA_ERROR_H
#define CAMERA_ERROR_H

#include <string>
#include "errors.h"

namespace OHOS {
namespace CameraStandard {
namespace CameraError {
constexpr ErrCode NO_ERROR = 0;

constexpr ErrCode INVALID_PARAM = 7400101;
constexpr ErrCode INVALID_OPTION = 7400102;
constexpr ErrCode SESSION_NOT_CONFIG = 7400103;
constexpr ErrCode SESSION_NOT_RUNNING = 7400104;
constexpr ErrCode SESSION_CONFIG_LOCKED = 7400105;
constexpr ErrCode DEVICE_SETTING_LOCKED = 7400106;
constexpr ErrCode CAMERA_CONFLICT = 7400107;
constexpr ErrCode SECURITY_DISABLED = 7400108;
constexpr ErrCode CAMERA_PREEMPED = 7400109;
constexpr ErrCode CONFLICT_WITH_CURRENT = 7400110;
constexpr ErrCode CAMERA_SERVICE_ERROR = 7400201;
} // namespace CameraError
} // namespace CameraStandard
} // namespace OHOS
#endif