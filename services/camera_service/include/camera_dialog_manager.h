/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef CAMERA_DIALOG_MANAGER_H
#define CAMERA_DIALOG_MANAGER_H

#include "ability_connection.h"
#include "camera_log.h"
#include "camera_dialog_connection.h"

namespace OHOS {
namespace CameraStandard {

class NoFrontCameraDialog {
public:
    static std::shared_ptr<NoFrontCameraDialog> GetInstance();

    void DisconnectAbilityForDialog();
    void SetConnection(sptr<NoFrontCameraAbilityConnection> connection);
    void ShowCameraDialog();

    static std::mutex mutex_;
    std::mutex connectMutex_;
    static std::shared_ptr<NoFrontCameraDialog> instance_;
    sptr<NoFrontCameraAbilityConnection> connection_;
};
} // namespace CameraStandard
} // namespace OHOS

#endif // DEVICE_PROTECTION_ABILITY_CONNECTION_H