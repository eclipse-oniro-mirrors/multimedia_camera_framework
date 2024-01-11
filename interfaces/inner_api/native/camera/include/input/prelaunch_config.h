/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef CAMERA_FRAMEWORK_PRELAUNCH_CONFIG_H
#define CAMERA_FRAMEWORK_PRELAUNCH_CONFIG_H

#include "input/camera_device.h"

namespace OHOS {
namespace CameraStandard {
enum RestoreParamType {
    NO_NEED_RESTORE_PARAM = 0,
    PERSISTENT_DEFAULT_PARAM = 1,
    TRANSIENT_ACTIVE_PARAM = 2,
};

struct SettingParam {
    int skinSmoothLevel;
    int faceSlender;
    int skinTone;
};

class PrelaunchConfig : public RefBase {
public:
    PrelaunchConfig(sptr<CameraDevice> cameraDevice);

    PrelaunchConfig() = default;

    virtual ~PrelaunchConfig() = default;

    /**
     * @brief Get CameraDevice of the PrelaunchConfig.
     *
     * @return cameraDevice.
     */
    sptr<CameraDevice> GetCameraDevice();

    RestoreParamType GetRestoreParamType();

    int GetActiveTime();

    SettingParam GetSettingParam();

    sptr<CameraDevice> cameraDevice_ = nullptr;

    SettingParam settingParam = {0, 0};

    int activeTime = 0;

    RestoreParamType  restoreParamType = RestoreParamType::NO_NEED_RESTORE_PARAM;
};
}
}
#endif // CAMERA_FRAMEWORK_PRELAUNCH_CONFIG_H
