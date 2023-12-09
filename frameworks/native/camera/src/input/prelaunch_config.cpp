/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "input/prelaunch_config.h"

using namespace std;

namespace OHOS {
namespace CameraStandard {
PrelaunchConfig::PrelaunchConfig(sptr<CameraDevice> cameraDevice): cameraDevice_(cameraDevice) {}

sptr<CameraDevice> PrelaunchConfig::GetCameraDevice()
{
    return cameraDevice_;
}

RestoreParamType PrelaunchConfig::GetRestoreParamType()
{
    return restoreParamType;
}

int PrelaunchConfig::GetActiveTime()
{
    return activeTime;
}

SettingParam PrelaunchConfig::GetSettingParam()
{
    return settingParam;
}
}
}