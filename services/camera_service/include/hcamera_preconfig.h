/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_H_PRECONFIG_H
#define OHOS_CAMERA_H_PRECONFIG_H

#include "camera_info_dumper.h"
#include "hcamera_host_manager.h"

namespace OHOS {
namespace CameraStandard {
class HCameraHostManager;
void DumpPreconfigInfo(CameraInfoDumper& infoDumper, sptr<HCameraHostManager>& hostManager);
} // namespace CameraStandard
} // namespace OHOS
#endif