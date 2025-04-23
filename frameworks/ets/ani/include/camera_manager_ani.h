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
#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_CAMERA_MANAGER_ANI_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_CAMERA_MANAGER_ANI_H

#include <memory>
#include <vector>

#include <ani.h>
#include "input/camera_manager.h"


namespace OHOS {
namespace CameraStandard {

class CameraManagerAni {
public:
    CameraManagerAni();
    ~CameraManagerAni();
    static ani_status CameraManagerAniInit(ani_env *env);
    static ani_object Constructor([[maybe_unused]] ani_env *env, ani_object context);
    static CameraManagerAni* Unwrap(ani_env *env, ani_object object);
    static ani_ref PrelaunchCamera([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object);
private:
    ani_env *env_;
    sptr<CameraManager> cameraManager_;
};
} // namespace CameraStandard
} // namespace OHOS

#endif // FRAMEWORKS_ANI_SRC_INCLUDE_CAMERA_MANAGER_ANI_H