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

#include "camera_manager_ani.h"
#include <array>
#include <ani.h>
#include "camera_log.h"


using namespace OHOS::CameraStandard;

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        MEDIA_ERR_LOG("Unsupported ANI_VERSION_1");
        return (ani_status)ANI_ERROR;
    }

    static const char *staticNsName = "L@ohos/multimedia/camera/camera;";

    ani_namespace staticNs;
    if (ANI_OK != env->FindNamespace(staticNsName, &staticNs)) {
        MEDIA_ERR_LOG("Not found %{public}s", staticNsName);
        return ANI_ERROR;
    }

    std::array staticMethods = {
        ani_native_function {"getCameraManager", nullptr,
            reinterpret_cast<void *>(CameraManagerAni::Constructor)},
    };

    if (ANI_OK != env->Namespace_BindNativeFunctions(staticNs, staticMethods.data(), staticMethods.size())) {
        MEDIA_ERR_LOG("Cannot bind native methods to %{public}s", staticNsName);
        return ANI_ERROR;
    };

    ani_status ret = CameraManagerAni::CameraManagerAniInit(env);
    if (ret != ANI_OK) {
        MEDIA_ERR_LOG("CameraManagerAniInit fail");
        return ret;
    }
    *result = ANI_VERSION_1;
    return ANI_OK;
}