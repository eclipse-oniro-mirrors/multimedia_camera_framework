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
#include <ani.h>
#include <iostream>
#include <array>

#include "camera_manager_ani.h"
#include "camera_log.h"
#include "camera_utils_ani.h"
#include "camera_security_utils_ani.h"

using namespace std;

namespace OHOS {
namespace CameraStandard {

CameraManagerAni::CameraManagerAni() {}
CameraManagerAni::~CameraManagerAni() {}

ani_status CameraManagerAni::CameraManagerAniInit(ani_env *env)
{
    static const char *className = "L@ohos/multimedia/camera/camera/CameraManagerHandle;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        MEDIA_ERR_LOG("Failed to find class: %{public}s", className);
        return (ani_status)ANI_ERROR;
    }

    std::array methods = {
        ani_native_function {"prelaunch", nullptr, reinterpret_cast<void *>(PrelaunchCamera) },
    };

    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        MEDIA_ERR_LOG("Failed to bind native methods to: %{public}s", className);
        return (ani_status)ANI_ERROR;
    };
    return ANI_OK;
}

ani_object CameraManagerAni::Constructor([[maybe_unused]] ani_env *env, ani_object context)
{
    auto nativeCameraManager = std::make_unique<CameraManagerAni>();
    nativeCameraManager->env_ = env;
    nativeCameraManager->cameraManager_ = CameraManager::GetInstance();
    if (nativeCameraManager->cameraManager_ == nullptr) {
        MEDIA_ERR_LOG("Failure wrapping js to native, nativeCameraManager->cameraManager_ null");
        ani_object nullobj = nullptr;
        return nullobj;
    }
    
    static const char *className = "L@ohos/multimedia/camera/camera/CameraManagerHandle;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        MEDIA_ERR_LOG("Failed to find class: %{public}s", className);
        ani_object nullobj = nullptr;
        return nullobj;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor)) {
        MEDIA_ERR_LOG("Failed to find method: %{public}s", "ctor");
        ani_object nullobj = nullptr;
        return nullobj;
    }

    ani_object nativeHandle;
    if (ANI_OK !=env->Object_New(cls, ctor, &nativeHandle, reinterpret_cast<ani_long>(nativeCameraManager.release()))) {
        MEDIA_ERR_LOG("New Media Fail");
    }
    return nativeHandle;
}

CameraManagerAni* CameraManagerAni::Unwrap(ani_env *env, ani_object object)
{
    ani_long nativeCameraManager;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativeCameraManager", &nativeCameraManager)) {
        return nullptr;
    }
    return reinterpret_cast<CameraManagerAni*>(nativeCameraManager);
}

ani_ref CameraManagerAni::PrelaunchCamera([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object)
{
    if (!CameraAniSecurity::CheckSystemApp(env)) {
        MEDIA_ERR_LOG("SystemApi PrelaunchCamera is called!");
        return nullptr;
    }
    ani_ref result = nullptr;
    int32_t retCode = CameraManager::GetInstance()->PrelaunchCamera();
    if (!CameraUtilsAni::CheckError(env, retCode)) {
        return result;
    }
    MEDIA_INFO_LOG("PrelaunchCamera");
    env->GetUndefined(&result);
    return result;
}
} // namespace CameraStandard
} // namespace OHOS