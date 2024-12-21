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

#include <dlfcn.h>
#include "camera_log.h"
#include "camera_dynamic_loader.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
const char *librarySuffix = ".so";
std::unique_ptr<CameraDynamicLoader> CameraDynamicLoader::instance = nullptr;
std::once_flag CameraDynamicLoader::onceFlag;
CameraDynamicLoader::CameraDynamicLoader()
{
    MEDIA_INFO_LOG("CameraDynamicLoader ctor");
}

CameraDynamicLoader::~CameraDynamicLoader()
{
    MEDIA_INFO_LOG("CameraDynamicLoader dtor");
    for (auto iterator = dynamicLibHandle_.begin(); iterator != dynamicLibHandle_.end(); ++iterator) {
        dlclose(iterator->second);
        MEDIA_INFO_LOG("close library camera_dynamic success: %{public}s", iterator->first.c_str());
    }
}

void* CameraDynamicLoader::OpenDynamicHandle(std::string dynamicLibrary)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard loaderLock(libLock_);
    if (!EndsWith(dynamicLibrary, librarySuffix)) {
        MEDIA_ERR_LOG("CloseDynamicHandle with error name!");
        return nullptr;
    }
    if (dynamicLibHandle_[dynamicLibrary] == nullptr) {
        void* dynamicLibHandle = dlopen(dynamicLibrary.c_str(), RTLD_NOW);
        if (dynamicLibHandle == nullptr) {
            MEDIA_ERR_LOG("Failed to open %{public}s, reason: %{public}sn", dynamicLibrary.c_str(), dlerror());
            return nullptr;
        }
        MEDIA_INFO_LOG("open library %{public}s success", dynamicLibrary.c_str());
        dynamicLibHandle_[dynamicLibrary] = dynamicLibHandle;
    }
    return dynamicLibHandle_[dynamicLibrary];
}

void* CameraDynamicLoader::GetFunction(std::string dynamicLibrary, std::string function)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard loaderLock(libLock_);
    // if not opened, then open directly
    if (dynamicLibHandle_[dynamicLibrary] == nullptr) {
        OpenDynamicHandle(dynamicLibrary);
    }

    void* handle = nullptr;
    if (dynamicLibHandle_[dynamicLibrary] != nullptr) {
        handle = dlsym(dynamicLibHandle_[dynamicLibrary], function.c_str());
        if (handle == nullptr) {
            MEDIA_ERR_LOG("Failed to load %{public}s, reason: %{public}sn", function.c_str(), dlerror());
            return nullptr;
        }
        MEDIA_INFO_LOG("GetFunction %{public}s success", function.c_str());
    }
    return handle;
}

void CameraDynamicLoader::CloseDynamicHandle(std::string dynamicLibrary)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard loaderLock(libLock_);
    if (!EndsWith(dynamicLibrary, librarySuffix)) {
        MEDIA_ERR_LOG("CloseDynamicHandle with error name!");
        return;
    }
    if (dynamicLibHandle_[dynamicLibrary] != nullptr) {
        dlclose(dynamicLibHandle_[dynamicLibrary]);
        dynamicLibHandle_[dynamicLibrary] = nullptr;
        MEDIA_INFO_LOG("close library camera_dynamic success: %{public}s", dynamicLibrary.c_str());
    }
}
}  // namespace Camera
}  // namespace OHOS