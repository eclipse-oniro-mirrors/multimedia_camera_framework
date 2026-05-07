/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "camera_display_plugin.h"
#include <sys/stat.h>
#include <unistd.h>
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
const std::string DISPLAY_PLUGIN_SO_PATH = "/system/lib64/module/hms/carservice/libcamera_display_impl.z.so";

sptr<CameraDisplayPlugin> CameraDisplayPlugin::GetInstance()
{
    static sptr<CameraDisplayPlugin> instance = new CameraDisplayPlugin();
    return instance;
}

CameraDisplayPlugin::CameraDisplayPlugin()
{
    MEDIA_DEBUG_LOG("CameraDisplayPlugin construct");
}

CameraDisplayPlugin::~CameraDisplayPlugin()
{
    UnLoadSo();
    MEDIA_DEBUG_LOG("CameraDisplayPlugin destruct");
}

bool CameraDisplayPlugin::LoadSo()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_RETURN_RET_DLOG(handle_, true, "CameraDisplayPlugin: so already loaded");
    CHECK_RETURN_RET_DLOG(!CheckSoExists(DISPLAY_PLUGIN_SO_PATH), false, "CameraDisplayPlugin: so file does not exist");
    handle_ = ::dlopen(DISPLAY_PLUGIN_SO_PATH.c_str(), RTLD_NOW);
    CHECK_RETURN_RET_ELOG(!handle_, false, "CameraDisplayPlugin: Failed to load so, error: %{public}s", dlerror());
    MEDIA_DEBUG_LOG("CameraDisplayPlugin: Successfully loaded so");
    return true;
}

void CameraDisplayPlugin::UnLoadSo()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_RETURN_DLOG(!handle_, "CameraDisplayPlugin: so not loaded, nothing to unload");
    if (dlclose(handle_) != 0) {
        MEDIA_ERR_LOG("CameraDisplayPlugin: Failed to unload so, error: %{public}s", dlerror());
    }
    handle_ = nullptr;
}

void* CameraDisplayPlugin::GetFunction(const std::string& functionName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_RETURN_RET_DLOG(!handle_, nullptr, "CameraDisplayPlugin: so not loaded");

    dlerror();
    void* funcInstance = dlsym(handle_, functionName.c_str());
    CHECK_RETURN_RET_ELOG(!funcInstance, nullptr,
        "CameraDisplayPlugin: Failed to get function: %{public}s, error: %{public}s", functionName.c_str(), dlerror());
    MEDIA_DEBUG_LOG("CameraDisplayPlugin: Successfully got function: %{public}s", functionName.c_str());
    return funcInstance;
}

bool CameraDisplayPlugin::CheckSoExists(const std::string& soPath) const
{
    struct stat buffer;
    return (stat(soPath.c_str(), &buffer) == 0) && (buffer.st_mode & S_IRUSR);
}
}
}