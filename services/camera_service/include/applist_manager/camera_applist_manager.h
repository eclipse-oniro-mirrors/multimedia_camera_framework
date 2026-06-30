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

#ifndef CAMERA_APPLIST_MANAGER_H
#define CAMERA_APPLIST_MANAGER_H

#include <mutex>
#include <nlohmann/json.hpp>
#include "safe_map.h"
#include "camera_log.h"
#include "datashare_helper.h"
#include "data_ability_observer_stub.h"

namespace OHOS {
namespace CameraStandard {
static const std::string USE_LOGIC_CAMERA_STRING = "useLogicCamera";
static const std::string CUSTOM_LOGIC_DIRECTION_STRING = "customLogicDirection";

struct ApplistConfigure {
    std::string bundleName;
    std::map<int32_t, int32_t> useLogicCamera;
    std::map<int32_t, int32_t> customLogicDirection;
};

class CameraApplistManager : public RefBase {
public:
    static sptr<CameraApplistManager> &GetInstance();
    ~CameraApplistManager();
    bool Init();
    std::shared_ptr<ApplistConfigure> GetConfigureByBundleName(const std::string& bundleName);
    bool GetNaturalDirectionCorrectByBundleName(const std::string& bundleName,
        bool& exemptNaturalDirectionCorrect);
    void GetCustomLogicDirection(const std::string& bundleName, int32_t& customLogicDirection);
    void GetAppNaturalDirectionByBundleName(const std::string& bundleName, int32_t& naturalDirection);

private:
    CameraApplistManager();

    int32_t GetLogicCameraScreenStatus();

#ifdef COMPATIBILITY_CONFIG_CENTER_ENABLE
    std::shared_ptr<ApplistConfigure> GetApplistConfigure(const std::string& bundleName);
    std::shared_ptr<ApplistConfigure> GetConfigureFromCompConfigRead(const std::string& bundleName);
    std::shared_ptr<ApplistConfigure> GetApplistConfigureFromJson(const nlohmann::json& json);

    template<typename Fn>
    Fn GetFunction(const std::string& functionName)
    {
        CHECK_EXECUTE(!initResult_, Init());
        CHECK_RETURN_RET_ELOG(!initResult_ || handle_ == nullptr, nullptr,
            "CameraApplistManager::GetFunction Init failed, function: %{public}s", functionName.c_str());
        void* func = nullptr;
        CHECK_RETURN_RET(functionMap_.Find(functionName, func), reinterpret_cast<Fn>(func));

        func = dlsym(handle_, functionName.c_str());
        CHECK_RETURN_RET_DLOG(func == nullptr, nullptr,
            "CameraApplistManager::GetFunction function %{public}s not found", functionName.c_str());
        functionMap_.EnsureInsert(functionName, func);
        return reinterpret_cast<Fn>(func);
    }
#endif

private:
    static sptr<CameraApplistManager> cameraApplistManager_;
    std::map<int32_t, int32_t> displayModeToNaturalDirectionMap_;
    std::map<std::string, std::shared_ptr<ApplistConfigure>> applistConfigureMap_;

    std::atomic<bool> initResult_ = false;
    static std::mutex instanceMutex_;

#ifdef COMPATIBILITY_CONFIG_CENTER_ENABLE
    void *handle_ = nullptr;
    SafeMap<std::string, void*> functionMap_;
#endif
};
} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_APPLIST_MANAGER_H
