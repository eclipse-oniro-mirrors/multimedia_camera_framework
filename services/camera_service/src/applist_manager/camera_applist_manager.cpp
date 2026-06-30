/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
// LCOV_EXCL_START
#include "applist_manager/camera_applist_manager.h"

#include <cstring>
#include <dlfcn.h>
#include <parameters.h>
#include "camera_util.h"
#include "display_manager_lite.h"

namespace OHOS {
namespace CameraStandard {
sptr<CameraApplistManager> CameraApplistManager::cameraApplistManager_;
std::mutex CameraApplistManager::instanceMutex_;

#ifdef COMPATIBILITY_CONFIG_CENTER_ENABLE
constexpr int32_t COMP_CONFIG_OK = 0;
constexpr char LOGIC_DEVICE[] = "logic_device";
const std::string COMPCONFIG_CLIENT_SO_PATH = "/system/lib64/platformsdk/libcompconfigclient.z.so";
constexpr char COMP_CONFIG_READ_UTIL_GET_CONFIG_BY_APP[] = "CompConfigReadUtil_GetConfigByApp";

typedef struct {
    const char* key;
    const char* value;
} CompConfigKvEntry;

typedef struct {
    int32_t ret;
    CompConfigKvEntry* entries;
    int32_t entryCount;
} CompConfigPropertyValueMapResult;

using CompConfigReadUtilGetConfigByAppFunc = CompConfigPropertyValueMapResult (*)(const char* bundleName);
#endif

sptr<CameraApplistManager> &CameraApplistManager::GetInstance()
{
    if (cameraApplistManager_ == nullptr) {
        std::unique_lock<std::mutex> lock(instanceMutex_);
        if (cameraApplistManager_ == nullptr) {
            MEDIA_INFO_LOG("Initializing cameraApplistManager instance");
            cameraApplistManager_ = new CameraApplistManager();
        }
    }
    return CameraApplistManager::cameraApplistManager_;
}

CameraApplistManager::CameraApplistManager()
{
    MEDIA_DEBUG_LOG("CameraApplistManager construct");
    bool isLogicCamera = system::GetParameter("const.system.sensor_correction_enable", "0") == "1";
    CHECK_EXECUTE(isLogicCamera, GetLogicCameraScreenStatus());
}

CameraApplistManager::~CameraApplistManager()
{
    MEDIA_DEBUG_LOG("CameraApplistManager::~CameraApplistManager");
#ifdef COMPATIBILITY_CONFIG_CENTER_ENABLE
    CHECK_RETURN(!handle_);
    dlclose(handle_);
    handle_ = nullptr;
#endif
}

int32_t CameraApplistManager::GetLogicCameraScreenStatus()
{
    std::string config = system::GetParameter("const.camera.support_logical_camera_screen_status", "");
    std::vector<std::string> elems = SplitString(config, ';');
    CHECK_RETURN_RET_ELOG(elems.empty(), CAMERA_INVALID_STATE, "GetLogicCameraScreenStatus elems is empty");
    for (const std::string& ele : elems) {
        CHECK_CONTINUE(ele.find(",") == std::string::npos);
        std::vector<std::string> subElems = SplitString(ele, ',');
        CHECK_RETURN_RET_ELOG((subElems.size() != SIZE_TWO) ||
            !(isIntegerRegex(subElems[0]) && isIntegerRegex(subElems[1])), CAMERA_INVALID_STATE,
            "GetLogicCameraScreenStatus subElems isIntegerRegex false");
        int32_t logicDisplayMode = std::stoi(subElems[0]);
        int32_t systemNaturalDirection = std::stoi(subElems[1]);
        displayModeToNaturalDirectionMap_[logicDisplayMode] = systemNaturalDirection;
        MEDIA_INFO_LOG("CameraApplistManager::GetLogicCameraScreenStatus logicDisplayMode: %{public}d, "
            "naturalDirection: %{public}d", logicDisplayMode, systemNaturalDirection);
    }
    return CAMERA_OK;
}

bool CameraApplistManager::Init()
{
#ifdef COMPATIBILITY_CONFIG_CENTER_ENABLE
    CHECK_RETURN_RET(initResult_, true);
    if (!handle_) {
        handle_ = ::dlopen(COMPCONFIG_CLIENT_SO_PATH.c_str(), RTLD_NOW);
        CHECK_RETURN_RET_ELOG(handle_ == nullptr, false, "CameraApplistManager::Init dlopen failed");
        initResult_ = true;
    }
#endif
    return initResult_;
}

#ifdef COMPATIBILITY_CONFIG_CENTER_ENABLE
std::shared_ptr<ApplistConfigure> CameraApplistManager::GetApplistConfigure(const std::string& bundleName)
{
    auto itr = applistConfigureMap_.find(bundleName);
    CHECK_RETURN_RET(itr != applistConfigureMap_.end(), itr->second);

    std::shared_ptr<ApplistConfigure> config = GetConfigureFromCompConfigRead(bundleName);
    applistConfigureMap_[bundleName] = config;
    return config;
}

std::shared_ptr<ApplistConfigure> CameraApplistManager::GetConfigureFromCompConfigRead(const std::string& bundleName)
{
    MEDIA_INFO_LOG("CameraApplistManager::GetConfigureFromCompConfigRead is Called");
    auto fnGetConfigByApp = GetFunction<CompConfigReadUtilGetConfigByAppFunc>(COMP_CONFIG_READ_UTIL_GET_CONFIG_BY_APP);
    CHECK_RETURN_RET_ELOG(fnGetConfigByApp == nullptr, nullptr,
        "CameraApplistManager::GetConfigureFromCompConfigRead GetFunction fnGetConfigByApp failed");
    auto appResult = fnGetConfigByApp(bundleName.c_str());
    CHECK_RETURN_RET_ELOG(appResult.ret != COMP_CONFIG_OK || !appResult.entryCount || appResult.entries == nullptr,
        nullptr, "CameraApplistManager::GetConfigureFromCompConfigRead GetConfigByApp failed");

    for (int i = 0; i < appResult.entryCount; ++i) {
        auto entry = appResult.entries[i];
        CHECK_RETURN_RET_ELOG(entry.key == nullptr || entry.value == nullptr, nullptr,
            "CameraApplistManager::GetConfigureFromCompConfigRead GetConfigByApp entry key or value is nullptr");
        CHECK_CONTINUE(strcmp(entry.key, LOGIC_DEVICE) != 0);
        MEDIA_INFO_LOG("CameraApplistManager::GetConfigureFromCompConfigRead bundleName: %{public}s, key: %{public}s, "
            "value: %{public}s", bundleName.c_str(), entry.key, entry.value);
        nlohmann::json whiteListJson = nlohmann::json::parse(entry.value, nullptr, false);
        CHECK_RETURN_RET_ELOG(whiteListJson.is_discarded(), nullptr,
            "CameraApplistManager::GetConfigureFromCompConfigRead json Parse Failed");
        return GetApplistConfigureFromJson(whiteListJson);
    }
    return nullptr;
}

std::shared_ptr<ApplistConfigure> CameraApplistManager::GetApplistConfigureFromJson(const nlohmann::json& json)
{
    CHECK_RETURN_RET_ELOG(json.is_null() || !json.is_object(), nullptr,
        "CameraApplistManager::GetApplistConfigureFromJson invalid json object");
    
    std::shared_ptr<ApplistConfigure> config = std::make_unique<ApplistConfigure>();
    std::map<int32_t, int32_t> useLogicCamera = {};
    if (json.contains(USE_LOGIC_CAMERA_STRING) && json[USE_LOGIC_CAMERA_STRING].is_object()) {
        for (const auto &[key, value] : json[USE_LOGIC_CAMERA_STRING].items()) {
            CHECK_CONTINUE(key.empty() || !isIntegerRegex(key) || !value.is_number_integer());
            useLogicCamera[std::stoi(key)] = value.get<int>();
        }
    }
    config->useLogicCamera = useLogicCamera;

    std::map<int32_t, int32_t> customLogicDirection = {};
    if (json.contains(CUSTOM_LOGIC_DIRECTION_STRING) && json[CUSTOM_LOGIC_DIRECTION_STRING].is_object()) {
        for (const auto &[key, value] : json[CUSTOM_LOGIC_DIRECTION_STRING].items()) {
            CHECK_CONTINUE(key.empty() || !isIntegerRegex(key) || !value.is_number_integer());
            customLogicDirection[std::stoi(key)] = value.get<int>();
        }
    }
    config->customLogicDirection = customLogicDirection;
    return config;
}
#endif

std::shared_ptr<ApplistConfigure> CameraApplistManager::GetConfigureByBundleName(const std::string& bundleName)
{
#ifdef COMPATIBILITY_CONFIG_CENTER_ENABLE
    CHECK_RETURN_RET_ELOG(bundleName.empty(), nullptr, "CameraApplistManager::GetConfigureByBundleName bundleName "
        "is empty");
    std::shared_ptr<ApplistConfigure> appConfigure = GetApplistConfigure(bundleName);
    MEDIA_INFO_LOG("CameraApplistManager::GetConfigureByBundleName BundleName: %{public}s", bundleName.c_str());
    return appConfigure;
#else
    return nullptr;
#endif
}

bool CameraApplistManager::GetNaturalDirectionCorrectByBundleName(const std::string& bundleName,
    bool& exemptNaturalDirectionCorrect)
{
#ifdef COMPATIBILITY_CONFIG_CENTER_ENABLE
    CHECK_RETURN_RET_ELOG(bundleName.empty(), false,
        "CameraApplistManager::GetNaturalDirectionCorrectByBundleName bundleName is empty");
    std::shared_ptr<ApplistConfigure> appConfigure = GetApplistConfigure(bundleName);
    CHECK_RETURN_RET_DLOG(appConfigure == nullptr, true,
        "CameraApplistManager::GetNaturalDirectionCorrectByBundleName appConfigure is nullptr");

    std::map<int32_t, int32_t> useLogicCamera = appConfigure->useLogicCamera;
    exemptNaturalDirectionCorrect = (!useLogicCamera.empty() &&
        (std::all_of(useLogicCamera.begin(), useLogicCamera.end(), [](const auto& pair) { return pair.second == 0; })));
    MEDIA_DEBUG_LOG("CameraApplistManager::GetNaturalDirectionCorrectByBundleName BundleName: %{public}s, "
        "exemptNaturalDirectionCorrect: %{public}d", bundleName.c_str(), exemptNaturalDirectionCorrect);
#endif
    return true;
}

void CameraApplistManager::GetCustomLogicDirection(const std::string& bundleName,
    int32_t& customLogicDirection)
{
#ifdef COMPATIBILITY_CONFIG_CENTER_ENABLE
    auto displayMode = static_cast<int32_t>(OHOS::Rosen::DisplayManagerLite::GetInstance().GetFoldDisplayMode());
    CHECK_RETURN_ELOG(bundleName.empty(), "CameraApplistManager::GetCustomLogicDirection bundleName is empty");
    std::shared_ptr<ApplistConfigure> appConfigure = GetApplistConfigure(bundleName);
    CHECK_RETURN_DLOG(appConfigure == nullptr, "CameraApplistManager::GetCustomLogicDirection appConfigure is nullptr");
    
    auto innerLogicDirection = appConfigure->customLogicDirection;
    CHECK_RETURN_DLOG(innerLogicDirection.empty(),
        "CameraApplistManager::GetCustomLogicDirection customLogicDirection is empty");
    auto item = innerLogicDirection.find(displayMode);
    CHECK_RETURN_DLOG(item == innerLogicDirection.end(),
        "CameraApplistManager::GetCustomLogicDirection naturalDirection is Normal");
    customLogicDirection = item->second;
    MEDIA_DEBUG_LOG("CameraApplistManager::GetCustomLogicDirection BundleName: %{public}s, displayMode: %{public}d, "
        "customLogicDirection: %{public}d", bundleName.c_str(), displayMode, customLogicDirection);
#endif
}

void CameraApplistManager::GetAppNaturalDirectionByBundleName(const std::string& bundleName,
    int32_t& naturalDirection)
{
#ifdef COMPATIBILITY_CONFIG_CENTER_ENABLE
    naturalDirection = 0;
    auto displayMode = static_cast<int32_t>(OHOS::Rosen::DisplayManagerLite::GetInstance().GetFoldDisplayMode());
    if (!displayModeToNaturalDirectionMap_.empty()) {
        auto item = displayModeToNaturalDirectionMap_.find(displayMode);
        CHECK_EXECUTE(item != displayModeToNaturalDirectionMap_.end(), naturalDirection = item->second);
        MEDIA_DEBUG_LOG("CameraApplistManager::GetAppNaturalDirectionByBundleName default naturalDirection: %{public}d",
            naturalDirection);
    }
    CHECK_RETURN_ELOG(bundleName.empty(),
        "CameraApplistManager::GetAppNaturalDirectionByBundleName bundleName is empty");
    std::shared_ptr<ApplistConfigure> appConfigure = GetApplistConfigure(bundleName);
    CHECK_RETURN_DLOG(appConfigure == nullptr,
        "CameraApplistManager::GetAppNaturalDirectionByBundleName appConfigure is nullptr");

    std::map<int32_t, int32_t> useLogicCamera = appConfigure->useLogicCamera;
    bool isCorrect = (!useLogicCamera.empty() &&
        (std::all_of(useLogicCamera.begin(), useLogicCamera.end(), [](const auto& pair) { return pair.second == 0; })));
    CHECK_RETURN(isCorrect);

    auto customLogicDirection = appConfigure->customLogicDirection;
    CHECK_RETURN_DLOG(customLogicDirection.empty(),
        "CameraApplistManager::GetAppNaturalDirectionByBundleName customLogicDirection is empty");
    auto item = customLogicDirection.find(displayMode);
    CHECK_RETURN_DLOG(item == customLogicDirection.end(),
        "CameraApplistManager::GetAppNaturalDirectionByBundleName naturalDirection is Normal");
    naturalDirection = (naturalDirection + item->second) % SIZE_FOUR;
    MEDIA_DEBUG_LOG("CameraApplistManager::GetAppNaturalDirectionByBundleName BundleName: %{public}s, "
        "displayMode: %{public}d, naturalDirection: %{public}d", bundleName.c_str(), displayMode, naturalDirection);
#endif
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP
