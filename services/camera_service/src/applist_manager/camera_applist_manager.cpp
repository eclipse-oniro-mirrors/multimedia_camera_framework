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

#include <parameters.h>

#include "camera_log.h"
#include "camera_util.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "display_manager_lite.h"

namespace OHOS {
namespace CameraStandard {
sptr<CameraApplistManager> CameraApplistManager::cameraApplistManager_;

std::mutex CameraApplistManager::instanceMutex_;

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
    isLogicCamera_ = system::GetParameter("const.system.sensor_correction_enable", "0") == "1";
    foldScreenType_ = system::GetParameter("const.window.foldscreen.type", "");
    CHECK_EXECUTE(!foldScreenType_.empty() && foldScreenType_[0] == '6', uriForWhiteList_ = COMPATIBLE_APP_STRATEGY);
    if (!foldScreenType_.empty() && foldScreenType_[0] == '7') {
        uriForWhiteList_ = APP_LOGICAL_DEVICE_CONFIGURATION;
        GetLogicCameraScreenStatus();
    }
    MEDIA_INFO_LOG("CameraApplistManager construct");
}

CameraApplistManager::~CameraApplistManager()
{
    ClearApplistManager();
    UnregisterCameraApplistManagerObserver();
    MEDIA_INFO_LOG("CameraApplistManager::~CameraApplistManager");
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
    CHECK_EXECUTE(!registerResult_, registerResult_ = RegisterCameraApplistManagerObserver());
    CHECK_EXECUTE(!initResult_, initResult_ = GetApplistConfigure());
    CHECK_RETURN_RET(registerResult_ && initResult_, true);
    return false;
}

std::shared_ptr<DataShare::DataShareHelper> CameraApplistManager::CreateCameraDataShareHelper()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_RET_ELOG(samgr == nullptr, nullptr, "CameraApplistManager GetSystemAbilityManager failed.");
    sptr<IRemoteObject> remoteObj = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_RET_ELOG(remoteObj == nullptr, nullptr, "CameraApplistManager GetSystemAbility Service Failed.");
    return DataShare::DataShareHelper::Creator(remoteObj, SETTING_URI_PROXY, SETTINGS_DATA_EXTRA_URI);
}

bool CameraApplistManager::RegisterCameraApplistManagerObserver()
{
    MEDIA_INFO_LOG("CameraApplistManager::RegisterCameraApplistManagerObserver is called");
    auto dataShareHelper = CreateCameraDataShareHelper();
    CHECK_RETURN_RET_ELOG(dataShareHelper == nullptr, false,
        "CameraApplistManager::RegisterCameraApplistManagerObserver DataShareHelper is nullptr");
    std::string uriApplistStr = SETTING_URI_PROXY + SETTINGS_DATA_KEY_URI + uriForWhiteList_;
    int ret = dataShareHelper->RegisterObserver(Uri(uriApplistStr), this);
    dataShareHelper->Release();
    CHECK_RETURN_RET_ELOG(ret != DataShare::E_OK, false,
        "CameraApplistManager::RegisterCameraApplistManagerObserver Failed");
    return true;
}

void CameraApplistManager::UnregisterCameraApplistManagerObserver()
{
    MEDIA_INFO_LOG("CameraApplistManager::UnregisterCameraApplistManagerObserver is called");
    auto dataShareHelper = CreateCameraDataShareHelper();
    CHECK_RETURN_ELOG(dataShareHelper == nullptr,
        "CameraApplistManager::RegisterCameraApplistManagerObserver DataShareHelper is nullptr");
    std::string uriApplistStr = SETTING_URI_PROXY + SETTINGS_DATA_KEY_URI + uriForWhiteList_;
    int ret = dataShareHelper->UnregisterObserver(Uri(uriApplistStr), this);
    dataShareHelper->Release();
    CHECK_RETURN_ELOG(ret != DataShare::E_OK,
        "CameraApplistManager::UnregisterCameraApplistManagerObserver Failed");
}

bool CameraApplistManager::GetApplistConfigure()
{
    ClearApplistManager();
    std::string jsonStr;
    auto dataShareHelper = CreateCameraDataShareHelper();
    CHECK_RETURN_RET_ELOG(dataShareHelper == nullptr, false,
        "CameraApplistManager::GetApplistConfigure dataShareHelper is nullptr");
    std::string uriApplistStr = SETTING_URI_PROXY + SETTINGS_DATA_KEY_URI + uriForWhiteList_;
    Uri uri(uriApplistStr);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_DATA_COLUMN_KEYWORD, uriForWhiteList_);
    std::vector<std::string> columns = { SETTINGS_DATA_COLUMN_VALUE };
    auto resultSet = dataShareHelper->Query(uri, predicates, columns);
    CHECK_RETURN_RET_ELOG(resultSet == nullptr, false,
        "CameraApplistManager::GetApplistConfigure dataShareHelper Query failed");

    int32_t count = 0;
    resultSet->GetRowCount(count);
    if (count == 0) {
        MEDIA_ERR_LOG("CameraApplistManager::GetApplistConfigure DataShareHelper query none result");
        resultSet->Close();
        dataShareHelper->Release();
        return false;
    }

    resultSet->GoToRow(0);
    int32_t ret = resultSet->GetString(0, jsonStr);
    if (ret != DataShare::E_OK) {
        MEDIA_ERR_LOG("CameraApplistManager::GetApplistConfigure DataShareHelper query result GetString failed, "
            "ret: %{public}d", ret);
        resultSet->Close();
        dataShareHelper->Release();
        return false;
    }
    resultSet->Close();
    dataShareHelper->Release();

    ParseApplistConfigureJsonStr(jsonStr);
    return true;
}

void CameraApplistManager::ParseApplistConfigureJsonStr(const std::string& cfgJsonStr)
{
    nlohmann::json jsonParsed = nlohmann::json::parse(cfgJsonStr, nullptr, false);
    CHECK_RETURN_ELOG(jsonParsed.is_discarded(), "CameraApplistManager::ParseApplistConfigureJsonStr Parse Failed");

    std::lock_guard<std::mutex> lock(applistConfigureMutex_);
    for (auto& [bundleName, info] : jsonParsed.items()) {
        ApplistConfigure appConfigure;
        appConfigure.bundleName = bundleName;

        bool flag = info.contains("exemptNaturalDirectionCorrect") &&
            info["exemptNaturalDirectionCorrect"].is_boolean();
        appConfigure.exemptNaturalDirectionCorrect = flag ? info["exemptNaturalDirectionCorrect"].get<bool>() : false;

        std::map<int32_t, int32_t> useLogicCamera = {};
        if (info.contains("useLogicCamera") && info["useLogicCamera"].is_object()) {
            for (const auto &[key, value] : info["useLogicCamera"].items()) {
                CHECK_CONTINUE(key.empty() || !isIntegerRegex(key) || !value.is_number_integer());
                useLogicCamera[std::stoi(key)] = value.get<int>();
            }
        }
        appConfigure.useLogicCamera = useLogicCamera;

        std::map<int32_t, int32_t> customLogicDirection = {};
        if (info.contains("customLogicDirection") && info["customLogicDirection"].is_object()) {
            for (const auto &[key, value] : info["customLogicDirection"].items()) {
                CHECK_CONTINUE(key.empty() || !isIntegerRegex(key) || !value.is_number_integer());
                customLogicDirection[std::stoi(key)] = value.get<int>();
            }
        }
        appConfigure.customLogicDirection = customLogicDirection;

        UpdateApplistConfigure(appConfigure);
    }
    MEDIA_INFO_LOG("CameraApplistManager::ParseApplistConfigureJsonStr Success");
}

void CameraApplistManager::UpdateApplistConfigure(const ApplistConfigure& appConfigure)
{
    auto item = applistConfigures_.find(appConfigure.bundleName);
    if (item != applistConfigures_.end()) {
        *(item->second) = appConfigure;
    } else {
        ApplistConfigure* applistConfigure = new (std::nothrow) ApplistConfigure(appConfigure);
        CHECK_RETURN_ELOG(applistConfigure == nullptr,
            "CameraApplistManager::UpdateApplistConfigure Alloc ApplistConfigure failed");
        applistConfigures_.emplace(applistConfigure->bundleName, applistConfigure);
    }
}

void CameraApplistManager::OnChange()
{
    MEDIA_INFO_LOG("CameraApplistManager::OnChange is called");
    GetApplistConfigure();
}

void CameraApplistManager::ClearApplistManager()
{
    std::lock_guard<std::mutex> lock(applistConfigureMutex_);
    for (auto& [key, appCfg] : applistConfigures_) {
        delete appCfg;
    }
    applistConfigures_.clear();
}

ApplistConfigure* CameraApplistManager::GetConfigureByBundleName(const std::string& bundleName)
{
    CHECK_RETURN_RET_ELOG(bundleName.empty(), nullptr, "CameraApplistManager::GetConfigureByBundleName bundleName "
        "is empty");
    CHECK_EXECUTE(!initResult_ || !registerResult_, Init());
    ApplistConfigure* appConfigure = nullptr;
    {
        std::lock_guard<std::mutex> lock(applistConfigureMutex_);
        auto item = applistConfigures_.find(bundleName);
        CHECK_EXECUTE(item != applistConfigures_.end(), appConfigure = item->second);
    }
    MEDIA_INFO_LOG("CameraApplistManager::GetConfigureByBundleName BundleName: %{public}s", bundleName.c_str());
    return appConfigure;
}

bool CameraApplistManager::GetNaturalDirectionCorrectByBundleName(const std::string& bundleName,
    bool& exemptNaturalDirectionCorrect)
{
    CHECK_RETURN_RET_ELOG(bundleName.empty(), false,
        "CameraApplistManager::GetNaturalDirectionCorrectByBundleName bundleName is empty");
    CHECK_EXECUTE(!initResult_ || !registerResult_, Init());
    ApplistConfigure* appConfigure = nullptr;
    {
        std::lock_guard<std::mutex> lock(applistConfigureMutex_);
        auto item = applistConfigures_.find(bundleName);
        CHECK_EXECUTE(item != applistConfigures_.end(), appConfigure = item->second);
    }
    CHECK_RETURN_RET_DLOG(appConfigure == nullptr, true,
        "CameraApplistManager::GetNaturalDirectionCorrectByBundleName appConfigure is nullptr");

    std::map<int32_t, int32_t> useLogicCamera = appConfigure->useLogicCamera;
    exemptNaturalDirectionCorrect = appConfigure->exemptNaturalDirectionCorrect || (!useLogicCamera.empty() &&
        (std::all_of(useLogicCamera.begin(), useLogicCamera.end(), [](const auto& pair) { return pair.second == 0; })));
    MEDIA_INFO_LOG("CameraApplistManager::GetNaturalDirectionCorrectByBundleName BundleName: %{public}s, "
        "exemptNaturalDirectionCorrect: %{public}d", bundleName.c_str(), exemptNaturalDirectionCorrect);
    return true;
}

void CameraApplistManager::GetAppNaturalDirectionByBundleName(const std::string& bundleName,
    int32_t& naturalDirection)
{
    auto displayMode = static_cast<int32_t>(OHOS::Rosen::DisplayManagerLite::GetInstance().GetFoldDisplayMode());
    if (!displayModeToNaturalDirectionMap_.empty()) {
        auto item = displayModeToNaturalDirectionMap_.find(displayMode);
        CHECK_EXECUTE(item != displayModeToNaturalDirectionMap_.end(), naturalDirection = item->second);
        MEDIA_DEBUG_LOG("CameraApplistManager::GetAppNaturalDirectionByBundleName default naturalDirection: %{public}d",
            naturalDirection);
    }
    CHECK_RETURN_ELOG(bundleName.empty(),
        "CameraApplistManager::GetAppNaturalDirectionByBundleName bundleName is empty");
    CHECK_EXECUTE(!initResult_ || !registerResult_, Init());
    ApplistConfigure* appConfigure = nullptr;
    {
        std::lock_guard<std::mutex> lock(applistConfigureMutex_);
        auto item = applistConfigures_.find(bundleName);
        CHECK_EXECUTE(item != applistConfigures_.end(), appConfigure = item->second);
    }
    CHECK_RETURN_DLOG(appConfigure == nullptr,
        "CameraApplistManager::GetAppNaturalDirectionByBundleName appConfigure is nullptr");
    auto customLogicDirection = appConfigure->customLogicDirection;
    CHECK_RETURN_DLOG(customLogicDirection.empty(),
        "CameraApplistManager::GetAppNaturalDirectionByBundleName customLogicDirection is empty");
    auto item = customLogicDirection.find(displayMode);
    CHECK_RETURN_DLOG(item == customLogicDirection.end(),
        "CameraApplistManager::GetAppNaturalDirectionByBundleName naturalDirection is Normal");
    naturalDirection = (naturalDirection + item->second) % SIZE_FOUR;
    MEDIA_DEBUG_LOG("CameraApplistManager::GetAppNaturalDirectionByBundleName BundleName: %{public}s, "
        "displayMode: %{public}d, naturalDirection: %{public}d", bundleName.c_str(), displayMode, naturalDirection);
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP
