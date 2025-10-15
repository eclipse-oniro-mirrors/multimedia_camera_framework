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
#include "camera_applist_manager.h"

#include "camera_log.h"
#include "camera_util.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace CameraStandard {
sptr<CameraApplistManager> CameraApplistManager::cameraApplistManager_;
std::mutex CameraApplistManager::instanceMutex_;

sptr<CameraApplistManager> &CameraApplistManager::GetInstance()
{
    if (cameraApplistManager_ == nullptr) {
        std::unique_lock<std::mutex> lock(instanceMutex_);
        if (cameraApplistManager_ == nullptr) {
            MEDIA_INFO_LOG("Initializing cameraApplistManager_ instance");
            cameraApplistManager_ = new CameraApplistManager();
        }
    }
    return CameraApplistManager::cameraApplistManager_;
}

CameraApplistManager::CameraApplistManager()
{
    MEDIA_INFO_LOG("CameraApplistManager construct");
}

CameraApplistManager::~CameraApplistManager()
{
    std::lock_guard<std::mutex> lock(dataShareHelperMutex_);
    CHECK_EXECUTE(dataShareHelper_ != nullptr, dataShareHelper_->Release());

    for (auto& [key, appCfg] : applistConfigures_) {
        delete appCfg;
    }
    applistConfigures_.clear();
    MEDIA_INFO_LOG("CameraApplistManager::~CameraApplistManager");
}

std::shared_ptr<DataShare::DataShareHelper> CameraApplistManager::CreateCameraDataShareHelper()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_RET_ELOG(samgr == nullptr, nullptr, "CameraApplistManager GetSystemAbilityManager failed.");
    sptr<IRemoteObject> remoteObj = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_RET_ELOG(remoteObj == nullptr, nullptr, "CameraApplistManager GetSystemAbility Service Failed.");
    return DataShare::DataShareHelper::Creator(remoteObj, SETTING_URI_PROXY, SETTINGS_DATA_EXTRA_URI);
}

bool CameraApplistManager::InitApplistConfigures()
{
    CHECK_RETURN_RET_ILOG(initResult_, true, "CameraApplistManager::InitApplistConfigures has inited");
    CHECK_EXECUTE(dataShareHelper_ == nullptr, dataShareHelper_ = CreateCameraDataShareHelper());
    CHECK_RETURN_RET_ELOG(dataShareHelper_ == nullptr, false,
        "CameraApplistManager::InitApplistConfigures dataShareHelper is nullptr");
    Uri uri(SETTING_URI_PROXY + SETTINGS_DATA_KEY_URI + COMPATIBLE_APP_STRATEGY);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_DATA_COLUMN_KEYWORD, COMPATIBLE_APP_STRATEGY);
    std::string cfgJsonStr;
    CHECK_RETURN_RET_ELOG(!GetApplistConfigure(uri, predicates, cfgJsonStr), false,
        "CameraApplistManager::InitApplistConfigures GetApplistConfigure failed");
    ParseApplistConfigureJsonStr(cfgJsonStr);
    CHECK_EXECUTE(!applistConfigures_.empty(), initResult_ = true);
    MEDIA_INFO_LOG("CameraApplistManager::InitApplistConfigures initResult: %{public}d", initResult_);
    return true;
}

bool CameraApplistManager::GetApplistConfigure(Uri& uri, DataShare::DataSharePredicates& predicates,
    std::string& jsonStr)
{
    CHECK_RETURN_RET_ELOG(dataShareHelper_ == nullptr, false,
        "CameraApplistManager::GetApplistConfigure dataShareHelper is nullptr");
    std::vector<std::string> columns = { SETTINGS_DATA_COLUMN_VALUE };
    auto resultSet = dataShareHelper_->Query(uri, predicates, columns);
    CHECK_RETURN_RET_ELOG(resultSet == nullptr, false,
        "CameraApplistManager::GetApplistConfigure dataShareHelper Query failed");
    int32_t count = 0;
    resultSet->GetRowCount(count);
    if (count == 0) {
        MEDIA_ERR_LOG("CameraApplistManager::GetApplistConfigure DataShareHelper query none result");
        resultSet->Close();
        return false;
    }

    resultSet->GoToRow(0);
    int32_t ret = resultSet->GetString(0, jsonStr);
    if (ret != DataShare::E_OK) {
        MEDIA_ERR_LOG("CameraApplistManager::GetApplistConfigure DataShareHelper query result GetString failed, "
            "ret: %{public}d", ret);
        resultSet->Close();
        return false;
    }

    resultSet->Close();
    return true;
}

void CameraApplistManager::ParseApplistConfigureJsonStr(const std::string& cfgJsonStr)
{
    nlohmann::json jsonParsed = nlohmann::json::parse(cfgJsonStr, nullptr, false);
    CHECK_RETURN_ELOG(jsonParsed.is_discarded(), "CameraApplistManager::ParseApplistConfigureJsonStr Parse Failed");

    ApplistConfigure appConfigure;
    for (auto& [bundleName, info] : jsonParsed.items()) {
        appConfigure.bundleName = bundleName;
        bool flag = info.contains("exemptNaturalDirectionCorrect") &&
            info["exemptNaturalDirectionCorrect"].is_boolean();
        if (flag) {
            appConfigure.exemptNaturalDirectionCorrect = info["exemptNaturalDirectionCorrect"].get<bool>();
        } else {
            appConfigure.exemptNaturalDirectionCorrect = false;
        }
        UpdateApplistConfigure(appConfigure);
    }
    MEDIA_INFO_LOG("CameraApplistManager::ParseApplistConfigureJsonStr Success");
}

void CameraApplistManager::UpdateApplistConfigure(const ApplistConfigure& appConfigure)
{
    std::lock_guard<std::mutex> lock(dataShareHelperMutex_);
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

ApplistConfigure* CameraApplistManager::GetConfigureByBundleName(const std::string& bundleName)
{
    CHECK_RETURN_RET_ELOG(bundleName.empty(), nullptr, "CameraApplistManager::GetConfigureByBundleName bundleName "
        "is empty");
    CHECK_EXECUTE(!initResult_, InitApplistConfigures());
    ApplistConfigure* appConfigure = nullptr;
    {
        std::lock_guard<std::mutex> lock(dataShareHelperMutex_);
        auto item = applistConfigures_.find(bundleName);
        CHECK_EXECUTE(item != applistConfigures_.end(), appConfigure = item->second);
    }
    MEDIA_INFO_LOG("CameraApplistManager::GeGetConfigureByBundleName BundleName: %{public}s", bundleName.c_str());
    return appConfigure;
}

bool CameraApplistManager::GetNaturalDirectionCorrectByBundleName(const std::string& bundleName,
    bool& exemptNaturalDirectionCorrect)
{
    MEDIA_INFO_LOG("CameraApplistManager::GetNaturalDirectionCorrectByBundleName is called");
    CHECK_RETURN_RET_ELOG(bundleName.empty(), false,
        "CameraApplistManager::GetNaturalDirectionCorrectByBundleName bundleName is empty");
    CHECK_EXECUTE(!initResult_, InitApplistConfigures());
    ApplistConfigure* appConfigure = nullptr;
    {
        std::lock_guard<std::mutex> lock(dataShareHelperMutex_);
        auto item = applistConfigures_.find(bundleName);
        CHECK_EXECUTE(item != applistConfigures_.end(), appConfigure = item->second);
    }
    CHECK_RETURN_RET_ELOG(appConfigure == nullptr, false,
        "CameraApplistManager::GetNaturalDirectionCorrectByBundleName appConfigure is nullptr");
    exemptNaturalDirectionCorrect = appConfigure->exemptNaturalDirectionCorrect;
    MEDIA_INFO_LOG("CameraApplistManager::GetNaturalDirectionCorrectByBundleName BundleName: %{public}s, "
        "exemptNaturalDirectionCorrect: %{public}d", bundleName.c_str(), exemptNaturalDirectionCorrect);
    return true;
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP