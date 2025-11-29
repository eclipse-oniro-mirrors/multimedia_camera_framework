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

#include "camera_log.h"
#include "camera_util.h"
#include "ipc_skeleton.h"
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
            MEDIA_INFO_LOG("Initializing cameraApplistManager instance");
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
    remoteObj_ = nullptr;
    ClearApplistManager();
    std::lock_guard<std::mutex> lock(observerMutex_);
    CHECK_RETURN_ELOG(UnregisterObserver(observer_) != CAMERA_OK,
        "CameraApplistManager::~CameraApplistManager UnregisterObserver failed");
    MEDIA_INFO_LOG("CameraApplistManager::~CameraApplistManager");
}

bool CameraApplistManager::Init()
{
    if (remoteObj_ == nullptr) {
        auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        CHECK_RETURN_RET_ELOG(samgr == nullptr, false, "CameraApplistManager GetSystemAbilityManager failed.");
        remoteObj_ = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
        CHECK_RETURN_RET_ELOG(remoteObj_ == nullptr, false, "CameraApplistManager GetSystemAbility Service Failed.");
    }
    CHECK_EXECUTE(!initResult_, initResult_ = RegisterCameraApplistManagerObserver());
    CHECK_RETURN_RET_ELOG(!initResult_, false, "CameraApplistManager::Init initResult: %{public}d", initResult_);
    return initResult_;
}

bool CameraApplistManager::GetApplistConfigure(std::string& jsonStr)
{
    auto dataShareHelper = CreateCameraDataShareHelper();
    CHECK_RETURN_RET_ELOG(dataShareHelper == nullptr, false,
        "CameraApplistManager::GetApplistConfigure dataShareHelper is nullptr");
    Uri uri(SETTING_URI_PROXY + SETTINGS_DATA_KEY_URI + COMPATIBLE_APP_STRATEGY);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_DATA_COLUMN_KEYWORD, COMPATIBLE_APP_STRATEGY);
    std::vector<std::string> columns = { SETTINGS_DATA_COLUMN_VALUE };
    auto resultSet = dataShareHelper->Query(uri, predicates, columns);
    CHECK_RETURN_RET_ELOG(resultSet == nullptr, false,
        "CameraApplistManager::GetApplistConfigure dataShareHelper Query failed");
    int32_t count = 0;
    resultSet->GetRowCount(count);
    if (count == 0) {
        MEDIA_ERR_LOG("CameraApplistManager::GetApplistConfigure DataShareHelper query none result");
        resultSet->Close();
        ReleaseDataShareHelper(dataShareHelper);
        return false;
    }

    resultSet->GoToRow(0);
    int32_t ret = resultSet->GetString(0, jsonStr);
    if (ret != DataShare::E_OK) {
        MEDIA_ERR_LOG("CameraApplistManager::GetApplistConfigure DataShareHelper query result GetString failed, "
            "ret: %{public}d", ret);
        resultSet->Close();
        ReleaseDataShareHelper(dataShareHelper);
        return false;
    }

    resultSet->Close();
    ReleaseDataShareHelper(dataShareHelper);
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

void CameraApplistManager::ClearApplistManager()
{
    std::lock_guard<std::mutex> lock(applistConfigureMutex_);
    for (auto& [key, appCfg] : applistConfigures_) {
        delete appCfg;
    }
    applistConfigures_.clear();
}

bool CameraApplistManager::ReleaseDataShareHelper(std::shared_ptr<DataShare::DataShareHelper> &helper)
{
    CHECK_RETURN_RET_ELOG(helper == nullptr, false, "CameraApplistManager::ReleaseDataShareHelper helper is nullptr");
    CHECK_RETURN_RET_ELOG(!helper->Release(), false, "CameraApplistManager::ReleaseDataShareHelper release fail");
    return true;
}

std::shared_ptr<DataShare::DataShareHelper> CameraApplistManager::CreateCameraDataShareHelper()
{
    CHECK_RETURN_RET_ELOG(remoteObj_ == nullptr, nullptr,
        "CameraApplistManager::CreateCameraDataShareHelper remoteObj is null");
    return DataShare::DataShareHelper::Creator(remoteObj_, SETTING_URI_PROXY, SETTINGS_DATA_EXTRA_URI);
}

bool CameraApplistManager::RegisterCameraApplistManagerObserver()
{
    CameraApplistObserver::UpdateFunc updateFunc = [this]() {
        std::string cfgJsonStr;
        ClearApplistManager();
        CHECK_RETURN_ELOG(!GetApplistConfigure(cfgJsonStr), "CameraApplistManager GetApplistConfigure failed");
        ParseApplistConfigureJsonStr(cfgJsonStr);
    };
    std::lock_guard<std::mutex> lock(observerMutex_);
    observer_ = CreateObserver(updateFunc);
    CHECK_RETURN_RET_ELOG(observer_ == nullptr, false, "CameraApplistManager::Init observer is null");
    CHECK_RETURN_RET_ELOG(RegisterObserver(observer_) != CAMERA_OK, false,
        "CameraApplistManager::Init RegisterObserver failed");
    return true;
}

sptr<CameraApplistObserver> CameraApplistManager::CreateObserver(const CameraApplistObserver::UpdateFunc &func)
{
    sptr<CameraApplistObserver> observer = new CameraApplistObserver();
    CHECK_RETURN_RET_ELOG(observer == nullptr, observer, "CameraApplistManager::CreateObserver observer is null");
    observer->SetUpdateFunc(func);
    return observer;
}

void CameraApplistManager::ExecRegisterCb(const sptr<CameraApplistObserver> &observer)
{
    CHECK_RETURN_ELOG(observer == nullptr, "CameraApplistManager::ExecRegisterCb observer is nullptr");
    observer->OnChange();
}

int32_t CameraApplistManager::RegisterObserver(const sptr<CameraApplistObserver> &observer)
{
    CHECK_RETURN_RET_ELOG(observer == nullptr, CAMERA_INVALID_ARG,
        "CameraApplistManager::RegisterObserver observer is nullptr");
    std::string callingIdentity = IPCSkeleton::ResetCallingIdentity();
    auto helper = CreateCameraDataShareHelper();
    if (helper == nullptr) {
        IPCSkeleton::SetCallingIdentity(callingIdentity);
        MEDIA_ERR_LOG("CameraApplistManager::RegisterObserver dataShareHelper is null");
        return CAMERA_INVALID_ARG;
    }
    Uri uri(SETTING_URI_PROXY + SETTINGS_DATA_KEY_URI + COMPATIBLE_APP_STRATEGY);
    helper->RegisterObserver(uri, observer);
    helper->NotifyChange(uri);
    std::thread execCb(CameraApplistManager::ExecRegisterCb, observer);
    execCb.detach();
    ReleaseDataShareHelper(helper);
    IPCSkeleton::SetCallingIdentity(callingIdentity);
    MEDIA_INFO_LOG("CameraApplistManager::RegisterObserver Success");
    return CAMERA_OK;
}

int32_t CameraApplistManager::UnregisterObserver(const sptr<CameraApplistObserver> &observer)
{
    CHECK_RETURN_RET_ELOG(observer == nullptr, CAMERA_INVALID_ARG,
        "CameraApplistManager::UnregisterObserver observer is nullptr");
    std::string callingIdentity = IPCSkeleton::ResetCallingIdentity();
    auto helper = CreateCameraDataShareHelper();
    if (helper == nullptr) {
        IPCSkeleton::SetCallingIdentity(callingIdentity);
        return CAMERA_INVALID_ARG;
    }
    Uri uri(SETTING_URI_PROXY + SETTINGS_DATA_KEY_URI + COMPATIBLE_APP_STRATEGY);
    helper->UnregisterObserver(uri, observer);
    ReleaseDataShareHelper(helper);
    IPCSkeleton::SetCallingIdentity(callingIdentity);
    MEDIA_INFO_LOG("CameraApplistManager::UnregisterObserver Success");
    return CAMERA_OK;
}

ApplistConfigure* CameraApplistManager::GetConfigureByBundleName(const std::string& bundleName)
{
    CHECK_RETURN_RET_ELOG(bundleName.empty(), nullptr, "CameraApplistManager::GetConfigureByBundleName bundleName "
        "is empty");
    CHECK_EXECUTE(!initResult_, initResult_ = RegisterCameraApplistManagerObserver());
    ApplistConfigure* appConfigure = nullptr;
    {
        std::lock_guard<std::mutex> lock(applistConfigureMutex_);
        auto item = applistConfigures_.find(bundleName);
        CHECK_EXECUTE(item != applistConfigures_.end(), appConfigure = item->second);
    }
    MEDIA_INFO_LOG("CameraApplistManager::GeGetConfigureByBundleName BundleName: %{public}s", bundleName.c_str());
    return appConfigure;
}

bool CameraApplistManager::GetNaturalDirectionCorrectByBundleName(const std::string& bundleName,
    bool& exemptNaturalDirectionCorrect)
{
    CHECK_RETURN_RET_ELOG(bundleName.empty(), false,
        "CameraApplistManager::GetNaturalDirectionCorrectByBundleName bundleName is empty");
    CHECK_EXECUTE(!initResult_, initResult_ = RegisterCameraApplistManagerObserver());
    ApplistConfigure* appConfigure = nullptr;
    {
        std::lock_guard<std::mutex> lock(applistConfigureMutex_);
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
