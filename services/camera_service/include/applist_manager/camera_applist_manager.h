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
#include "datashare_helper.h"
#include "data_ability_observer_stub.h"

namespace OHOS {
namespace CameraStandard {

static const std::string SETTING_URI_PROXY =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
static const std::string SETTINGS_DATA_EXTRA_URI = "datashare:///com.ohos.settingsdata.DataAbility";
static const std::string SETTINGS_DATA_KEY_URI = "&key=";
static const std::string SETTINGS_DATA_COLUMN_KEYWORD = "KEYWORD";
static const std::string SETTINGS_DATA_COLUMN_VALUE = "VALUE";
static const std::string COMPATIBLE_APP_STRATEGY = "COMPATIBLE_APP_STRATEGY";
static const std::string APP_LOGICAL_DEVICE_CONFIGURATION = "APP_LOGICAL_DEVICE_CONFIGURATION";

struct ApplistConfigure {
    std::string bundleName;
    bool exemptNaturalDirectionCorrect = false;
    std::map<int32_t, int32_t> useLogicCamera;
    std::map<int32_t, int32_t> customLogicDirection;
};

class CameraApplistManager : public AAFwk::DataAbilityObserverStub {
public:
    static sptr<CameraApplistManager> &GetInstance();
    ~CameraApplistManager();
    bool Init();
    ApplistConfigure* GetConfigureByBundleName(const std::string& bundleName);
    bool GetNaturalDirectionCorrectByBundleName(const std::string& bundleName,
        bool& exemptNaturalDirectionCorrect);
    void GetAppNaturalDirectionByBundleName(const std::string& bundleName, int32_t& naturalDirection);
    void OnChange() override;

private:
    CameraApplistManager();

    int32_t GetLogicCameraScreenStatus();
    std::shared_ptr<DataShare::DataShareHelper> CreateCameraDataShareHelper();
    bool RegisterCameraApplistManagerObserver();
    void UnregisterCameraApplistManagerObserver();
    bool GetApplistConfigure();
    void ParseApplistConfigureJsonStr(const std::string& cfgJsonStr);
    void UpdateApplistConfigure(const ApplistConfigure& appConfigure);
    void ClearApplistManager();

private:
    static sptr<CameraApplistManager> cameraApplistManager_;
    std::map<std::string, ApplistConfigure*> applistConfigures_;
    std::map<int32_t, int32_t> displayModeToNaturalDirectionMap_;

    bool isLogicCamera_ = false;
    std::string foldScreenType_ = "";
    std::string uriForWhiteList_ = "";

    bool initResult_ = false;
    bool registerResult_ = false;
    sptr<IRemoteObject> remoteObj_;

    static std::mutex instanceMutex_;
    std::mutex applistConfigureMutex_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_APPLIST_MANAGER_H
