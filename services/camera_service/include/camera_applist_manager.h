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

namespace OHOS {
namespace CameraStandard {

static const std::string SETTING_URI_PROXY =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
static const std::string SETTINGS_DATA_EXTRA_URI = "datashare:///com.ohos.settingsdata.DataAbility";
static const std::string SETTINGS_DATA_KEY_URI = "&key=";
static const std::string SETTINGS_DATA_COLUMN_KEYWORD = "KEYWORD";
static const std::string SETTINGS_DATA_COLUMN_VALUE = "VALUE";
static const std::string COMPATIBLE_APP_STRATEGY = "COMPATIBLE_APP_STRATEGY";

struct ApplistConfigure {
    std::string bundleName;
    bool exemptNaturalDirectionCorrect;
};

class CameraApplistManager : public RefBase {
public:
    static sptr<CameraApplistManager> &GetInstance();
    ~CameraApplistManager();
    bool InitApplistConfigures();
    ApplistConfigure* GetConfigureByBundleName(const std::string& bundleName);
    bool GetNaturalDirectionCorrectByBundleName(const std::string& bundleName,
        bool& exemptNaturalDirectionCorrect);

private:
    CameraApplistManager();

    std::shared_ptr<DataShare::DataShareHelper> CreateCameraDataShareHelper();
    bool GetApplistConfigure(Uri& uri, DataShare::DataSharePredicates& predicates, std::string& jsonStr);
    void ParseApplistConfigureJsonStr(const std::string& cfgJsonStr);
    void UpdateApplistConfigure(const ApplistConfigure& appConfigure);

private:
    static sptr<CameraApplistManager> cameraApplistManager_;
    std::map<std::string, ApplistConfigure*> applistConfigures_;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper_;

    bool initResult_ = false;

    static std::mutex instanceMutex_;
    std::mutex applistConfigureMutex_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_APPLIST_MANAGER_H
