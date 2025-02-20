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

#ifndef CAMERA_DATASHARE_HELPER_H
#define CAMERA_DATASHARE_HELPER_H

#include "datashare_helper.h"

namespace OHOS {
namespace CameraStandard {
static const std::string SETTINGS_DATA_BASE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
static const std::string SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
static const std::string SETTINGS_DATA_FIELD_KEYWORD = "KEYWORD";
static const std::string SETTINGS_DATA_FIELD_VALUE = "VALUE";
static const std::string PREDICATES_STRING = "settings.camera.mute_persist";
#ifdef NOTIFICATION_ENABLE
static const std::string PREDICATES_CAMERA_BEAUTY_STATUS = "settings.camera.beauty_status";
static const std::string PREDICATES_CAMERA_BEAUTY_TIMES = "settings.camera.beauty_times";
#endif
class CameraDataShareHelper : public RefBase {
public:
    CameraDataShareHelper() = default;
    ~CameraDataShareHelper() = default;
    int32_t QueryOnce(const std::string key, std::string &value);
    int32_t UpdateOnce(const std::string key, std::string value);
    bool IsDataShareReady();
private:
    bool isDataShareReady_ = false;
    std::shared_ptr<DataShare::DataShareHelper> CreateCameraDataShareHelper();
};
} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_DATASHARE_HELPER_H