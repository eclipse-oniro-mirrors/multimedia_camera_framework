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
#include "camera_datashare_helper.h"

#include "camera_log.h"
#include "camera_util.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace CameraStandard {

std::shared_ptr<DataShare::DataShareHelper> CameraDataShareHelper::CreateCameraDataShareHelper()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_RET_ELOG(samgr == nullptr, nullptr, "CameraDataShareHelper GetSystemAbilityManager failed.");
    sptr<IRemoteObject> remoteObj = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_RET_ELOG(remoteObj == nullptr, nullptr, "CameraDataShareHelper GetSystemAbility Service Failed.");
    return DataShare::DataShareHelper::Creator(remoteObj, SETTINGS_DATA_BASE_URI, SETTINGS_DATA_EXT_URI);
}

int32_t CameraDataShareHelper::QueryOnce(const std::string key, std::string &value)
{
    auto dataShareHelper = CreateCameraDataShareHelper();
    CHECK_RETURN_RET_ELOG(dataShareHelper == nullptr, CAMERA_INVALID_ARG, "dataShareHelper_ is nullptr");
    Uri uri(SETTINGS_DATA_BASE_URI);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_DATA_FIELD_KEYWORD, key);
    std::vector<std::string> columns;
    columns.emplace_back(SETTINGS_DATA_FIELD_VALUE);

    auto resultSet = dataShareHelper->Query(uri, predicates, columns);
    if (resultSet == nullptr) {
        MEDIA_INFO_LOG("CameraDataShareHelper query fail");
        dataShareHelper->Release();
        return CAMERA_INVALID_ARG;
    }

    if (resultSet->GoToFirstRow() != DataShare::E_OK) {
        MEDIA_INFO_LOG("CameraDataShareHelper Query failed,go to first row error");
        resultSet->Close();
        dataShareHelper->Release();
        return CAMERA_INVALID_ARG;
    }

    int columnIndex;
    resultSet->GetColumnIndex(SETTINGS_DATA_FIELD_VALUE, columnIndex);
    resultSet->GetString(columnIndex, value);
    resultSet->Close();
    dataShareHelper->Release();
    MEDIA_INFO_LOG("CameraDataShareHelper query success,value=%{public}s", value.c_str());
    return CAMERA_OK;
}

int32_t CameraDataShareHelper::UpdateOnce(const std::string key, std::string value)
{
    auto dataShareHelper = CreateCameraDataShareHelper();
    CHECK_RETURN_RET_ELOG(dataShareHelper == nullptr, CAMERA_INVALID_ARG, "dataShareHelper_ is nullptr");
    Uri uri(SETTINGS_DATA_BASE_URI);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_DATA_FIELD_KEYWORD, key);

    DataShare::DataShareValuesBucket bucket;
    DataShare::DataShareValueObject keywordObj(key);
    DataShare::DataShareValueObject valueObj(value);
    bucket.Put(SETTINGS_DATA_FIELD_KEYWORD, keywordObj);
    bucket.Put(SETTINGS_DATA_FIELD_VALUE, valueObj);

    if (dataShareHelper->Update(uri, predicates, bucket) <= 0) {
        dataShareHelper->Insert(uri, bucket);
        dataShareHelper->Release();
        MEDIA_ERR_LOG("CameraDataShareHelper Update:%{public}s failed", key.c_str());
        return CAMERA_INVALID_ARG;
    }
    MEDIA_INFO_LOG("CameraDataShareHelper Update:%{public}s success", key.c_str());
    dataShareHelper->Release();
    return CAMERA_OK;
}

bool CameraDataShareHelper::IsDataShareReady()
{
    CHECK_RETURN_RET(isDataShareReady_, true);
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_RET_ELOG(samgr == nullptr, false, "CameraDataShareHelper GetSystemAbilityManager failed.");
    sptr<IRemoteObject> remoteObj = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_RETURN_RET_ELOG(remoteObj == nullptr, false, "CameraDataShareHelper GetSystemAbility Service Failed.");
    std::pair<int, std::shared_ptr<DataShare::DataShareHelper>> ret =
        DataShare::DataShareHelper::Create(remoteObj, SETTINGS_DATA_BASE_URI, SETTINGS_DATA_EXT_URI);
    MEDIA_INFO_LOG("create dataShareHelper ret=%{public}d", ret.first);
    if (ret.first == DataShare::E_OK) {
        auto dataShareHelper = ret.second;
        if (dataShareHelper != nullptr) {
            bool releaseRet = dataShareHelper->Release();
            MEDIA_INFO_LOG("release dataShareHelper, ret=%{public}d", releaseRet);
        }
        isDataShareReady_ = true;
        return true;
    } else if (ret.first == DataShare::E_DATA_SHARE_NOT_READY) {
        isDataShareReady_ = false;
        return false;
    }
    return true;
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP