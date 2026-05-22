/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "dp_utils.h"

#include <dirent.h>
#include <sys/stat.h>

#include "bundle_mgr_interface.h"
#include "dp_log.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
std::string GetClientBundle(int uid)
{
    std::string bundleName = "";
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        DP_ERR_LOG("Get ability manager failed");
        return bundleName;
    }

    sptr<IRemoteObject> object = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (object == nullptr) {
        DP_DEBUG_LOG("object is NULL.");
        return bundleName;
    }

    sptr<OHOS::AppExecFwk::IBundleMgr> bms = iface_cast<OHOS::AppExecFwk::IBundleMgr>(object);
    if (bms == nullptr) {
        DP_DEBUG_LOG("bundle manager service is NULL.");
        return bundleName;
    }

    auto result = bms->GetNameForUid(uid, bundleName);
    if (result != ERR_OK || bundleName.empty()) {
        DP_ERR_LOG("GetBundleNameForUid fail");
        return "";
    }
    AppExecFwk::BundleInfo bundleInfo;
    bms->GetBundleInfo(bundleName,
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION),
        bundleInfo, AppExecFwk::Constants::ALL_USERID);
    std::string versionName = bundleInfo.versionName;
    if (versionName.empty()) {
        DP_ERR_LOG("get versionName form application failed.");
        return "";
    }
    DP_INFO_LOG("bundle name is %{public}s versionName:%{public}s", bundleName.c_str(), versionName.c_str());

    return bundleName;
}

DpsCallerInfo GetDpsCallerInfo()
{
    DpsCallerInfo dpsCallerInfo;
    dpsCallerInfo.pid = IPCSkeleton::GetCallingPid();
    dpsCallerInfo.uid = IPCSkeleton::GetCallingUid();
    dpsCallerInfo.tokenID = IPCSkeleton::GetCallingTokenID();
    dpsCallerInfo.bundleName = GetClientBundle(dpsCallerInfo.uid);
    DP_DEBUG_LOG("GetDpsCallerInfo pid:%{public}d uid:%{public}d", dpsCallerInfo.pid, dpsCallerInfo.uid);
    return dpsCallerInfo;
}

std::unordered_map<std::string, std::string> ParseKeyValue(const std::string& input) {
    std::unordered_map<std::string, std::string> result;
    DP_CHECK_RETURN_RET(input.empty(), result);
    std::stringstream src(input);
    std::string pair;

    while (std::getline(src, pair, ':')) {
        size_t pos = pair.find('=');
        if (pos != std::string::npos) {
            std::string key = pair.substr(0, pos);
            std::string value = pair.substr(pos + 1);
            result[key] = value;
        }
    }

    return result;
}

uint64_t GetFolderSize(const std::string& path)
{
    uint64_t totalSize = 0;
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return totalSize;
    }
    if (S_ISDIR(st.st_mode)) {
        DIR* dir = opendir(path.c_str());
        if (!dir) {
            return totalSize;
        }
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            std::string filePath = path + "/" + entry->d_name;
            if ((entry->d_type == DT_DIR) &&
                (std::string(entry->d_name) != "." && std::string(entry->d_name) != "..")) {
                totalSize += GetFolderSize(filePath);
            } else if (stat(filePath.c_str(), &st) == 0) {
                totalSize += static_cast<uint64_t>(st.st_size);
            }
        }
        closedir(dir);
    } else {
        totalSize = static_cast<uint64_t>(st.st_size);
    }
    return totalSize;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS