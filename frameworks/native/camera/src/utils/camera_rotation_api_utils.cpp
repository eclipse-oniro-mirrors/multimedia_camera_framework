/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "camera_rotation_api_utils.h"

#include "bundle_mgr_interface.h"
#include "camera_log.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "parameters.h"
#include "system_ability_definition.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace CameraStandard {
namespace CameraApiVersion {
#define API_DEFAULT_VERSION 1000
static uint32_t g_apiCompatibleVersion = API_DEFAULT_VERSION;
static std::mutex g_apiCompatibleVersionMutex;

uint32_t GetApiVersion()
{
    std::lock_guard<std::mutex> lock(g_apiCompatibleVersionMutex);
    if (g_apiCompatibleVersion != API_DEFAULT_VERSION) {
        return g_apiCompatibleVersion;
    }
    OHOS::sptr<OHOS::ISystemAbilityManager> systemAbilityManager =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    OHOS::sptr<OHOS::IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> iBundleMgr = OHOS::iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (iBundleMgr == nullptr) {
        MEDIA_ERR_LOG("GetApiCompatibleVersion iBundleMgr is null");
        return g_apiCompatibleVersion;
    }
    AppExecFwk::BundleInfo bundleInfo;
    if (iBundleMgr->GetBundleInfoForSelf(0, bundleInfo) == ERR_OK) {
        g_apiCompatibleVersion = bundleInfo.targetVersion % API_DEFAULT_VERSION;
        MEDIA_INFO_LOG("targetVersion: [%{public}u], apiCompatibleVersion: [%{public}u]", bundleInfo.targetVersion,
            g_apiCompatibleVersion);
    } else {
        MEDIA_ERR_LOG("Call for GetApiCompatibleVersion failed");
    }
    return g_apiCompatibleVersion;
}
} // namespace CameraApiVersion
} // namespace CameraStandard
} // namespace OHOS
