/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "camera_app_manager_utils.h"
#include "camera_log.h"

#include <app_mgr_interface.h>
#include <if_system_ability_manager.h>
#include <iservice_registry.h>

namespace OHOS {
namespace CameraStandard {
class CameraAppManagerUtils::CameraAppManagerUtilsDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit CameraAppManagerUtilsDeathRecipient() {}
        ~CameraAppManagerUtilsDeathRecipient() {}

        void OnRemoteDied(const wptr<IRemoteObject> &remote) override
        {
            MEDIA_ERR_LOG("Remote died.");
            CameraAppManagerUtils::OnRemoveInstance();
        }
};

static constexpr uint32_t APP_MGR_SERVICE_ID = 501;
static std::mutex g_cameraAppManagerInstanceMutex;
sptr<OHOS::AppExecFwk::IAppMgr> CameraAppManagerUtils::appManagerInstance_ = nullptr;

sptr<OHOS::AppExecFwk::IAppMgr> CameraAppManagerUtils::GetAppManagerInstance()
{
    std::lock_guard<std::mutex> lock(g_cameraAppManagerInstanceMutex);
    if (appManagerInstance_) {
        return appManagerInstance_;
    }

    sptr<OHOS::ISystemAbilityManager> abilityMgr =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (abilityMgr == nullptr) {
        MEDIA_ERR_LOG("Failed to get ISystemAbilityManager");
        return nullptr;
    }
    sptr<IRemoteObject> remoteObject = abilityMgr->GetSystemAbility(APP_MGR_SERVICE_ID);
    if (remoteObject == nullptr) {
        MEDIA_ERR_LOG("Failed to get app manager service, id=%{public}u", APP_MGR_SERVICE_ID);
        return nullptr;
    }
    sptr<OHOS::AppExecFwk::IAppMgr> appMgrProxy = iface_cast<OHOS::AppExecFwk::IAppMgr>(remoteObject);
    if (appMgrProxy == nullptr || !appMgrProxy->AsObject()) {
        MEDIA_ERR_LOG("Failed to get app manager proxy");
        return nullptr;
    }
    sptr<CameraAppManagerUtilsDeathRecipient> CameraAppManagerUtilsDeathRecipient_ =
        new CameraAppManagerUtilsDeathRecipient();
    remoteObject->AddDeathRecipient(CameraAppManagerUtilsDeathRecipient_);
    appManagerInstance_ = appMgrProxy;
    return appManagerInstance_;
}

void CameraAppManagerUtils::GetForegroundApplications(std::vector<OHOS::AppExecFwk::AppStateData>& appsData)
{
    auto appMgr = GetAppManagerInstance();
    if (!appMgr) {
        return;
    }
    int32_t ret = appMgr->GetForegroundApplications(appsData);
    MEDIA_INFO_LOG("GetForegroundApplications, ret: %{public}u, num of apps: %{public}zu", ret, appsData.size());
}

bool CameraAppManagerUtils::IsForegroundApplication(const uint32_t tokenId)
{
    MEDIA_INFO_LOG("check IsForegroundApplication");
    bool IsForeground = false;
    std::vector<OHOS::AppExecFwk::AppStateData> appsData;
    GetForegroundApplications(appsData);
    for (const auto& curApp : appsData) {
        if (curApp.accessTokenId == tokenId) {
            IsForeground = true;
            break;
        }
    }
    MEDIA_INFO_LOG("IsForegroundApplication, ret: %{public}u", static_cast<uint32_t>(IsForeground));
    return IsForeground;
}

void CameraAppManagerUtils::OnRemoveInstance()
{
    std::lock_guard<std::mutex> lock(g_cameraAppManagerInstanceMutex);
    appManagerInstance_ = nullptr;
}
} // namespace PowerMgr
} // namespace OHOS