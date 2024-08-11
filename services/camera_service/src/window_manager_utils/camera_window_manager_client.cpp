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
 
#include "camera_log.h"
#include "camera_util.h"
#include "camera_window_manager_agent.h"
#include "camera_window_manager_client.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include <cstdint>
 
namespace OHOS {
namespace CameraStandard {
std::mutex CameraWindowManagerClient::instanceMutex_;
sptr<CameraWindowManagerClient> CameraWindowManagerClient::cameraWindowManagerClient_;
 
CameraWindowManagerClient::CameraWindowManagerClient()
{
    SubscribeSystemAbility();
}

CameraWindowManagerClient::~CameraWindowManagerClient()
{
    CameraWindowManagerClient::GetInstance()->UnregisterWindowManagerAgent();
}
 
sptr<CameraWindowManagerClient>& CameraWindowManagerClient::GetInstance()
{
    if (cameraWindowManagerClient_ == nullptr) {
        std::unique_lock<std::mutex> lock(instanceMutex_);
        if (cameraWindowManagerClient_ == nullptr) {
            MEDIA_INFO_LOG("Initializing CameraWindowManagerClient instance");
            cameraWindowManagerClient_ = new CameraWindowManagerClient();
        }
    }
    return cameraWindowManagerClient_;
}
 
int32_t CameraWindowManagerClient::RegisterWindowManagerAgent()
{
    MEDIA_DEBUG_LOG("RegisterWindowManagerAgent start");
    int32_t ret = CAMERA_UNKNOWN_ERROR;
    if (sceneSessionManagerProxy_) {
        ret = sceneSessionManagerProxy_->RegisterWindowManagerAgent(
            WindowManagerAgentType::WINDOW_MANAGER_AGENT_TYPE_CAMERA_WINDOW, windowManagerAgent_);
    } else {
        MEDIA_ERR_LOG("sceneSessionManagerProxy_ is null");
    }
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("failed to UnregisterWindowManagerAgent error code: %{public}d", ret);
    }
    MEDIA_DEBUG_LOG("RegisterWindowManagerAgent end");
    return ret;
}
 
int32_t CameraWindowManagerClient::UnregisterWindowManagerAgent()
{
    MEDIA_DEBUG_LOG("UnregisterWindowManagerAgent start");
    int32_t ret = CAMERA_UNKNOWN_ERROR;
    if (sceneSessionManagerProxy_) {
        ret = sceneSessionManagerProxy_->UnregisterWindowManagerAgent(
            WindowManagerAgentType::WINDOW_MANAGER_AGENT_TYPE_CAMERA_WINDOW, windowManagerAgent_);
    } else {
        MEDIA_ERR_LOG("sceneSessionManagerProxy_ is null");
    }
    CHECK_ERROR_PRINT_LOG(ret != CAMERA_OK, "failed to UnregisterWindowManagerAgent error code: %{public}d", ret);
    MEDIA_DEBUG_LOG("UnregisterWindowManagerAgent end");
    return ret;
}
 
void CameraWindowManagerClient::GetFocusWindowInfo(pid_t& pid)
{
    MEDIA_DEBUG_LOG("GetFocusWindowInfo start");
    sptr<OHOS::Rosen::FocusChangeInfo> focusInfo = new OHOS::Rosen::FocusChangeInfo();
    if (sceneSessionManagerProxy_) {
        sceneSessionManagerProxy_->GetFocusWindowInfo(*focusInfo);
    } else {
        MEDIA_ERR_LOG("sceneSessionManagerProxy_ is null");
    }
    MEDIA_ERR_LOG("GetFocusWindowInfo pid_: %{public}d", focusInfo->pid_);
    pid = focusInfo->pid_;
    MEDIA_DEBUG_LOG("GetFocusWindowInfo end");
}
 
void CameraWindowManagerClient::InitWindowProxy()
{
    MEDIA_DEBUG_LOG("InitWindowProxy begin");
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_ERROR_RETURN_LOG(!systemAbilityManager, "Failed to get system ability manager");
 
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(WINDOW_MANAGER_SERVICE_ID);
    if (!remoteObject) {
        MEDIA_ERR_LOG("remoteObjectWmMgrService is null");
        return;
    }
 
    mockSessionManagerServiceProxy_ = iface_cast<IMockSessionManagerInterface>(remoteObject);
    CHECK_ERROR_RETURN_LOG(!mockSessionManagerServiceProxy_, "Failed to get mockSessionManagerServiceProxy_");
 
    sptr<IRemoteObject> remoteObjectMgrService = mockSessionManagerServiceProxy_->GetSessionManagerService();
    CHECK_ERROR_RETURN_LOG(!remoteObjectMgrService, "remoteObjectMgrService is null");
 
    sessionManagerServiceProxy_ = iface_cast<ISessionManagerService>(remoteObjectMgrService);
    CHECK_ERROR_RETURN_LOG(!sessionManagerServiceProxy_, "Failed to get sessionManagerServiceProxy_");
 
    sptr<IRemoteObject> remoteObjectMgr = sessionManagerServiceProxy_->GetSceneSessionManager();
    CHECK_ERROR_RETURN_LOG(!remoteObjectMgr, "remoteObjectMgr is null");
 
    sceneSessionManagerProxy_ = iface_cast<ISceneSessionManager>(remoteObjectMgr);
    CHECK_ERROR_RETURN_LOG(!sceneSessionManagerProxy_, "Failed to get sceneSessionManagerProxy_");
 
    MEDIA_DEBUG_LOG("InitWindowProxy end");
}
 
void CameraWindowManagerClient::InitWindowManagerAgent()
{
    MEDIA_DEBUG_LOG("InitWindowManagerAgent start");
    windowManagerAgent_ = new CameraWindowManagerAgent();
    CHECK_ERROR_PRINT_LOG(windowManagerAgent_ == nullptr, "Failed to init windowManagerAgent_");
    int32_t windowRet = CameraWindowManagerClient::GetInstance()->RegisterWindowManagerAgent();
    CHECK_ERROR_PRINT_LOG(windowRet != 0, "RegisterWindowManagerAgent faild");
    MEDIA_DEBUG_LOG("InitWindowManagerAgent end");
}
 
sptr<IWindowManagerAgent> CameraWindowManagerClient::GetWindowManagerAgent()
{
    return windowManagerAgent_;
}

int32_t CameraWindowManagerClient::SubscribeSystemAbility()
{
    MEDIA_DEBUG_LOG("SubscribeSystemAbility start");
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_ERROR_RETURN_RET_LOG(samgr == nullptr, CAMERA_UNKNOWN_ERROR, "Failed to get system ability manager");
    saStatusChangeCallback_ = new CameraWindowManagerClient::WMSSaStatusChangeCallback();
    CHECK_AND_RETURN_RET_LOG(saStatusChangeCallback_ != nullptr, CAMERA_UNKNOWN_ERROR,
        "saStatusChangeCallback_ init error");
    int32_t ret = samgr->SubscribeSystemAbility(WINDOW_MANAGER_SERVICE_ID, saStatusChangeCallback_);
    MEDIA_DEBUG_LOG("SubscribeSystemAbility ret = %{public}d", ret);
    return ret == 0? CAMERA_OK : CAMERA_UNKNOWN_ERROR;
}
 
int32_t CameraWindowManagerClient::UnSubscribeSystemAbility()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_ERROR_RETURN_RET_LOG(samgr == nullptr, CAMERA_UNKNOWN_ERROR, "Failed to get system ability manager");
    if (saStatusChangeCallback_ == nullptr) {
        return CAMERA_OK;
    }
    CHECK_ERROR_RETURN_RET(saStatusChangeCallback_ == nullptr, CAMERA_OK);
    int32_t ret = samgr->UnSubscribeSystemAbility(WINDOW_MANAGER_SERVICE_ID, saStatusChangeCallback_);
    MEDIA_DEBUG_LOG("SubscribeSystemAbility ret = %{public}d", ret);
    return ret == 0? CAMERA_OK : CAMERA_UNKNOWN_ERROR;
}
 
void CameraWindowManagerClient::WMSSaStatusChangeCallback::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    CameraWindowManagerClient::GetInstance()->InitWindowProxy();
    CameraWindowManagerClient::GetInstance()->InitWindowManagerAgent();
}
 
void CameraWindowManagerClient::WMSSaStatusChangeCallback::OnRemoveSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    CameraWindowManagerClient::GetInstance()->mockSessionManagerServiceProxy_ = nullptr;
    CameraWindowManagerClient::GetInstance()->sessionManagerServiceProxy_ = nullptr;
    CameraWindowManagerClient::GetInstance()->sceneSessionManagerProxy_ = nullptr;
    CameraWindowManagerClient::GetInstance()->windowManagerAgent_ = nullptr;
}
} // namespace CameraStandard
} // namespace OHOS