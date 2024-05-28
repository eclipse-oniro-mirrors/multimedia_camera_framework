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
    InitWindowProxy();
    InitWindowManagerAgent();
}
 
sptr<CameraWindowManagerClient>& CameraWindowManagerClient::GetInstance()
{
    if (cameraWindowManagerClient_ == nullptr) {
        std::unique_lock<std::mutex> lock(instanceMutex_);
        if (cameraWindowManagerClient_ == nullptr) {
            MEDIA_INFO_LOG("Initializing CameraWindowManagerClient instance");
            cameraWindowManagerClient_ = new(std::nothrow) CameraWindowManagerClient();
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
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("failed to UnregisterWindowManagerAgent error code: %{public}d", ret);
    }
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
    if (!systemAbilityManager) {
        MEDIA_ERR_LOG("Failed to get system ability manager");
        return;
    }
 
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(WINDOW_MANAGER_SERVICE_ID);
    if (!remoteObject) {
        MEDIA_ERR_LOG("remoteObjectWmMgrService is null");
        return;
    }
    mockSessionManagerServiceProxy_ = iface_cast<IMockSessionManagerInterface>(remoteObject);
    if (!mockSessionManagerServiceProxy_) {
        MEDIA_ERR_LOG("Failed to get mockSessionManagerServiceProxy_");
        return;
    }
 
    sptr<IRemoteObject> remoteObjectMgrService = mockSessionManagerServiceProxy_->GetSessionManagerService();
    if (!remoteObjectMgrService) {
        MEDIA_ERR_LOG("remoteObjectMgrService is null");
        return;
    }
    sessionManagerServiceProxy_ = iface_cast<ISessionManagerService>(remoteObjectMgrService);
    if (!sessionManagerServiceProxy_) {
        MEDIA_ERR_LOG("Failed to get sessionManagerServiceProxy_");
        return;
    }
 
    sptr<IRemoteObject> remoteObjectMgr = sessionManagerServiceProxy_->GetSceneSessionManager();
    if (!remoteObjectMgr) {
        MEDIA_ERR_LOG("remoteObjectMgr is null");
        return;
    }
    sceneSessionManagerProxy_ = iface_cast<ISceneSessionManager>(remoteObjectMgr);
    if (sceneSessionManagerProxy_ == nullptr) {
        MEDIA_ERR_LOG("Failed to get sceneSessionManagerProxy_");
        return;
    }
    MEDIA_DEBUG_LOG("InitWindowProxy end");
}
 
void CameraWindowManagerClient::InitWindowManagerAgent()
{
    MEDIA_DEBUG_LOG("InitWindowManagerAgent start");
    windowManagerAgent_ = new CameraWindowManagerAgent();
    if (windowManagerAgent_ == nullptr) {
        MEDIA_ERR_LOG("Failed to init windowManagerAgent_");
    }
    MEDIA_DEBUG_LOG("InitWindowManagerAgent start");
}
 
sptr<IWindowManagerAgent> CameraWindowManagerClient::GetWindowManagerAgent()
{
    return windowManagerAgent_;
}
} // namespace CameraStandard
} // namespace OHOS