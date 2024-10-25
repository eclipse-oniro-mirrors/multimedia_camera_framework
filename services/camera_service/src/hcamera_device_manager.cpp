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

#include "camera_app_manager_client.h"
#include "camera_log.h"
#include "camera_window_manager_agent.h"
#include "camera_window_manager_client.h"
#include "ipc_skeleton.h"
#include "hcamera_service_proxy.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "hcamera_device_manager.h"
#include <mutex>

namespace OHOS {
namespace CameraStandard {
static const int32_t FOREGROUND_STATE_OF_PROCESS = 0;
static const int32_t PIP_STATE_OF_PROCESS = 1;
static const int32_t BCAKGROUND_STATE_OF_PROCESS = 2;
static const int32_t UNKNOW_STATE_OF_PROCESS = 3;
static const std::unordered_map<int32_t, int32_t> APP_MGR_STATE_TO_CAMERA_STATE = {
    {2,  FOREGROUND_STATE_OF_PROCESS},
    {4,  BCAKGROUND_STATE_OF_PROCESS}
};
static const int32_t FOCUSED_STATE_OF_PROCESS = 1;
static const int32_t UNFOCUSED_STATE_OF_PROCESS = 0;
sptr<HCameraDeviceManager> HCameraDeviceManager::cameraDeviceManager_;
std::mutex HCameraDeviceManager::instanceMutex_;

HCameraDeviceManager::HCameraDeviceManager() {}

HCameraDeviceManager::~HCameraDeviceManager()
{
    HCameraDeviceManager::cameraDeviceManager_ = nullptr;
}

sptr<HCameraDeviceManager> &HCameraDeviceManager::GetInstance()
{
    if (HCameraDeviceManager::cameraDeviceManager_ == nullptr) {
        std::unique_lock<std::mutex> lock(instanceMutex_);
        if (HCameraDeviceManager::cameraDeviceManager_ == nullptr) {
            MEDIA_INFO_LOG("Initializing camera device manager instance");
            HCameraDeviceManager::cameraDeviceManager_ = new HCameraDeviceManager();
            CameraWindowManagerClient::GetInstance();
        }
    }
    return HCameraDeviceManager::cameraDeviceManager_;
}

void HCameraDeviceManager::AddDevice(pid_t pid, sptr<HCameraDevice> device)
{
    MEDIA_INFO_LOG("HCameraDeviceManager::AddDevice start");
    std::lock_guard<std::mutex> lock(mapMutex_);
    int32_t uidOfRequestProcess = IPCSkeleton::GetCallingUid();
    int32_t pidOfRequestProcess = IPCSkeleton::GetCallingPid();
    uint32_t accessTokenIdOfRequestProc = IPCSkeleton::GetCallingTokenID();
    sptr<HCameraDeviceHolder> cameraHolder = new HCameraDeviceHolder(
        pidOfRequestProcess, uidOfRequestProcess, FOREGROUND_STATE_OF_PROCESS,
        FOCUSED_STATE_OF_PROCESS, device, accessTokenIdOfRequestProc);
    pidToCameras_.EnsureInsert(pid, cameraHolder);
    MEDIA_INFO_LOG("HCameraDeviceManager::AddDevice end");
}

void HCameraDeviceManager::RemoveDevice()
{
    MEDIA_INFO_LOG("HCameraDeviceManager::RemoveDevice start");
    std::lock_guard<std::mutex> lock(mapMutex_);
    pidToCameras_.Clear();
    MEDIA_INFO_LOG("HCameraDeviceManager::RemoveDevice end");
}

sptr<HCameraDeviceHolder> HCameraDeviceManager::GetCameraHolderByPid(pid_t pidRequest)
{
    MEDIA_INFO_LOG("HCameraDeviceManager::GetCameraHolderByPid start");
    std::lock_guard<std::mutex> lock(mapMutex_);
    sptr<HCameraDeviceHolder> cameraHolder = nullptr;
    pidToCameras_.Find(pidRequest, cameraHolder);
    MEDIA_INFO_LOG("HCameraDeviceManager::GetCameraHolderByPid end");
    return cameraHolder;
}

sptr<HCameraDevice> HCameraDeviceManager::GetCameraByPid(pid_t pidRequest)
{
    MEDIA_INFO_LOG("HCameraDeviceManager::GetCameraByPid start");
    std::lock_guard<std::mutex> lock(mapMutex_);
    sptr<HCameraDeviceHolder> cameraHolder = nullptr;
    pidToCameras_.Find(pidRequest, cameraHolder);
    sptr<HCameraDevice> camera = nullptr;
    if (cameraHolder != nullptr) {
        camera = cameraHolder->GetDevice();
    }
    MEDIA_INFO_LOG("HCameraDeviceManager::GetCameraByPid end");
    return camera;
}

pid_t HCameraDeviceManager::GetActiveClient()
{
    MEDIA_INFO_LOG("HCameraDeviceManager::GetActiveClient start");
    std::lock_guard<std::mutex> lock(mapMutex_);
    pid_t activeClientPid = -1;
    if (!pidToCameras_.IsEmpty()) {
        pidToCameras_.Iterate([&](pid_t pid, sptr<HCameraDeviceHolder> camerasHolder) {
            activeClientPid = pid;
        });
    }
    MEDIA_INFO_LOG("HCameraDeviceManager::GetActiveClient end");
    return activeClientPid;
}

void HCameraDeviceManager::SetStateOfACamera(std::string cameraId, int32_t state)
{
    MEDIA_INFO_LOG("HCameraDeviceManager::SetStateOfACamera start %{public}s, state: %{public}d",
                   cameraId.c_str(), state);\
    if (state == 0) {
        stateOfACamera_.EnsureInsert(cameraId, state);
    } else {
        stateOfACamera_.Clear();
    }
    MEDIA_INFO_LOG("HCameraDeviceManager::SetStateOfACamera end");
}

SafeMap<std::string, int32_t> &HCameraDeviceManager::GetCameraStateOfASide()
{
    return stateOfACamera_;
}

void HCameraDeviceManager::SetPeerCallback(sptr<ICameraBroker>& callback)
{
    CHECK_ERROR_RETURN_LOG(callback == nullptr, "HCameraDeviceManager::SetPeerCallback failed to set peer callback");
    std::lock_guard<std::mutex> lock(peerCbMutex_);
    peerCallback_ = callback;
}

void HCameraDeviceManager::UnsetPeerCallback()
{
    std::lock_guard<std::mutex> lock(peerCbMutex_);
    peerCallback_ = nullptr;
}

bool HCameraDeviceManager::GetConflictDevices(sptr<HCameraDevice> &cameraNeedEvict,
                                              sptr<HCameraDevice> cameraRequestOpen)
{
    pid_t pidOfActiveClient = GetActiveClient();
    pid_t pidOfOpenRequest = IPCSkeleton::GetCallingPid();
    pid_t uidOfOpenRequest = IPCSkeleton::GetCallingUid();
    uint32_t accessTokenIdOfRequestProc = IPCSkeleton::GetCallingTokenID();
    MEDIA_INFO_LOG("GetConflictDevices get active: %{public}d, openRequestPid:%{public}d, openRequestUid:%{public}d",
        pidOfActiveClient, pidOfOpenRequest, uidOfOpenRequest);
    if (stateOfACamera_.Size() != 0) {
        CHECK_ERROR_RETURN_RET_LOG(pidOfActiveClient != -1, false,
            "HCameraDeviceManager::GetConflictDevices rgm and OH camera is turning on in the same time");
        return IsAllowOpen(pidOfOpenRequest);
    } else {
        MEDIA_INFO_LOG("HCameraDeviceManager::GetConflictDevices no rgm camera active");
    }
    if (pidOfActiveClient == -1) {
        return true;
    }
    sptr<HCameraDeviceHolder> activeCameraHolder = GetCameraHolderByPid(pidOfActiveClient);
    if (activeCameraHolder == nullptr) {
        return true;
    }
    if (pidOfActiveClient == pidOfOpenRequest) {
        MEDIA_INFO_LOG("HCameraDeviceManager::GetConflictDevices is same pid");
        if (!activeCameraHolder->GetDevice()->GetCameraId().compare(cameraRequestOpen->GetCameraId())) {
            cameraNeedEvict = activeCameraHolder->GetDevice();
            return true;
        } else {
            return false;
        }
    }
    int32_t activeState = CameraAppManagerClient::GetInstance()->GetProcessState(pidOfActiveClient);
    int32_t requestState = CameraAppManagerClient::GetInstance()->GetProcessState(pidOfOpenRequest);
    MEDIA_INFO_LOG("HCameraDeviceManager::GetConflictDevices active pid:%{public}d state: %{public}d,"
        "request pid:%{public}d state: %{public}d", pidOfActiveClient, activeState, pidOfOpenRequest, requestState);
    UpdateProcessState(activeState, requestState,
        activeCameraHolder->GetAccessTokenId(), accessTokenIdOfRequestProc);
    pid_t focusWindowPid = -1;
    CameraWindowManagerClient::GetInstance()->GetFocusWindowInfo(focusWindowPid);
    if (focusWindowPid == -1) {
        MEDIA_INFO_LOG("GetFocusWindowInfo faild");
    }

    int32_t focusStateOfRequestProcess = focusWindowPid ==
        pidOfOpenRequest ? FOCUSED_STATE_OF_PROCESS : UNFOCUSED_STATE_OF_PROCESS;
    int32_t focusStateOfActiveProcess = focusWindowPid ==
        pidOfActiveClient ? FOCUSED_STATE_OF_PROCESS : UNFOCUSED_STATE_OF_PROCESS;
    activeCameraHolder->SetState(activeState);
    activeCameraHolder->SetFocusState(focusStateOfActiveProcess);

    sptr<HCameraDeviceHolder> requestCameraHolder = new HCameraDeviceHolder(
        pidOfOpenRequest, uidOfOpenRequest, requestState,
        focusStateOfRequestProcess, cameraRequestOpen, accessTokenIdOfRequestProc);
    
    PrintClientInfo(activeCameraHolder, requestCameraHolder);
    if (*(activeCameraHolder->GetPriority()) <= *(requestCameraHolder->GetPriority())) {
        cameraNeedEvict = activeCameraHolder->GetDevice();
        return true;
    } else {
        return false;
    }
}

std::string HCameraDeviceManager::GetACameraId()
{
    MEDIA_INFO_LOG("HCameraDeviceManager::GetActiveClient start");
    std::string cameraId;
    if (!stateOfACamera_.IsEmpty()) {
        stateOfACamera_.Iterate([&](const std::string pid, int32_t state) {
            cameraId = pid;
        });
    }
    MEDIA_INFO_LOG("HCameraDeviceManager::GetActiveClient end");
    return cameraId;
}

bool HCameraDeviceManager::IsAllowOpen(pid_t pidOfOpenRequest)
{
    MEDIA_INFO_LOG("HCameraDeviceManager::isAllowOpen has a client open in A proxy");
    CHECK_ERROR_RETURN_RET_LOG(pidOfOpenRequest == -1, false,
        "HCameraDeviceManager::GetConflictDevices wrong pid of the process whitch is goning to turn on");
    std::string cameraId = GetACameraId();
    CHECK_ERROR_RETURN_RET_LOG(peerCallback_ == nullptr, false,
        "HCameraDeviceManager::isAllowOpen falied to close peer device");
    peerCallback_->NotifyCloseCamera(cameraId);
    MEDIA_ERR_LOG("HCameraDeviceManager::isAllowOpen success to close peer device");
    return true;
}

void HCameraDeviceManager::UpdateProcessState(int32_t& activeState, int32_t& requestState,
    uint32_t activeAccessTokenId, uint32_t requestAccessTokenId)
{
    sptr<IWindowManagerAgent> winMgrAgent = CameraWindowManagerClient::GetInstance()->GetWindowManagerAgent();
    uint32_t accessTokenIdInPip = 0;
    if (winMgrAgent != nullptr) {
        accessTokenIdInPip =
            static_cast<CameraWindowManagerAgent*>(winMgrAgent.GetRefPtr())->GetAccessTokenId();
        MEDIA_DEBUG_LOG("update current pip window accessTokenId");
    }

    auto updateState = [accessTokenIdInPip](int32_t& state, uint32_t accessTokenId) {
        auto it = APP_MGR_STATE_TO_CAMERA_STATE.find(state);
        state = (it != APP_MGR_STATE_TO_CAMERA_STATE.end()) ? it->second : UNKNOW_STATE_OF_PROCESS;
        if (accessTokenId == accessTokenIdInPip) {
            state = PIP_STATE_OF_PROCESS;
        }
    };

    updateState(activeState, activeAccessTokenId);
    updateState(requestState, requestAccessTokenId);
}

void HCameraDeviceManager::PrintClientInfo(sptr<HCameraDeviceHolder> activeCameraHolder,
    sptr<HCameraDeviceHolder> requestCameraHolder)
{
    MEDIA_INFO_LOG("activeInfo: uid: %{public}d, pid:%{public}d, processState:%{public}d,"
        "focusState:%{public}d, cameraId:%{public}s",
        activeCameraHolder->GetPriority()->GetUid(), activeCameraHolder->GetPid(),
        activeCameraHolder->GetPriority()->GetState(),
        activeCameraHolder->GetPriority()->GetFocusState(),
        activeCameraHolder->GetDevice()->GetCameraId().c_str());

    MEDIA_INFO_LOG("requestInfo: uid: %{public}d, pid:%{public}d, processState:%{public}d,"
        "focusState:%{public}d, cameraId:%{public}s",
        requestCameraHolder->GetPriority()->GetUid(), requestCameraHolder->GetPid(),
        requestCameraHolder->GetPriority()->GetState(),
        requestCameraHolder->GetPriority()->GetFocusState(),
        requestCameraHolder->GetDevice()->GetCameraId().c_str());
}
} // namespace CameraStandard
} // namespace OHOS