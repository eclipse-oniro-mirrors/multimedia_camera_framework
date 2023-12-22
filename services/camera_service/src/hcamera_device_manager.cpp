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

#include "camera_log.h"
#include "ipc_skeleton.h"
#include "hcamera_service_proxy.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "hcamera_device_manager.h"

namespace OHOS {
namespace CameraStandard {
static const int32_t SERVICE_ID_OF_DH = 66850;
static const int32_t WAIT_FOR_A_CLOSE_CAMERA = 2;
static const int32_t PRIORITY_OF_FOREGROUND = 0;
static const int32_t PRIORITY_OF_BACKGROUND = 400;
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
            HCameraDeviceManager::cameraDeviceManager_ = new(std::nothrow) HCameraDeviceManager();
        }
    }
    return HCameraDeviceManager::cameraDeviceManager_;
}

void HCameraDeviceManager::AddDevice(pid_t pid, sptr<HCameraDevice> device)
{
    MEDIA_DEBUG_LOG("HCameraDeviceManager::AddDevice start");
    pidToCameras_.EnsureInsert(pid, device);
    MEDIA_DEBUG_LOG("HCameraDeviceManager::AddDevice end");
}

void HCameraDeviceManager::RemoveDevice()
{
    MEDIA_DEBUG_LOG("HCameraDeviceManager::RemoveDevice start");
    pidToCameras_.Clear();
    MEDIA_DEBUG_LOG("HCameraDeviceManager::RemoveDevice end");
}

sptr<HCameraDevice> HCameraDeviceManager::GetCameraByPid(pid_t pidRequest)
{
    MEDIA_DEBUG_LOG("HCameraDeviceManager::GetCameraByPid start");
    sptr<HCameraDevice> camera = nullptr;
    pidToCameras_.Find(pidRequest, camera);
    MEDIA_DEBUG_LOG("HCameraDeviceManager::GetCameraByPid end");
    return camera;
}

pid_t HCameraDeviceManager::GetActiveClient()
{
    MEDIA_DEBUG_LOG("HCameraDeviceManager::GetActiveClient start");
    pid_t activeClientPid = -1;
    if (!pidToCameras_.IsEmpty()) {
        pidToCameras_.Iterate([&](pid_t pid, sptr<HCameraDevice> cameras) {
            activeClientPid = pid;
        });
    }
    MEDIA_DEBUG_LOG("HCameraDeviceManager::GetActiveClient end");
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

bool HCameraDeviceManager::GetConflictDevices(sptr<HCameraDevice> &cameraNeedEvict,
                                              sptr<HCameraDevice> cameraIdRequestOpen)
{
    pid_t activeClient = GetActiveClient();
    pid_t pidOfOpenRequest = IPCSkeleton::GetCallingPid();
    if (stateOfACamera_.Size() != 0) {
        if (activeClient != -1) {
            MEDIA_ERR_LOG("HCameraDeviceManager::GetConflictDevices A and OH camera is turning on in the same time");
            return false;
        }
        return isAllowOpen(pidOfOpenRequest);
    } else {
        MEDIA_INFO_LOG("HCameraDeviceManager::GetConflictDevices no A camera active");
    }
    if (activeClient == -1) {
        return true;
    }
    sptr<HCameraDevice> activeCamera = GetCameraByPid(activeClient);
    if (activeCamera == nullptr) {
        return true;
    }
    int32_t priorityOfOpenRequestPid = 1001;
    int32_t result = Memory::MemMgrClient::GetInstance().
                    GetReclaimPriorityByPid(pidOfOpenRequest, priorityOfOpenRequestPid);
    MEDIA_INFO_LOG("HCameraDeviceManager::GetConflictDevices callerPid:%{public}d, priority score: %{public}d",
                   pidOfOpenRequest, priorityOfOpenRequestPid);
    if (!result) {
        if (activeClient == pidOfOpenRequest) {
            MEDIA_INFO_LOG("HCameraDeviceManager::GetConflictDevices is same pid");
            if (!activeCamera->GetCameraId().compare(cameraIdRequestOpen->GetCameraId())) {
                cameraNeedEvict = activeCamera;
                return true;
            } else {
                return false;
            }
        }
        int32_t priorityOfIterPid = 1001;
        int32_t iterResult = Memory::MemMgrClient::GetInstance().
                            GetReclaimPriorityByPid(activeClient, priorityOfIterPid);
        MEDIA_INFO_LOG("HCameraDeviceManager::canOpenCamera pid:%{public}d, priority score: %{public}d",
                       activeClient, priorityOfIterPid);
        if (!iterResult && priorityOfOpenRequestPid <= priorityOfIterPid) {
            cameraNeedEvict= activeCamera;
            return true;
        } else {
            return false;
        }
    } else {
        MEDIA_ERR_LOG("HCameraDeviceManager::GetConflictDevices falied to get priority");
        return false;
    }
}

std::string HCameraDeviceManager::GetACameraId()
{
    MEDIA_INFO_LOG("HCameraDeviceManager::GetActiveClient start");
    std::string cameraId;
    if (!stateOfACamera_.IsEmpty()) {
        stateOfACamera_.Iterate([&](std::string pid, int32_t state) {
            cameraId = pid;
        });
    }
    MEDIA_INFO_LOG("HCameraDeviceManager::GetActiveClient end");
    return cameraId;
}

int32_t HCameraDeviceManager::GetAdjForCameraState(std::string cameraId)
{
    int32_t state = 1;
    stateOfACamera_.Find(cameraId, state);
    MEDIA_INFO_LOG("HCameraDeviceManager::SetStateOfACamera start %{public}s, state: %{public}d",
                   cameraId.c_str(), state);
    return state == 0 ? PRIORITY_OF_FOREGROUND : PRIORITY_OF_BACKGROUND;
}

bool HCameraDeviceManager::isAllowOpen(pid_t pidOfOpenRequest)
{
    MEDIA_INFO_LOG("HCameraDeviceManager::isAllowOpen has a client open in A proxy");
    if (pidOfOpenRequest != -1) {
        std::string cameraId = GetACameraId();
        sptr<IRemoteObject> object = nullptr;
        auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgr == nullptr) {
            MEDIA_ERR_LOG("Failed to get System ability manager");
            return false;
        }
        object = samgr->GetSystemAbility(SERVICE_ID_OF_DH);
        if (object == nullptr) {
            MEDIA_ERR_LOG("object is null");
            return false;
        }
        sptr<ICameraProxy> ancoCallback = iface_cast<ICameraProxy>(object);
        if (ancoCallback == nullptr) {
            MEDIA_ERR_LOG("serviceProxy_ is null.");
            return false;
        }
        ancoCallback->NotifyCloseCamera(cameraId);
        sleep(WAIT_FOR_A_CLOSE_CAMERA);
        return true;
    } else {
        MEDIA_ERR_LOG("HCameraDeviceManager::GetConflictDevices wrong pid of the process whitch is goning to turn on");
        return false;
    }
}
} // namespace CameraStandard
} // namespace OHOS