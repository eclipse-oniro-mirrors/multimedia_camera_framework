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
#include "hcamera_device_manager.h"

namespace OHOS {
namespace CameraStandard {
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

bool HCameraDeviceManager::GetConflictDevices(sptr<HCameraDevice> &cameraNeedEvict,
                                              sptr<HCameraDevice> cameraIdRequestOpen)
{
    pid_t activeClient = HCameraDeviceManager::GetInstance()->GetActiveClient();
    if (activeClient == -1) {
        return true;
    }
    sptr<HCameraDevice> activeCamera = HCameraDeviceManager::GetCameraByPid(activeClient);
    if (activeCamera == nullptr) {
        return true;
    }
    pid_t pidOfOpenRequest = IPCSkeleton::GetCallingPid();
    MEDIA_DEBUG_LOG("HCameraDeviceManager::GetConflictDevices callerPid:%{public}d", pidOfOpenRequest);

    int32_t priorityOfOpenRequestPid = 1001;
    int32_t result = Memory::MemMgrClient::GetInstance().
                    GetReclaimPriorityByPid(pidOfOpenRequest, priorityOfOpenRequestPid);
    MEDIA_DEBUG_LOG("HCameraDeviceManager::GetConflictDevices result:%{public}d, priority score: %{public}d",
                    result, priorityOfOpenRequestPid);

    if (!result) {
        // 如果是同一个进程，两种情况，1：相机已打开，相机进驱逐队列，但提示可开 2:根据组合判断是否可开
        if (activeClient == pidOfOpenRequest) {
            MEDIA_DEBUG_LOG("HCameraDeviceManager::GetConflictDevices is same pid");
            if (!activeCamera->GetCameraId().compare(cameraIdRequestOpen->GetCameraId())) {
                cameraNeedEvict = activeCamera;
                return true;
            } else {
                return false;
            }
        }
        // 不是同一个进程
        int32_t priorityOfIterPid = 1001;
        int32_t iterResult = Memory::MemMgrClient::GetInstance().
                            GetReclaimPriorityByPid(activeClient, priorityOfIterPid);
        MEDIA_DEBUG_LOG("HCameraDeviceManager::canOpenCamera pid:%{public}d, priority score: %{public}d",
                        activeClient, priorityOfIterPid);
        // 新到进程优先级更高， 当前已打开的相机进入驱逐队列，提示可开
        if (!iterResult && priorityOfOpenRequestPid <= priorityOfIterPid) {
            cameraNeedEvict= activeCamera;
            return true;
        } else {
            // 新到进程优先级低，返回不可开
            return false;
        }
    } else {
        MEDIA_ERR_LOG("HCameraDeviceManager::GetConflictDevices falied to get priority with pid: %{publid}d",
                      pidOfOpenRequest);
        return false;
    }
}
} // namespace CameraStandard
} // namespace OHOS