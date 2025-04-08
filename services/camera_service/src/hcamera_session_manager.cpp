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

#include "hcamera_session_manager.h"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <sched.h>

#include "camera_dynamic_loader.h"
#include "camera_util.h"
#include "hcamera_device_manager.h"
#include "hcapture_session.h"
#include "parameters.h"

namespace OHOS {
namespace CameraStandard {
static const int32_t GROUP_SIZE_MIN_LIMIT = 1; // Default session min size is 1
static const int32_t GROUP_SIZE_MAX_LIMIT = 10; // Default session max size is 10

static size_t GetGroupSizeLimit(pid_t pid)
{
    if (HCameraDeviceManager::GetInstance()->IsProcessHasConcurrentDevice(pid)) {
        return GROUP_SIZE_MAX_LIMIT;
    }
    return GROUP_SIZE_MIN_LIMIT;
}

size_t HCameraSessionManager::GetTotalSessionSize()
{
    std::lock_guard<std::mutex> lock(totalSessionMapMutex_);
    size_t totalSize = 0;
    for (auto& it : totalSessionMap_) {
        totalSize += it.second.size();
    }
    return totalSize;
}

size_t HCameraSessionManager::GetGroupCount()
{
    std::lock_guard<std::mutex> lock(totalSessionMapMutex_);
    return totalSessionMap_.size();
}

size_t HCameraSessionManager::GetSessionSize(pid_t pid)
{
    std::lock_guard<std::mutex> lock(totalSessionMapMutex_);
    auto it = totalSessionMap_.find(pid);
    if (it != totalSessionMap_.end()) {
        return it->second.size();
    }
    return 0;
}
std::list<sptr<HCaptureSession>> HCameraSessionManager::GetTotalSession()
{
    std::list<sptr<HCaptureSession>> totalList {};
    std::lock_guard<std::mutex> lock(totalSessionMapMutex_);
    for (auto& mapIt : totalSessionMap_) {
        for (auto& listIt : mapIt.second) {
            totalList.emplace_back(listIt);
        }
    }
    return totalList;
}

std::list<sptr<HCaptureSession>> HCameraSessionManager::GetGroupSessions(pid_t pid)
{
    std::list<sptr<HCaptureSession>> totalList {};
    std::lock_guard<std::mutex> lock(totalSessionMapMutex_);
    auto mapIt = totalSessionMap_.find(pid);
    if (mapIt == totalSessionMap_.end()) {
        return totalList;
    }
    for (auto& listIt : mapIt->second) {
        totalList.emplace_back(listIt);
    }
    return totalList;
}

sptr<HCaptureSession> HCameraSessionManager::GetGroupDefaultSession(pid_t pid)
{
    std::lock_guard<std::mutex> lock(totalSessionMapMutex_);
    auto mapIt = totalSessionMap_.find(pid);
    if (mapIt == totalSessionMap_.end()) {
        return nullptr;
    }
    auto& list = mapIt->second;
    if (list.empty()) {
        return nullptr;
    }
    return list.front();
}

CamServiceError HCameraSessionManager::AddSession(sptr<HCaptureSession> session)
{
    if (session == nullptr) {
        return CAMERA_INVALID_ARG;
    }
    auto pid = session->GetPid();
    std::lock_guard<std::mutex> lock(totalSessionMapMutex_);
    auto& list = totalSessionMap_[pid];
    list.emplace_back(session);

    if (list.size() > GetGroupSizeLimit(pid)) {
        return CAMERA_SESSION_MAX_INSTANCE_NUMBER_REACHED;
    }
    return CAMERA_OK;
}

void HCameraSessionManager::RemoveSession(sptr<HCaptureSession> session)
{
    if (session == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(totalSessionMapMutex_);
    auto mapIt = totalSessionMap_.find(session->GetPid());
    if (mapIt == totalSessionMap_.end()) {
        return;
    }
    auto& list = mapIt->second;
    for (auto listIt = list.begin(); listIt != list.end(); listIt++) {
        if (session == *listIt) {
            list.erase(listIt);
            break;
        }
    }
    if (list.empty()) {
        RemoveGroupNoLock(mapIt);
    }
}

void HCameraSessionManager::PreemptOverflowSessions(pid_t pid)
{
    size_t limitSize = GetGroupSizeLimit(pid);
    std::vector<sptr<HCaptureSession>> overflowSessions = {};
    {
        std::lock_guard<std::mutex> lock(totalSessionMapMutex_);
        auto mapIt = totalSessionMap_.find(pid);
        if (mapIt == totalSessionMap_.end()) {
            return;
        }
        auto& list = mapIt->second;
        size_t currentListSize = list.size();
        if (currentListSize <= limitSize) {
            return;
        }
        size_t overflowSize = currentListSize - limitSize;
        for (size_t i = 0; i < overflowSize; i++) {
            auto previousSession = list.front();
            overflowSessions.emplace_back(previousSession);
            list.pop_front();
        }
        if (list.empty()) {
            RemoveGroupNoLock(mapIt);
        }
    }
    for (auto& session : overflowSessions) {
        session->OnSessionPreempt();
    }
}

void HCameraSessionManager::RemoveGroup(pid_t pid)
{
    std::lock_guard<std::mutex> lock(totalSessionMapMutex_);
    auto mapIt = totalSessionMap_.find(pid);
    if (mapIt == totalSessionMap_.end()) {
        return;
    }
    RemoveGroupNoLock(mapIt);
}

void HCameraSessionManager::RemoveGroupNoLock(std::unordered_map<pid_t, SessionGroup>::iterator mapIt)
{
    totalSessionMap_.erase(mapIt);
}
} // namespace CameraStandard
} // namespace OHOS
