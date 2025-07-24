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
#include "hmech_session.h"
#include "parameters.h"

namespace OHOS {
namespace CameraStandard {
static const int32_t GROUP_SIZE_MIN_LIMIT = 1; // Default session min size is 1
static const int32_t GROUP_SIZE_MAX_LIMIT = 10; // Default session max size is 10

static size_t GetGroupSizeLimit(pid_t pid)
{
    return HCameraDeviceManager::GetInstance()->IsProcessHasConcurrentDevice(pid) ? GROUP_SIZE_MAX_LIMIT :
                                                                                    GROUP_SIZE_MIN_LIMIT;
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
    return it != totalSessionMap_.end() ? it->second.size() : 0;
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
    CHECK_RETURN_RET(mapIt == totalSessionMap_.end(), totalList);
    for (auto& listIt : mapIt->second) {
        totalList.emplace_back(listIt);
    }
    return totalList;
}

std::vector<sptr<HCaptureSession>> HCameraSessionManager::GetUserSessions(int32_t userId)
{
    std::vector<sptr<HCaptureSession>> userList {};
    std::lock_guard<std::mutex> lock(totalSessionMapMutex_);
    for (auto it = totalSessionMap_.begin(); it != totalSessionMap_.end(); ++it) {
        for (auto& listIt : it->second) {
            if (listIt->GetUserId() == userId) {
                userList.emplace_back(listIt);
            }
        }
    }
    return userList;
}

sptr<HCaptureSession> HCameraSessionManager::GetGroupDefaultSession(pid_t pid)
{
    std::lock_guard<std::mutex> lock(totalSessionMapMutex_);
    auto mapIt = totalSessionMap_.find(pid);
    CHECK_RETURN_RET(mapIt == totalSessionMap_.end(), nullptr);
    auto& list = mapIt->second;
    return list.empty() ? nullptr : list.front();
}

sptr<HMechSession> HCameraSessionManager::GetMechSession(int32_t userId)
{
    std::lock_guard<std::mutex> lock(mechMapMutex_);
    auto mapIt = mechSessionMap_.find(userId);
    if (mapIt == mechSessionMap_.end()) {
        return nullptr;
    }
    return mapIt->second;
}

CamServiceError HCameraSessionManager::AddSession(sptr<HCaptureSession> session)
{
    CHECK_RETURN_RET(session == nullptr, CAMERA_INVALID_ARG);
    auto pid = session->GetPid();
    std::lock_guard<std::mutex> lock(totalSessionMapMutex_);
    auto& list = totalSessionMap_[pid];
    list.emplace_back(session);

    return list.size() > GetGroupSizeLimit(pid) ? CAMERA_SESSION_MAX_INSTANCE_NUMBER_REACHED : CAMERA_OK;
}

CamServiceError HCameraSessionManager::AddSessionForPC(sptr<HCaptureSession> session)
{
    CHECK_RETURN_RET(session == nullptr, CAMERA_INVALID_ARG);
    auto pid = session->GetPid();
    std::lock_guard<std::mutex> lock(totalSessionMapMutex_);
    auto& list = totalSessionMap_[pid];
    list.emplace_back(session);
    return CAMERA_OK;
}

CamServiceError HCameraSessionManager::AddMechSession(int32_t userId,
    sptr<HMechSession> mechSession)
{
    if (mechSession == nullptr) {
        return CAMERA_INVALID_ARG;
    }
    std::lock_guard<std::mutex> lock(mechMapMutex_);
    mechSessionMap_.insert(std::make_pair(userId, mechSession));
    return CAMERA_OK;
}

void HCameraSessionManager::RemoveSession(sptr<HCaptureSession> session)
{
    CHECK_RETURN(session == nullptr);
    std::lock_guard<std::mutex> lock(totalSessionMapMutex_);
    auto mapIt = totalSessionMap_.find(session->GetPid());
    CHECK_RETURN(mapIt == totalSessionMap_.end());
    auto& list = mapIt->second;
    for (auto listIt = list.begin(); listIt != list.end(); listIt++) {
        if (session == *listIt) {
            list.erase(listIt);
            break;
        }
    }
    CHECK_RETURN(!list.empty());
    RemoveGroupNoLock(mapIt);
}

void HCameraSessionManager::RemoveMechSession(int32_t userId)
{
    std::lock_guard<std::mutex> lock(mechMapMutex_);
    mechSessionMap_.erase(userId);
}

void HCameraSessionManager::PreemptOverflowSessions(pid_t pid)
{
    size_t limitSize = GetGroupSizeLimit(pid);
    std::vector<sptr<HCaptureSession>> overflowSessions = {};
    {
        std::lock_guard<std::mutex> lock(totalSessionMapMutex_);
        auto mapIt = totalSessionMap_.find(pid);
        CHECK_RETURN(mapIt == totalSessionMap_.end());
        auto& list = mapIt->second;
        size_t currentListSize = list.size();
        CHECK_RETURN(currentListSize <= limitSize);
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
    CHECK_RETURN(mapIt == totalSessionMap_.end());
    RemoveGroupNoLock(mapIt);
}

void HCameraSessionManager::RemoveGroupNoLock(std::unordered_map<pid_t, SessionGroup>::iterator mapIt)
{
    totalSessionMap_.erase(mapIt);
}
} // namespace CameraStandard
} // namespace OHOS
