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

#ifndef OHOS_CAMERA_H_CAPTURE_SESSION_MANAGER_H
#define OHOS_CAMERA_H_CAPTURE_SESSION_MANAGER_H

#include <iterator>
#include <list>
#include <memory>
#include <mutex>
#include <cstdint>
#include <unordered_map>

#include "camera_util.h"
#include "refbase.h"
#include "singleton.h"
#include "hcamera_switch_session.h"

namespace OHOS {
namespace CameraStandard {
class HCaptureSession;
class HMechSession;
class HCameraSwitchSession;
class SessionGroup : public std::list<sptr<HCaptureSession>> {};
class HCameraSessionManager : public Singleton<HCameraSessionManager> {
public:
    size_t GetTotalSessionSize();
    size_t GetGroupCount();
    size_t GetSessionSize(pid_t pid);
    std::list<sptr<HCaptureSession>> GetTotalSession();
    std::list<sptr<HCaptureSession>> GetGroupSessions(pid_t pid);
    std::vector<sptr<HCaptureSession>> GetUserSessions(int32_t userId);
    sptr<HCaptureSession> GetGroupDefaultSession(pid_t pid);
    sptr<HMechSession> GetMechSession(int32_t userId);
    sptr<HCameraSwitchSession> GetCameraSwitchSession();
    CamServiceError AddSession(sptr<HCaptureSession> session);
    CamServiceError AddSessionForPC(sptr<HCaptureSession> session);
    CamServiceError AddMechSession(int32_t userId, sptr<HMechSession> mechSession);
    void RemoveSession(sptr<HCaptureSession> session);
    void RemoveMechSession(int32_t userId);
    void RemoveCameraSwitchSession();
    void RemoveGroup(pid_t pid);
    void PreemptOverflowSessions(pid_t pid);
    void SetCameraSwitchSession(sptr<HCameraSwitchSession> session);

private:
    void RemoveGroupNoLock(std::unordered_map<pid_t, SessionGroup>::iterator mapIt);

    std::mutex totalSessionMapMutex_;
    std::unordered_map<pid_t, SessionGroup> totalSessionMap_;
    std::mutex mechMapMutex_;
    std::unordered_map<int32_t, sptr<HMechSession>> mechSessionMap_;
    sptr<HCameraSwitchSession> cameraSwitchSession;
};
} // namespace CameraStandard
} // namespace OHOS

#endif