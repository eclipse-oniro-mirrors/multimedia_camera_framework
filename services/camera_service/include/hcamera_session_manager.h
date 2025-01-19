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

namespace OHOS {
namespace CameraStandard {
class HCaptureSession;
class SessionGroup : public std::list<sptr<HCaptureSession>> {};
class HCameraSessionManager : public Singleton<HCameraSessionManager> {
public:
    size_t GetTotalSessionSize();
    size_t GetGroupCount();
    size_t GetSessionSize(pid_t pid);
    std::list<sptr<HCaptureSession>> GetTotalSession();
    std::list<sptr<HCaptureSession>> GetGroupSessions(pid_t pid);
    sptr<HCaptureSession> GetGroupDefaultSession(pid_t pid);
    CamServiceError AddSession(sptr<HCaptureSession> session);
    void RemoveSession(sptr<HCaptureSession> session);
    void RemoveGroup(pid_t pid);

private:
    void RemoveGroupNoLock(std::unordered_map<pid_t, SessionGroup>::iterator mapIt);

    std::mutex totalSessionMapMutex_;
    std::unordered_map<pid_t, SessionGroup> totalSessionMap_;
};
} // namespace CameraStandard
} // namespace OHOS

#endif