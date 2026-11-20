/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 
#ifndef CAMERA_PRIORITY_SCHED_PLUGIN_H
#define CAMERA_PRIORITY_SCHED_PLUGIN_H
 
#include <string>
#include <vector>
#include <mutex>
#include <sys/types.h>
#include "refbase.h"
#include "safe_map.h"
 
struct CameraAppInfo {
    int32_t uid;
    uint32_t accessTokenId;
    pid_t pid;
    std::string bundleName;
};
 
namespace OHOS {
namespace CameraStandard {
 
class HCameraDeviceHolder;
 
class CameraPrioritySchedPlugin : public RefBase {
public:
    ~CameraPrioritySchedPlugin();
    static sptr<CameraPrioritySchedPlugin> &GetInstance();
 
    std::vector<CameraAppInfo> JudgePreempt(const std::string& cameraId,
        const std::vector<sptr<HCameraDeviceHolder>>& currentRunningApps,
        const sptr<HCameraDeviceHolder>& requestApp);
 
    bool IsInitialized() const { return initResult_; }
 
private:
    CameraPrioritySchedPlugin() = default;
    bool Init();
 
    void *handle_ = nullptr;
    static bool initResult_;
    static sptr<CameraPrioritySchedPlugin> instance_;
    static std::mutex instanceMutex_;
    SafeMap<std::string, void*> functionMap_;
 
    void *GetFunction(const std::string& functionName);
};
 
} // namespace CameraStandard
} // namespace OHOS
 
#endif // CAMERA_PRIORITY_SCHED_PLUGIN_H