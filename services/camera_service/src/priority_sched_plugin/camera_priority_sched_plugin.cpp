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
 
#include <dlfcn.h>
#include <unistd.h>
#include <unordered_set>
#include "ipc_skeleton.h"
#include "bundle_mgr_interface.h"
#include "system_ability_definition.h"
#include "camera_log.h"
#include "hcamera_device_manager.h"
#include "priority_sched_plugin/camera_priority_sched_plugin.h"
#include "camera_util.h"
#include "bms_adapter.h"
#include "parameters.h"
 
namespace OHOS {
namespace CameraStandard {
 
#if (defined(__aarch64__) || defined(__x86_64__))
const std::string CAMERA_PRIORITY_PLUGIN_SO_PATH = "/system/lib64/libpriority_sched_policy_camera.z.so";
#else
const std::string CAMERA_PRIORITY_PLUGIN_SO_PATH = "/system/lib/libpriority_sched_policy_camera.z.so";
#endif
 
using InitFunc = bool (*)();
using JudgePreemptFunc = bool (*)(const std::string&, const CameraAppInfo*, int32_t,
    const CameraAppInfo*, std::vector<CameraAppInfo>&);
 
bool CameraPrioritySchedPlugin::initResult_ = false;
sptr<CameraPrioritySchedPlugin> CameraPrioritySchedPlugin::instance_ = nullptr;
std::mutex CameraPrioritySchedPlugin::instanceMutex_;
 
sptr<CameraPrioritySchedPlugin> &CameraPrioritySchedPlugin::GetInstance()
{
    if (instance_ == nullptr) {
        std::unique_lock<std::mutex> lock(instanceMutex_);
        if (instance_ == nullptr) {
            MEDIA_INFO_LOG("Initializing CameraPrioritySchedPlugin instance");
            instance_ = new CameraPrioritySchedPlugin();
            initResult_ = instance_->Init();
        }
    }
    CHECK_PRINT_ELOG(!initResult_, "CameraPrioritySchedPlugin::GetInstance init first failed");
    CHECK_EXECUTE(!initResult_, initResult_ = instance_->Init());
    CHECK_PRINT_ELOG(!initResult_, "CameraPrioritySchedPlugin::GetInstance init second failed");
    return instance_;
}
 
CameraPrioritySchedPlugin::~CameraPrioritySchedPlugin()
{
    CHECK_RETURN(!handle_);
    dlclose(handle_);
    handle_ = nullptr;
}
 
bool CameraPrioritySchedPlugin::Init()
{
    MEDIA_INFO_LOG("CameraPrioritySchedPlugin start init");
    if (handle_) {
        InitFunc initFunc = (InitFunc)GetFunction("CameraPrioritySched_Init");
        CHECK_RETURN_RET_ELOG(initFunc == nullptr, false,
            "CameraPrioritySchedPlugin::Init function not found");
        return initFunc();
    }
    handle_ = ::dlopen(CAMERA_PRIORITY_PLUGIN_SO_PATH.c_str(), RTLD_NOW);
    CHECK_RETURN_RET_ELOG(!handle_, false, "dlopen failed check so file exists");
    InitFunc initFunc = (InitFunc)GetFunction("CameraPrioritySched_Init");
    CHECK_RETURN_RET_ELOG(initFunc == nullptr, false,
        "CameraPrioritySchedPlugin::Init function not found");
    bool result = initFunc();
    MEDIA_INFO_LOG("CameraPrioritySchedPlugin init result: %{public}d", result);
    return result;
}
 
std::vector<CameraAppInfo> CameraPrioritySchedPlugin::JudgePreempt(
    const std::string& cameraId,
    const std::vector<sptr<HCameraDeviceHolder>>& currentRunningApps,
    const sptr<HCameraDeviceHolder>& requestApp)
{
    if (cameraId.empty() || requestApp == nullptr) {
        MEDIA_ERR_LOG("CameraPrioritySchedPlugin::JudgePreempt invalid params");
        return {};
    }
 
    if (!initResult_ || handle_ == nullptr) {
        MEDIA_ERR_LOG("CameraPrioritySchedPlugin::JudgePreempt plugin not initialized");
        return {};
    }
 
    std::vector<CameraAppInfo> runningInfoList;
    for (const auto& holder : currentRunningApps) {
        if (holder == nullptr) {
            continue;
        }
        std::string bundleName = BmsAdapter::GetInstance().GetBundleName(holder->GetUid());
        if (bundleName.empty()) {
            continue;
        }
        CameraAppInfo info;
        info.uid = holder->GetUid();
        info.pid = holder->GetPid();
        info.accessTokenId = holder->GetAccessTokenId();
        info.bundleName = bundleName;
        MEDIA_INFO_LOG("CameraPrioritySchedPlugin::JudgePreempt running uid:%{public}d pid:%{public}d bundleName:%{public}s",
            info.uid, info.pid, info.bundleName.c_str());
        runningInfoList.push_back(info);
    }
 
    CameraAppInfo requestInfo;
    requestInfo.uid = requestApp->GetUid();
    requestInfo.pid = requestApp->GetPid();
    requestInfo.accessTokenId = requestApp->GetAccessTokenId();
    requestInfo.bundleName = BmsAdapter::GetInstance().GetBundleName(requestApp->GetUid());
    MEDIA_INFO_LOG("CameraPrioritySchedPlugin::JudgePreempt cameraId:%{public}s request uid:%{public}d pid:%{public}d bundleName:%{public}s runningCount:%{public}zu",
        cameraId.c_str(), requestInfo.uid, requestInfo.pid, requestInfo.bundleName.c_str(), runningInfoList.size());
 
    JudgePreemptFunc judgePreemptFunc = (JudgePreemptFunc)GetFunction("CameraPrioritySched_JudgePreempt");
    CHECK_RETURN_RET_ELOG(judgePreemptFunc == nullptr, std::vector<CameraAppInfo>(),
        "CameraPrioritySchedPlugin::JudgePreempt function not found");
    std::vector<CameraAppInfo> allowAppList;
    bool result = judgePreemptFunc(cameraId, runningInfoList.data(),
        static_cast<int32_t>(runningInfoList.size()), &requestInfo, allowAppList);
    CHECK_RETURN_RET_ELOG(!result, std::vector<CameraAppInfo>(),
        "CameraPrioritySchedPlugin::JudgePreempt so call failed");
    MEDIA_INFO_LOG("CameraPrioritySchedPlugin judgePreemptFunc result: %{public}d", result);
    return allowAppList;
}
 
void *CameraPrioritySchedPlugin::GetFunction(const std::string& functionName)
{
    CHECK_RETURN_RET_DLOG(handle_ == nullptr, nullptr,
        "CameraPrioritySchedPlugin::GetFunction fail not loaded");
    void* funcInstance = nullptr;
    CHECK_RETURN_RET(functionMap_.Find(functionName, funcInstance), funcInstance);
    void* handleFunc = dlsym(handle_, functionName.c_str());
    CHECK_RETURN_RET_DLOG(handleFunc == nullptr, nullptr,
        "CameraPrioritySchedPlugin::GetFunction fail function:%{public}s not find", functionName.c_str());
    MEDIA_INFO_LOG("CameraPrioritySchedPlugin::GetFunction %{public}s success", functionName.c_str());
    functionMap_.EnsureInsert(functionName, handleFunc);
    return handleFunc;
}
 
} // namespace CameraStandard
} // namespace OHOS