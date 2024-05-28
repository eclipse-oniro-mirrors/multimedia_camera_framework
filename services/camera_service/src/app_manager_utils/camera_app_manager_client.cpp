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
#include "camera_app_manager_client.h"
#include "camera_util.h"
#include "running_process_info.h"
 
 
namespace OHOS {
namespace CameraStandard {
std::mutex CameraAppManagerClient::instanceMutex_;
sptr<CameraAppManagerClient> CameraAppManagerClient::cameraAppManagerClient_;
 
CameraAppManagerClient::CameraAppManagerClient()
{
    MEDIA_DEBUG_LOG("Make shared appMgrHolder_");
    appMgrHolder_ = std::make_shared<AppExecFwk::AppMgrClient>();
}
 
CameraAppManagerClient::~CameraAppManagerClient()
{
    appMgrHolder_ = nullptr;
}
 
sptr<CameraAppManagerClient>& CameraAppManagerClient::GetInstance()
{
    if (cameraAppManagerClient_ == nullptr) {
        std::unique_lock<std::mutex> lock(instanceMutex_);
        if (cameraAppManagerClient_ == nullptr) {
            MEDIA_INFO_LOG("Initializing CameraWindowManagerClient instance");
            cameraAppManagerClient_ = new(std::nothrow) CameraAppManagerClient();
        }
    }
    return cameraAppManagerClient_;
}
 
int32_t CameraAppManagerClient::GetProcessState(int32_t pid)
{
    AppExecFwk::RunningProcessInfo runningProcessstate;
    int ret = appMgrHolder_->GetRunningProcessInfoByPid(pid, runningProcessstate);
    MEDIA_INFO_LOG("GetProcessStateByPid error code: %{public}d, state: %{public}d", ret, runningProcessstate.state_);
    if (ret == CAMERA_OK) {
        return static_cast<int32_t>(runningProcessstate.state_);
    }
    return -1;
}
} // namespace CameraStandard
} // namespace OHOS