/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "mode/mode_manager.h"


#include "camera_util.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "camera_log.h"
#include "system_ability_definition.h"
#include "camera_error_code.h"
#include "icamera_util.h"
#include "device_manager_impl.h"

using namespace std;
namespace OHOS {
namespace CameraStandard {
sptr<ModeManager> ModeManager::modeManager_;

ModeManager::ModeManager()
{
    Init();
}

ModeManager::~ModeManager()
{
    serviceProxy_ = nullptr;
    ModeManager::modeManager_ = nullptr;
}

sptr<ModeManager> &ModeManager::GetInstance()
{
    if (ModeManager::modeManager_ == nullptr) {
        MEDIA_INFO_LOG("Initializing mode manager for first time!");
        ModeManager::modeManager_ = new(std::nothrow) ModeManager();
        CHECK_AND_PRINT_LOG(!ModeManager::modeManager_, "Failed to new ModeManager");
    }
    return ModeManager::modeManager_;
}

void ModeManager::Init()
{
    CAMERA_SYNC_TRACE;
    sptr<IRemoteObject> object = nullptr;
    MEDIA_DEBUG_LOG("ModeManager:init srart");
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        MEDIA_ERR_LOG("ModeManager get System ability manager failed");
        return;
    }
    MEDIA_DEBUG_LOG("ModeManager:GetSystemAbility srart");
    object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    if (object == nullptr) {
        MEDIA_ERR_LOG("object is null");
        return;
    }
    serviceProxy_ = iface_cast<ICameraService>(object);
    if (serviceProxy_ == nullptr) {
        MEDIA_ERR_LOG("serviceProxy_ is null");
        return;
    }
    return;
}

sptr<CaptureSession> ModeManager::CreateCaptureSession(CameraMode mode)
{
    CAMERA_SYNC_TRACE;
    sptr<ICaptureSession> session = nullptr;
    sptr<CaptureSession> captureSession = nullptr;

    int32_t retCode = CAMERA_OK;
    if (serviceProxy_ == nullptr) {
        MEDIA_ERR_LOG("serviceProxy_ is null");
        return nullptr;
    }
    MEDIA_ERR_LOG("ModeManager CreateCaptureSession E");
    retCode = serviceProxy_->CreateCaptureSession(session);
    MEDIA_ERR_LOG("ModeManager CreateCaptureSession X, %{public}d", retCode);
    if (retCode == CAMERA_OK && session != nullptr) {
        switch (mode) {
            case CameraMode::PORTRAIT:
                captureSession = new(std::nothrow) PortraitSession(session);
                break;
            default:
                captureSession = new(std::nothrow) CaptureSession(session);
                break;
        }
    } else {
        MEDIA_ERR_LOG("Failed to get capture session object from hcamera service!, %{public}d", retCode);
        return nullptr;
    }
    return captureSession;
}

std::vector<CameraMode> ModeManager::GetSupportedModes(sptr<CameraDevice>& camera)
{
    vector<CameraMode> objectModes = {};
    return objectModes;
}

sptr<CameraOutputCapability> ModeManager::GetSupportedOutputCapability(sptr<CameraDevice>& camera,
    CameraMode modeName)
{
    sptr<CameraOutputCapability> cameraOutputCapability = nullptr;
    return cameraOutputCapability;
}
} // namespace CameraStandard
} // namespace OHOS
