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
 
#ifndef OHOS_CAMERA_CAMERA_WINDOW_MANAGER_CLIENT_H
#define OHOS_CAMERA_CAMERA_WINDOW_MANAGER_CLIENT_H
 
#include "hcamera_mock_session_manager_interface.h"
#include "hcamera_scene_session_manager_proxy.h"
#include "hcamera_window_session_manager_service_proxy.h"
#include "system_ability_status_change_stub.h"
 
namespace OHOS {
namespace CameraStandard {
class CameraWindowManagerClient : public RefBase {
public:
    class WMSSaStatusChangeCallback : public SystemAbilityStatusChangeStub {
    public:
        void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
        void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    };
    static sptr<CameraWindowManagerClient>& GetInstance();
    virtual ~CameraWindowManagerClient();
    int32_t RegisterWindowManagerAgent();
    int32_t UnregisterWindowManagerAgent();
    sptr<IWindowManagerAgent> GetWindowManagerAgent();
    void GetFocusWindowInfo(pid_t& pid);
 
private:
    CameraWindowManagerClient();
    void InitWindowProxy();
    void InitWindowManagerAgent();
    int32_t SubscribeSystemAbility();
    int32_t UnSubscribeSystemAbility();
    sptr<IMockSessionManagerInterface> mockSessionManagerServiceProxy_ = nullptr;
    sptr<ISessionManagerService> sessionManagerServiceProxy_ = nullptr;
    sptr<ISceneSessionManager> sceneSessionManagerProxy_ = nullptr;
    sptr<IWindowManagerAgent> windowManagerAgent_ = nullptr;
    sptr<WMSSaStatusChangeCallback> saStatusChangeCallback_;
    static std::mutex instanceMutex_;
    static sptr<CameraWindowManagerClient> cameraWindowManagerClient_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif