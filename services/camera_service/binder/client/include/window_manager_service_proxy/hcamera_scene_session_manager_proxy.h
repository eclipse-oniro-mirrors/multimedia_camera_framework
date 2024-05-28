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
 
#ifndef OHOS_CAMERA_HCAMERA_SCENE_SESSION_MANAGER_PROXY_H
#define OHOS_CAMERA_HCAMERA_SCENE_SESSION_MANAGER_PROXY_H
 
#include "icamera_scene_session_manager.h"
#include <iremote_proxy.h>
 
namespace OHOS {
namespace CameraStandard {
class CameraSceneSessionManagerProxy : public IRemoteProxy<ISceneSessionManager> {
public:
    explicit CameraSceneSessionManagerProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<ISceneSessionManager>(impl) {}
    virtual ~CameraSceneSessionManagerProxy() = default;
 
    int32_t RegisterWindowManagerAgent(WindowManagerAgentType type,
            const sptr<IWindowManagerAgent>& windowManagerAgent) override;
    int32_t UnregisterWindowManagerAgent(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent) override;
    void GetFocusWindowInfo(OHOS::Rosen::FocusChangeInfo& focusInfo) override;
private:
    static inline BrokerDelegator<CameraSceneSessionManagerProxy> delegator_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_HCAMERA_SCENE_SESSION_MANAGER_PROXY_H