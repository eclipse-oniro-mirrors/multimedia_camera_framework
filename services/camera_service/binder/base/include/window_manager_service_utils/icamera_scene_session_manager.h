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
 
#ifndef OHOS_CAMERA_ICAMERA_SCENE_SESSION_MANAGER_H
#define OHOS_CAMERA_ICAMERA_SCENE_SESSION_MANAGER_H
 
#include "focus_change_info.h"
#include <iremote_broker.h>
#include "icamera_window_manager_callback.h"
 
namespace OHOS {
namespace CameraStandard {
enum class WindowManagerAgentType : uint32_t {
    WINDOW_MANAGER_AGENT_TYPE_CAMERA_WINDOW = 9,
};
 
class IWindowManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.IWindowManager");
    enum class WindowManagerMessage : uint32_t {
        TRANS_ID_REGISTER_WINDOW_MANAGER_AGENT = 7,
        TRANS_ID_UNREGISTER_WINDOW_MANAGER_AGENT = 8,
    };
 
    virtual int32_t RegisterWindowManagerAgent(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent) = 0;
    virtual int32_t UnregisterWindowManagerAgent(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent) = 0;
    virtual void GetFocusWindowInfo(OHOS::Rosen::FocusChangeInfo& focusInfo) = 0;
};
 
class ISceneSessionManager : public IWindowManager  {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.ISceneSessionManager");
 
    enum class SceneSessionManagerMessage : uint32_t {
        TRANS_ID_REGISTER_WINDOW_MANAGER_AGENT = 4,
        TRANS_ID_UNREGISTER_WINDOW_MANAGER_AGENT = 5,
        TRANS_ID_GET_FOCUS_SESSION_INFO = 7,
    };
 
    virtual int32_t RegisterWindowManagerAgent(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent) = 0;
    virtual int32_t UnregisterWindowManagerAgent(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent) = 0;
    virtual void GetFocusWindowInfo(OHOS::Rosen::FocusChangeInfo& focusInfo) = 0;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_ICAMERA_SCENE_SESSION_MANAGER_H