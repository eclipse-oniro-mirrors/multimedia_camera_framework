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
 
#include "hcamera_scene_session_manager_proxy.h"
#include "camera_log.h"
 
namespace OHOS {
namespace CameraStandard {
int32_t CameraSceneSessionManagerProxy::RegisterWindowManagerAgent(WindowManagerAgentType type,
    const sptr<IWindowManagerAgent>& windowManagerAgent)
{
    MessageOption option;
    MessageParcel reply;
    MessageParcel data;
 
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteUint32(static_cast<uint32_t>(type));
    data.WriteRemoteObject(windowManagerAgent->AsObject());
 
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(
        SceneSessionManagerMessage::TRANS_ID_REGISTER_WINDOW_MANAGER_AGENT),
        data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "RegisterWindowManagerAgent failed, error: %{public}d", error);

    return reply.ReadInt32();
}
 
int32_t CameraSceneSessionManagerProxy::UnregisterWindowManagerAgent(WindowManagerAgentType type,
    const sptr<IWindowManagerAgent>& windowManagerAgent)
{
    MessageParcel reply;
    MessageOption option;
    MessageParcel data;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteUint32(static_cast<uint32_t>(type));
    data.WriteRemoteObject(windowManagerAgent->AsObject());
 
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(
        SceneSessionManagerMessage::TRANS_ID_UNREGISTER_WINDOW_MANAGER_AGENT),
        data, reply, option);
    CHECK_ERROR_PRINT_LOG(error != ERR_NONE, "UnregisterWindowManagerAgent failed, error: %{public}d", error);
 
    return reply.ReadInt32();
}
 
void CameraSceneSessionManagerProxy::GetFocusWindowInfo(OHOS::Rosen::FocusChangeInfo& focusInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    data.WriteInterfaceToken(GetDescriptor());
 
    int32_t error = Remote()->SendRequest(
        static_cast<uint32_t>(SceneSessionManagerMessage::TRANS_ID_GET_FOCUS_SESSION_INFO),
        data, reply, option);
    CHECK_ERROR_RETURN_LOG(error != ERR_NONE, "HCameraDeviceProxy DisableResult failed, error: %{public}d", error);
    sptr<OHOS::Rosen::FocusChangeInfo> info = reply.ReadParcelable<OHOS::Rosen::FocusChangeInfo>();
    if (info) {
        focusInfo = *info;
    } else {
        MEDIA_ERR_LOG("GetFocusWindowInfo Focus info is null");
    }
}
} // namespace CameraStandard
} // namespace OHOS