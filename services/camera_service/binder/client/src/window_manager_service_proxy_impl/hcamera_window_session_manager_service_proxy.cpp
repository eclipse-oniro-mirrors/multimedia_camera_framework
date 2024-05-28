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
 
#include "hcamera_window_session_manager_service_proxy.h"
#include "camera_log.h"
 
namespace OHOS {
namespace CameraStandard {
sptr<IRemoteObject> CameraWindowSessionManagerProxy::GetSceneSessionManager()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
 
    data.WriteInterfaceToken(GetDescriptor());
 
    auto error = Remote()->SendRequest(
        static_cast<uint32_t>(SessionManagerServiceMessage::TRANS_ID_GET_SCENE_SESSION_MANAGER),
        data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraDeviceProxy DisableResult failed, error: %{public}d", error);
        return nullptr;
    }
 
    return reply.ReadRemoteObject();
}
} // namespace CameraStandard
} // namespace OHOS