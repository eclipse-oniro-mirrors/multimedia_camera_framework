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
 
#include "hcamera_mock_session_manager_interface.h"
#include "camera_log.h"
 
namespace OHOS {
namespace CameraStandard {
sptr<IRemoteObject> CameraMockSessionManagerProxy::GetSessionManagerService()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
 
    int32_t error = Remote()->SendRequest(
        static_cast<uint32_t>(MockSessionManagerServiceMessage::TRANS_ID_GET_SESSION_MANAGER_SERVICE),
        data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("RegisterWindowManagerAgent failed, error: %{public}d", error);
        return nullptr;
    }
    sptr<IRemoteObject> remoteObject = reply.ReadRemoteObject();
    return remoteObject;
}
} // namespace CameraStandard
} // namespace OHOS