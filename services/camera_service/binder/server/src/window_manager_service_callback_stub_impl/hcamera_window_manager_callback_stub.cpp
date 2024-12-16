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
 
#include "hcamera_window_manager_callback_stub.h"
#include "camera_log.h"
#include "camera_service_ipc_interface_code.h"
 
namespace OHOS {
namespace CameraStandard {
int CameraWindowManagerAgentStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int errCode = -1;
 
    CHECK_ERROR_RETURN_RET(data.ReadInterfaceToken() != GetDescriptor(), errCode);
    switch (code) {
        case static_cast<uint32_t>(WindowServiceInterfaceCode::TRANS_ID_UPDATE_CAMERA_WINDOW_STATUS):
            errCode = CameraWindowManagerAgentStub::HandleUpdateCameraWindowStatus(data);
            break;
        default:
            MEDIA_ERR_LOG("HCameraDeviceCallbackStub request code %{public}u not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }
    return errCode;
}
 
int CameraWindowManagerAgentStub::HandleUpdateCameraWindowStatus(MessageParcel& data)
{
    uint32_t accessTokenId = data.ReadUint32();
    bool isShowing = data.ReadBool();
    MEDIA_DEBUG_LOG("HandleUpdateCameraWindowStatus get accessTokenId changed, isShowing: %{public}d", isShowing);
    UpdateCameraWindowStatus(accessTokenId, isShowing);
    return 0;
}
} // namespace CameraStandard
} // namespace OHOS