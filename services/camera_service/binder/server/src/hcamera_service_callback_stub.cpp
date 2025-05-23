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

#include "hcamera_service_callback_stub.h"
#include "camera_log.h"
#include "camera_service_ipc_interface_code.h"

namespace OHOS {
namespace CameraStandard {
int HCameraServiceCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int errCode = -1;

    CHECK_ERROR_RETURN_RET(data.ReadInterfaceToken() != GetDescriptor(), errCode);
    switch (code) {
        case CAMERA_CALLBACK_STATUS_CHANGED:
            errCode = HCameraServiceCallbackStub::HandleOnCameraStatusChanged(data);
            break;

        case CAMERA_CALLBACK_FLASHLIGHT_STATUS_CHANGED:
            errCode = HCameraServiceCallbackStub::HandleOnFlashlightStatusChanged(data);
            break;

        default:
            MEDIA_ERR_LOG("HCameraServiceCallbackStub request code %{public}u not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }

    return errCode;
}

int HCameraServiceCallbackStub::HandleOnCameraStatusChanged(MessageParcel& data)
{
    std::string cameraId = data.ReadString();
    int32_t status = data.ReadInt32();
    std::string bundleName = data.ReadString();
    MEDIA_INFO_LOG("HCameraServiceCallbackStub::HandleOnCameraStatusChanged called, cameraId = %{public}s, "
                   "status = %{public}d, bundleName = %{public}s", cameraId.c_str(), status, bundleName.c_str());
    return OnCameraStatusChanged(cameraId, static_cast<CameraStatus>(status), bundleName);
}

int HCameraServiceCallbackStub::HandleOnFlashlightStatusChanged(MessageParcel& data)
{
    std::string cameraId = data.ReadString();
    int32_t status = data.ReadInt32();

    return OnFlashlightStatusChanged(cameraId, static_cast<FlashStatus>(status));
}

int HTorchServiceCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int errCode = -1;

    CHECK_ERROR_RETURN_RET(data.ReadInterfaceToken() != GetDescriptor(), errCode);
    switch (code) {
        case static_cast<uint32_t>(TorchServiceCallbackInterfaceCode::TORCH_CALLBACK_TORCH_STATUS_CHANGE):
            errCode = HTorchServiceCallbackStub::HandleOnTorchStatusChange(data);
            break;
        default:
            MEDIA_ERR_LOG("HTorchServiceCallbackStub request code %{public}u not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }

    return errCode;
}

int HTorchServiceCallbackStub::HandleOnTorchStatusChange(MessageParcel& data)
{
    int32_t status = data.ReadInt32();

    return OnTorchStatusChange((TorchStatus)status);
}

int HFoldServiceCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int errCode = -1;
    CHECK_ERROR_RETURN_RET(data.ReadInterfaceToken() != GetDescriptor(), errCode);
    switch (code) {
        case static_cast<uint32_t>(FoldServiceCallbackInterfaceCode::FOLD_CALLBACK_FOLD_STATUS_CHANGE):
            errCode = HFoldServiceCallbackStub::HandleOnFoldStatusChanged(data);
            break;
        default:
            MEDIA_ERR_LOG("HFoldServiceCallbackStub request code %{public}u not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }
    return errCode;
}

int HFoldServiceCallbackStub::HandleOnFoldStatusChanged(MessageParcel& data)
{
    int32_t status = data.ReadInt32();

    return OnFoldStatusChanged((FoldStatus)status);
}

int HCameraMuteServiceCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int errCode = -1;

    CHECK_ERROR_RETURN_RET(data.ReadInterfaceToken() != GetDescriptor(), errCode);
    switch (code) {
        case static_cast<uint32_t>(CameraMuteServiceCallbackInterfaceCode::CAMERA_CALLBACK_MUTE_MODE):
            errCode = HCameraMuteServiceCallbackStub::HandleOnCameraMute(data);
            break;
        default:
            MEDIA_ERR_LOG("HCameraMuteServiceCallbackStub request code %{public}u not handled", code);
            errCode = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
    }

    return errCode;
}

int HCameraMuteServiceCallbackStub::HandleOnCameraMute(MessageParcel& data)
{
    bool muteMode = data.ReadBool();

    return OnCameraMute(muteMode);
}
} // namespace CameraStandard
} // namespace OHOS
