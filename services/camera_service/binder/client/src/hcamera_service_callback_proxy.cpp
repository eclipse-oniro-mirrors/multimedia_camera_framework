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

#include "hcamera_service_callback_proxy.h"
#include "camera_log.h"
#include "camera_service_ipc_interface_code.h"

namespace OHOS {
namespace CameraStandard {
HCameraServiceCallbackProxy::HCameraServiceCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ICameraServiceCallback>(impl) { }

int32_t HCameraServiceCallbackProxy::OnCameraStatusChanged(const std::string& cameraId, const CameraStatus status)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    option.SetFlags(option.TF_ASYNC);
    MEDIA_INFO_LOG("HCameraServiceCallbackProxy OnCameraStatusChanged called");

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(cameraId);
    data.WriteInt32(status);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceCallbackInterfaceCode::CAMERA_CALLBACK_STATUS_CHANGED),
        data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceCallbackProxy OnCameraStatusChanged failed, error: %{public}d", error);
    }
    return error;
}

int32_t HCameraServiceCallbackProxy::OnFlashlightStatusChanged(const std::string& cameraId, const FlashStatus status)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    option.SetFlags(option.TF_ASYNC);
    int error = ERR_NONE;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(cameraId);
    data.WriteInt32(status);
    error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraServiceCallbackInterfaceCode::CAMERA_CALLBACK_FLASHLIGHT_STATUS_CHANGED),
        data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceCallbackProxy OnFlashlightStatus failed, error: %{public}d", error);
    }
    return error;
}

HCameraMuteServiceCallbackProxy::HCameraMuteServiceCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ICameraMuteServiceCallback>(impl) { }

int32_t HCameraMuteServiceCallbackProxy::OnCameraMute(bool muteMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    option.SetFlags(option.TF_ASYNC);

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteBool(muteMode);

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(CameraMuteServiceCallbackInterfaceCode::CAMERA_CALLBACK_MUTE_MODE),
        data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceCallbackProxy OnCameraMute failed, error: %{public}d", error);
    }
    return error;
}

HTorchServiceCallbackProxy::HTorchServiceCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ITorchServiceCallback>(impl) { }

int32_t HTorchServiceCallbackProxy::OnTorchStatusChange(const TorchStatus status)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    option.SetFlags(option.TF_ASYNC);
    int error = ERR_NONE;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteInt32(status);
    error = Remote()->SendRequest(
        static_cast<uint32_t>(TorchServiceCallbackInterfaceCode::TORCH_CALLBACK_TORCH_STATUS_CHANGE),
        data, reply, option);
    if (error != ERR_NONE) {
        MEDIA_ERR_LOG("HCameraServiceCallbackProxy OnTorchStatusChange failed, error: %{public}d", error);
    }
    return error;
}
} // namespace CameraStandard
} // namespace OHOS
